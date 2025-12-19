# Resources:
# - https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification
from __future__ import annotations

import datetime
from operator import itemgetter
from typing import TYPE_CHECKING, BinaryIO

from dissect.util.stream import RangeStream, RunlistStream
from dissect.util.ts import dostimestamp

from dissect.fat import fat
from dissect.fat.c_exfat import BOOT_REGION_SIZE, c_exfat
from dissect.fat.c_fat import FREE_CLUSTER, c_fat
from dissect.fat.exceptions import DeletedDirectoryError, EmptyDirectoryError, InvalidBPB, LastEmptyDirectoryError

if TYPE_CHECKING:
    from collections.abc import Iterator


class ExFATFS:
    def __init__(self, fh: BinaryIO, encoding: str = "utf-16") -> None:
        self.fh = fh
        self.encoding = encoding
        self.type = c_fat.Fattype.EXFAT

        fh.seek(0)
        self.boot_region_stream = RangeStream(fh, 0, BOOT_REGION_SIZE)  # main boot region is 12 sectors long
        self.bpb = c_exfat.boot_sector(self.boot_region_stream)
        validate_bpb(self.bpb)

        # Checksum is calculated over the first 11 sectors
        self.boot_region_stream.seek(0)
        self.checksum = exfat_checksum32(self.boot_region_stream, BOOT_REGION_SIZE - 512)
        if self.checksum != c_exfat.uint32(self.boot_region_stream):  # read the stored checksum
            raise InvalidBPB("Invalid exFAT boot region checksum")

        self.sector_size = 1 << self.bpb.sect_size_bits  # sector size in bytes
        self.cluster_size = self.sector_size * (1 << self.bpb.sect_per_clus_bits)  # cluster size in bytes

        self.fat_stream = RangeStream(
            fh,
            self.bpb.fat_offset * self.sector_size,  # fat_offset is stored in sectors
            self.bpb.fat_length * self.sector_size,  # fat_length is stored in sectors
        )
        self.fat = fat.FAT(self.fat_stream, c_fat.Fattype.EXFAT)
        self.data_stream = RangeStream(
            fh,
            self.bpb.clu_offset * self.sector_size,  # clu_offset is stored in sectors
            self.bpb.clu_count * self.cluster_size,
        )

        self.root = ExfatRootDirectory(self)
        self.volume_label = self.root.volume_label
        self.volume_id = self.bpb.vol_serial

    def get(
        self, path: str, dirent: ExfatDirectoryEntry | ExfatRootDirectory | None = None
    ) -> ExfatDirectoryEntry | ExfatRootDirectory:
        dirent = dirent if dirent else self.root

        # Programmatically we will often use the `/` separator, so replace it with the native path separator of FAT
        # `/` is an illegal character in FAT filenames, so it's safe to replace
        parts = path.replace("/", "\\").split("\\")
        for part in parts:
            if not part:
                continue

            if dirent is self.root and part in (".", ".."):
                continue

            part_upper = part.upper()
            for child in dirent.iterdir():
                if part_upper == child.name.upper():
                    dirent = child
                    break
            else:
                raise FileNotFoundError(f"File not found: {path}")

        return dirent


def validate_bpb(bpb: c_exfat.boot_sector | bytes) -> None:
    if isinstance(bpb, bytes):
        bpb = c_exfat.boot_sector(bpb[: len(c_exfat.boot_sector)])

    if any(byte != 0 for byte in bpb.must_be_zero):
        raise InvalidBPB("exFAT BPB must be all zeros")

    if not (bpb.jmp_boot[0] == 0xEB and bpb.jmp_boot[1] == 0x76 and bpb.jmp_boot[2] == 0x90):
        raise InvalidBPB(f"Invalid exFAT jmp_boot: {bpb.jmp_boot!r}")

    if bpb.num_fats not in (1, 2):
        raise InvalidBPB(f"Invalid exFAT num_fats, must be 1 or 2: {bpb.num_fats}")

    if bpb.sect_size_bits not in range(9, 13):
        raise InvalidBPB(f"Invalid exFAT sect_size_bits, must be between 9 and 12: {bpb.sect_size_bits}")

    if bpb.sect_per_clus_bits not in range(25 - bpb.sect_size_bits):
        raise InvalidBPB(
            f"Invalid exFAT sect_per_clus_bits, must be between 0 and {25 - bpb.sect_size_bits}: "
            f"{bpb.sect_per_clus_bits}"
        )

    max_fat_offset = bpb.clu_offset - (bpb.fat_length * bpb.num_fats)
    if 24 < bpb.fat_offset > max_fat_offset:
        raise InvalidBPB(f"Invalid exFAT fat_offset, must be between 24 and {max_fat_offset}: {bpb.fat_offset}")

    if bpb.clu_count > 0x0FFFFFF5:
        raise InvalidBPB(f"Invalid exFAT clu_count, must be less than 0x0FFFFFF5: 0x{bpb.clu_count:x}")

    vol_length_min = 1 << (20 - bpb.sect_size_bits)
    if bpb.vol_length < vol_length_min:
        raise InvalidBPB(f"Invalid exFAT vol_length, must be at least 1 MiB: {bpb.vol_length}")


class ExfatDirectoryEntry:
    def __init__(self, fs: ExFATFS, fh: BinaryIO, parent: ExfatDirectoryEntry | ExfatRootDirectory | None = None):
        self.fs = fs
        self.parent = parent

        dentry = c_exfat.exfat_dentry(fh.read(c_exfat.DENTRY_SIZE))
        self.type = dentry.type
        self.dirent = dentry.dentry

        self.streament = None
        self.ldirents = []

        if self.type == 0x00:
            raise EmptyDirectoryError("Dirent is an empty entry")

        if self.type < 0x80:  # entry marked as deleted
            raise DeletedDirectoryError("Dirent is marked as deleted")

        if self._is_file_entry:
            for entry in range(self.dirent.file.num_ext):
                entry = c_exfat.exfat_dentry(fh.read(c_exfat.DENTRY_SIZE))
                if entry.type == c_exfat.EXFAT_STREAM:
                    self.streament = entry.dentry.stream
                    continue

                self.ldirents.append(entry.dentry.name)
        elif self.type == c_exfat.EXFAT_BITMAP:
            self.streament = self.dirent.bitmap
        elif self.type == c_exfat.EXFAT_UPCASE:
            self.streament = self.dirent.upcase

        self.attr = self.dirent.file.attr if self._is_file_entry else 0
        self._runlist = None
        self._entries = None

    @property
    def size(self) -> int:
        return self.streament.size

    @property
    def cluster(self) -> int:
        return self.streament.start_clu

    @property
    def ctime(self) -> datetime.datetime:
        if self._is_file_entry:
            return dostimestamp(
                (self.dirent.file.create_date << 16 | self.dirent.file.create_time),
                self.dirent.file.create_time_cs,
            ).replace(tzinfo=_timezone(self.dirent.file.create_tz))

        return datetime.datetime(1980, 1, 1)  # noqa: DTZ001

    @property
    def atime(self) -> datetime.datetime:
        if self._is_file_entry:
            return dostimestamp(
                (self.dirent.file.access_date << 16 | self.dirent.file.access_time),
            ).replace(tzinfo=_timezone(self.dirent.file.access_tz))
        return datetime.datetime(1980, 1, 1)  # noqa: DTZ001

    @property
    def mtime(self) -> datetime.datetime:
        if self._is_file_entry:
            return dostimestamp(
                (self.dirent.file.modify_date << 16 | self.dirent.file.modify_time),
                self.dirent.file.modify_time_cs,
            ).replace(tzinfo=_timezone(self.dirent.file.modify_tz))
        return datetime.datetime(1980, 1, 1)  # noqa: DTZ001

    def is_readonly(self) -> bool:
        return bool(self.attr & c_fat.ATTR_READ_ONLY)

    def is_hidden(self) -> bool:
        return bool(self.attr & c_fat.ATTR_HIDDEN)

    def is_system(self) -> bool:
        return bool(self.attr & c_fat.ATTR_SYSTEM)

    def is_volume_id(self) -> bool:
        return bool(self.attr & c_fat.ATTR_VOLUME_ID)

    def is_directory(self) -> bool:
        return bool(self.attr & c_fat.ATTR_DIRECTORY)

    def is_archive(self) -> bool:
        return bool(self.attr & c_fat.ATTR_ARCHIVE)

    @property
    def in_fat(self) -> bool:
        return self.streament.flags == c_exfat.ALLOC_FAT_CHAIN

    @property
    def name(self) -> str:
        if self.type == c_exfat.EXFAT_BITMAP:
            return "$ALLOC_BITMAP"
        if self.type == c_exfat.EXFAT_UPCASE:
            return "$UPCASE_TABLE"

        return b"".join([bytes(name.unicode_0_14).strip(b"\x00") for name in self.ldirents]).decode()

    @property
    def _is_file_entry(self) -> bool:
        return self.type == c_exfat.EXFAT_FILE

    def listdir(self) -> list[str]:
        return [entry.name for entry in self.iterdir()]

    def iterdir(self) -> Iterator[ExfatDirectoryEntry]:
        if not self.is_directory():
            raise NotADirectoryError(self.name)

        if not self._entries:
            entries = []
            for entry in iter_dirent(self.fs, self.open(), self):
                if entry.type in (c_exfat.EXFAT_VOLUME,):
                    continue

                yield entry
                entries.append(entry)
            self._entries = entries
        else:
            yield from self._entries

    def dataruns(self) -> list[tuple[int, int]]:
        if self._runlist is None:
            self._runlist = [] if self.cluster == FREE_CLUSTER else list(self.fs.fat.runlist(self.cluster))
        return self._runlist

    def open(self) -> RunlistStream | RangeStream:
        if self.in_fat:
            return RunlistStream(self.fs.data_stream, self.dataruns(), self.size, self.fs.cluster_size)
        return RangeStream(
            self.fs.data_stream,
            (self.cluster - 2) * self.fs.cluster_size,
            self.size,
            self.fs.cluster_size,
        )


class ExfatRootDirectory(ExfatDirectoryEntry):
    def __init__(self, fs: ExFATFS) -> None:
        self.fs = fs
        self.type = None

        self._entries = None
        self._runlist = None

    @property
    def name(self) -> str:
        return "\\"

    @property
    def volume_label(self) -> str:
        label = c_exfat.exfat_dentry(self.open().read(c_exfat.DENTRY_SIZE)).dentry.volume.vol_label
        return label.decode(self.fs.encoding)

    @property
    def size(self) -> int:
        return sum(map(itemgetter(1), self.dataruns())) * self.fs.cluster_size

    @property
    def cluster(self) -> int:
        return self.fs.bpb.root_cluster

    @property
    def in_fat(self) -> bool:
        return False

    def is_directory(self) -> bool:
        return True

    def open(self) -> RunlistStream:
        return RunlistStream(self.fs.data_stream, self.dataruns(), self.size, self.fs.cluster_size)


def iter_dirent(
    fs: ExFATFS,
    fh: BinaryIO,
    parent: ExfatDirectoryEntry | ExfatRootDirectory | None = None,
) -> Iterator[ExfatDirectoryEntry]:
    while True:
        try:
            yield ExfatDirectoryEntry(fs, fh, parent)
        except EmptyDirectoryError:  # noqa: PERF203
            continue
        except DeletedDirectoryError:
            continue
        except LastEmptyDirectoryError:
            break
        except EOFError:
            break


def exfat_checksum32(data: bytes, size: int) -> int:
    checksum = 0
    for idx, byte in enumerate(c_exfat.uint8[size](data)):
        if idx in (106, 107, 112):  # skip vol_flags, percent_in_use
            continue

        checksum = ((checksum << 31) | (checksum >> 1)) + byte
        checksum &= 0xFFFFFFFF
    return checksum


def _timezone(timezone: int) -> datetime.timezone:
    """Convert exFAT timezone byte to datetime.timezone object."""
    # timezone is a signed 7-bit number of 15-minute intervals from UTC
    offset = (timezone & 0x3F) - 0x40 if (timezone & 0x40) else (timezone & 0x7F)
    return datetime.timezone(datetime.timedelta(minutes=offset * 15))
