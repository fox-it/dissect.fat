# Resources:
# - https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification
from __future__ import annotations

import datetime
from functools import cached_property, lru_cache
from operator import itemgetter
from typing import TYPE_CHECKING, BinaryIO

from dissect.util.stream import RangeStream, RunlistStream
from dissect.util.ts import dostimestamp

from dissect.fat.c_exfat import BOOT_REGION_SIZE, c_exfat
from dissect.fat.c_fat import c_fat
from dissect.fat.exception import DeletedDirectoryError, EmptyDirectoryError, InvalidBPB, LastEmptyDirectoryError
from dissect.fat.util import FAT, FatType

if TYPE_CHECKING:
    from collections.abc import Iterator


class ExFAT:
    """exFAT filesystem implementation.

    Args:
        fh: File-like object containing the FAT filesystem.
        encoding: Encoding to use for decoding file names. Defaults to "utf-16".
    """

    def __init__(self, fh: BinaryIO, encoding: str = "utf-16") -> None:
        self.fh = fh
        self.encoding = encoding
        self.type = FatType.EXFAT

        fh.seek(0)
        boot_region = fh.read(BOOT_REGION_SIZE)
        self.bpb = c_exfat.boot_sector(boot_region)
        validate_bpb(self.bpb)

        # Checksum is calculated over the first 11 sectors
        self.checksum = exfat_checksum32(boot_region[: BOOT_REGION_SIZE - 512])
        # Read the stored checksum
        if self.checksum != c_exfat.uint32(boot_region[BOOT_REGION_SIZE - 512 : BOOT_REGION_SIZE]):
            raise InvalidBPB("Invalid exFAT boot region checksum")

        self.sector_size = 1 << self.bpb.sect_size_bits  # sector size in bytes
        self.cluster_size = self.sector_size * (1 << self.bpb.sect_per_clus_bits)  # cluster size in bytes

        fat_stream = RangeStream(
            fh,
            self.bpb.fat_offset * self.sector_size,  # fat_offset is stored in sectors
            self.bpb.fat_length * self.sector_size,  # fat_length is stored in sectors
        )
        self.fat = FAT(fat_stream, fat_stream.size, 32)
        self.data_stream = RangeStream(
            fh,
            self.bpb.clu_offset * self.sector_size,  # clu_offset is stored in sectors
            self.bpb.clu_count * self.cluster_size,
        )

        self.root = RootDirectory(self)

        self.volume_label = ""
        with self.root.open() as rootfh:
            dirent = c_exfat.exfat_dentry(rootfh)
            if dirent.type == c_exfat.EXFAT_VOLUME:
                self.volume_label = dirent.dentry.volume_label.vol_label.decode(self.encoding).rstrip("\x00")

        self.volume_id = self.bpb.vol_serial

    def get(self, path: str, dirent: DirectoryEntry | RootDirectory | None = None) -> DirectoryEntry | RootDirectory:
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
    """Validate the BPB fields according to exFAT specification. Raises :class:`InvalidBPB` if any field is invalid.

    Args:
        bpb: The BPB to validate, either as a parsed structure or as raw bytes.
    """
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


def is_exfat(fh: BinaryIO) -> bool:
    """Check if the given file-like object contains an exFAT filesystem by validating the BPB.

    Args:
        fh: File-like object to check.
    """
    fh.seek(0)
    try:
        validate_bpb(fh.read(512))
    except InvalidBPB:
        return False
    else:
        return True


class DirectoryEntry:
    """exFAT directory entry implementation.

    Args:
        fs: The exFAT filesystem this directory entry belongs to.
        fh: File-like object positioned at the start of the directory entry to read.
    """

    def __init__(self, fs: ExFAT, fh: BinaryIO | None):
        self.fs = fs

        self.dirent, self.secondary_dirent = self._read_dirent(fh)
        self.streament = None

        if self.type == c_exfat.EXFAT_BITMAP:
            self.streament = self.dirent.dentry.bitmap
        elif self.type == c_exfat.EXFAT_UPCASE:
            self.streament = self.dirent.dentry.upcase
        elif self.type == c_exfat.EXFAT_FILE:
            for entry in self.secondary_dirent:
                if entry.type == c_exfat.EXFAT_STREAM:
                    self.streament = entry.dentry.stream
                    break

        self._runlist = None

    def _read_dirent(self, fh: BinaryIO | None) -> tuple[c_exfat.exfat_dentry, list[c_exfat.exfat_dentry]]:
        """Read a directory entry from the given file handle, handling secondary entries if present.

        Args:
            fh: File-like object positioned at the start of the directory entry to read.

        Returns:
            A tuple containing the directory entry and a list of secondary directory entries.
        """
        if fh is None:
            return None, []

        dentry = c_exfat.exfat_dentry(fh)
        secondary_dentries = []

        if dentry.type == 0x00:
            raise EmptyDirectoryError("Dirent is an empty entry")

        if dentry.type < 0x80:
            raise DeletedDirectoryError("Dirent is marked as deleted")

        if dentry.type == c_exfat.EXFAT_FILE:
            secondary_dentries = [c_exfat.exfat_dentry(fh) for _ in range(dentry.dentry.file.num_ext)]

        return dentry, secondary_dentries

    @cached_property
    def type(self) -> int:
        """Return the type of the directory entry."""
        return self.dirent.type

    @cached_property
    def name(self) -> str:
        """Return the name of the directory entry."""
        if self.type == c_exfat.EXFAT_BITMAP:
            return "$ALLOC_BITMAP"
        if self.type == c_exfat.EXFAT_UPCASE:
            return "$UPCASE_TABLE"

        name_entries = [e for e in self.secondary_dirent if e.type == c_exfat.EXFAT_NAME]
        return b"".join([bytes(e.dentry.name.unicode_0_14).strip(b"\x00") for e in name_entries]).decode()

    @cached_property
    def attr(self) -> int:
        """Return the attribute value of the directory entry."""
        return self.dirent.dentry.file.attr if self.type == c_exfat.EXFAT_FILE else 0

    @property
    def size(self) -> int:
        """Return the size of the directory entry in bytes."""
        return self.streament.size

    @property
    def cluster(self) -> int:
        """Return the starting cluster number of the directory entry."""
        return self.streament.start_clu

    @property
    def ctime(self) -> datetime.datetime:
        """Return the creation time of the directory entry."""
        if self.type == c_exfat.EXFAT_FILE:
            return dostimestamp(
                (self.dirent.file.create_date << 16 | self.dirent.file.create_time),
                self.dirent.file.create_time_cs,
            ).replace(tzinfo=_timezone(self.dirent.file.create_tz))

        return datetime.datetime(1980, 1, 1)  # noqa: DTZ001

    @property
    def atime(self) -> datetime.datetime:
        """Return the last access time of the directory entry."""
        if self.type == c_exfat.EXFAT_FILE:
            return dostimestamp(
                (self.dirent.file.access_date << 16 | self.dirent.file.access_time),
            ).replace(tzinfo=_timezone(self.dirent.file.access_tz))

        return datetime.datetime(1980, 1, 1)  # noqa: DTZ001

    @property
    def mtime(self) -> datetime.datetime:
        """Return the last modification time of the directory entry."""
        if self.type == c_exfat.EXFAT_FILE:
            return dostimestamp(
                (self.dirent.file.modify_date << 16 | self.dirent.file.modify_time),
                self.dirent.file.modify_time_cs,
            ).replace(tzinfo=_timezone(self.dirent.file.modify_tz))

        return datetime.datetime(1980, 1, 1)  # noqa: DTZ001

    def is_readonly(self) -> bool:
        """Return whether the directory entry is read-only."""
        return bool(self.attr & c_fat.ATTR_READ_ONLY)

    def is_hidden(self) -> bool:
        """Return whether the directory entry is hidden."""
        return bool(self.attr & c_fat.ATTR_HIDDEN)

    def is_system(self) -> bool:
        """Return whether the directory entry is a system file."""
        return bool(self.attr & c_fat.ATTR_SYSTEM)

    def is_volume_id(self) -> bool:
        """Return whether the directory entry is a volume ID."""
        return bool(self.attr & c_fat.ATTR_VOLUME_ID)

    def is_directory(self) -> bool:
        """Return whether the directory entry is a directory."""
        return bool(self.attr & c_fat.ATTR_DIRECTORY)

    def is_archive(self) -> bool:
        """Return whether the directory entry has the archive attribute set."""
        return bool(self.attr & c_fat.ATTR_ARCHIVE)

    def listdir(self) -> list[str]:
        """Return a list of names of the entries in the directory."""
        return [entry.name for entry in self.iterdir()]

    def iterdir(self) -> Iterator[DirectoryEntry]:
        """Yield the directory entries in the directory."""
        if not self.is_directory():
            raise NotADirectoryError(self.name)

        for entry in _iter_dirent(self.fs, self.open()):
            if entry.type == c_exfat.EXFAT_VOLUME:
                continue

            yield entry

    def dataruns(self) -> list[tuple[int, int]]:
        """Return the runlist of the directory entry."""
        if self._runlist is None:
            self._runlist = [] if self.cluster == FAT.FREE_CLUSTER else list(self.fs.fat.runlist(self.cluster))

        return self._runlist

    def open(self) -> RunlistStream | RangeStream:
        """Open the directory entry for reading."""
        if self.streament.flags == c_exfat.ALLOC_FAT_CHAIN:
            return RunlistStream(self.fs.data_stream, self.dataruns(), self.size, self.fs.cluster_size)

        return RangeStream(
            self.fs.data_stream,
            (self.cluster - 2) * self.fs.cluster_size,
            self.size,
            self.fs.cluster_size,
        )


class RootDirectory(DirectoryEntry):
    """Root directory implementation."""

    def __init__(self, fs: ExFAT) -> None:
        super().__init__(fs, None)

    @cached_property
    def type(self) -> int:
        return c_exfat.EXFAT_INVAL

    @property
    def name(self) -> str:
        return ""

    @cached_property
    def attr(self) -> int:
        return c_fat.ATTR_DIRECTORY

    @property
    def size(self) -> int:
        return sum(map(itemgetter(1), self.dataruns())) * self.fs.cluster_size

    @property
    def cluster(self) -> int:
        return self.fs.bpb.root_cluster

    def open(self) -> RunlistStream:
        return RunlistStream(self.fs.data_stream, self.dataruns(), self.size, self.fs.cluster_size)


def _iter_dirent(fs: ExFAT, fh: BinaryIO) -> Iterator[DirectoryEntry]:
    while True:
        try:
            yield DirectoryEntry(fs, fh)
        except EmptyDirectoryError:  # noqa: PERF203
            continue
        except DeletedDirectoryError:
            continue
        except LastEmptyDirectoryError:
            break
        except EOFError:
            break


def exfat_checksum32(data: bytes) -> int:
    checksum = 0
    for idx, byte in enumerate(data):
        if idx in (106, 107, 112):  # skip vol_flags, percent_in_use
            continue

        checksum = ((checksum << 31) | (checksum >> 1)) + byte
        checksum &= 0xFFFFFFFF
    return checksum


@lru_cache(8)
def _timezone(timezone: int) -> datetime.timezone:
    """Convert exFAT timezone byte to a timezone object."""
    # timezone is a signed 7-bit number of 15-minute intervals from UTC
    offset = (timezone & 0x3F) - 0x40 if (timezone & 0x40) else (timezone & 0x7F)
    return datetime.timezone(datetime.timedelta(minutes=offset * 15))
