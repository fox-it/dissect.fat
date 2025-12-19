# References:
# - https://ogris.de/fatrepair/fat.c
# - https://github.com/nathanhi/pyfatfs
# - https://download.microsoft.com/download/1/6/1/161ba512-40e2-4cc9-843a-923143f3456c/fatgen103.doc
from __future__ import annotations

import datetime
from operator import itemgetter
from typing import TYPE_CHECKING, BinaryIO

from dissect.util.stream import RangeStream, RunlistStream
from dissect.util.ts import dostimestamp

from dissect.fat import fat
from dissect.fat.c_fat import (
    FREE_CLUSTER,
    VALID_BPB_MEDIA,
    Fattype,
    c_fat,
)
from dissect.fat.exceptions import (
    EmptyDirectoryError,
    FileNotFoundError,
    InvalidBPB,
    InvalidDirectoryError,
    LastEmptyDirectoryError,
    NotADirectoryError,
)

if TYPE_CHECKING:
    from collections.abc import Iterator


class FATFS:
    def __init__(self, fh: BinaryIO, encoding: str = "ibm437"):
        self.fh = fh
        self.encoding = encoding

        fh.seek(0)
        sector = fh.read(512)
        bpb_size = len(c_fat.Bpb)
        self.bpb = c_fat.Bpb(sector[:bpb_size])
        bpb16 = c_fat.Bpb16(sector[bpb_size:])
        bpb32 = c_fat.Bpb32(sector[bpb_size:])

        validate_bpb(self.bpb)

        self.fat_size = self.bpb.BPB_FATSz16 or bpb32.BPB_FATSz32
        self.total_sectors = self.bpb.BPB_TotSec16 or self.bpb.BPB_TotSec32

        # Taken from FAT32 spec
        root_dir_sectors = ((self.bpb.BPB_RootEntCnt * 32) + (self.bpb.BPB_BytsPerSec - 1)) // self.bpb.BPB_BytsPerSec
        self.first_data_sector = self.bpb.BPB_RsvdSecCnt + (self.bpb.BPB_NumFATs * self.fat_size) + root_dir_sectors

        data_sec = self.total_sectors - self.first_data_sector
        count_of_clusters = data_sec // self.bpb.BPB_SecPerClus
        if count_of_clusters < 4085:
            self.type = Fattype.FAT12
            self.bpb_ext = bpb16
        elif count_of_clusters < 65525:
            self.type = Fattype.FAT16
            self.bpb_ext = bpb16
        else:
            self.type = Fattype.FAT32
            self.bpb_ext = bpb32

        self.sector_size = self.bpb.BPB_BytsPerSec
        self.cluster_size = self.bpb.BPB_BytsPerSec * self.bpb.BPB_SecPerClus

        # FAT starts after reserved sectors
        # Only parse the first FAT for now
        fat_stream = RangeStream(
            fh,
            self.bpb.BPB_RsvdSecCnt * self.sector_size,
            self.fat_size * self.sector_size,
        )
        self.fat = fat.FAT(fat_stream, self.type)
        self.data_stream = RangeStream(fh, self.first_data_sector * self.sector_size, data_sec * self.sector_size)

        # volume label with stripped padding
        self.volume_label = bytes(self.bpb_ext.BS_VolLab).strip(b"\x20").decode(encoding)

        # volume serial number, hex encoded
        self.volume_id = f"{self.bpb_ext.BS_VolID:x}"

        self.root = FatRootDirectory(self)

    def get(
        self, path: str, dirent: FatDirectoryEntry | FatRootDirectory | None = None
    ) -> FatDirectoryEntry | FatRootDirectory:
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


def validate_bpb(bpb: c_fat.Bpb | bytes) -> None:
    if isinstance(bpb, bytes):
        bpb = c_fat.Bpb(bpb[: len(c_fat.Bpb)])

    # Detect a valid x86 JMP opcode
    if not (bpb.BS_jmpBoot[0] == 0xEB and bpb.BS_jmpBoot[2] == 0x90) and bpb.BS_jmpBoot[0] != 0xE9:
        raise InvalidBPB(f"Invalid BS_jmpBoot: {bytes(bpb.BS_jmpBoot)!r}")

    if bpb.BPB_BytsPerSec not in [2**x for x in range(9, 13)]:
        raise InvalidBPB(f"Invalid BPB_BytsPerSec: 0x{bpb.BPB_BytsPerSec:x}")

    if bpb.BPB_SecPerClus not in [2**x for x in range(8)]:
        raise InvalidBPB(f"Invalid BPB_SecPerClus: 0x{bpb.BPB_SecPerClus:x}")

    if bpb.BPB_RsvdSecCnt == 0:
        raise InvalidBPB(f"Invalid BPB_RsvdSecCnt, must not be 0: 0x{bpb.BPB_RsvdSecCnt:x}")

    if bpb.BPB_Media not in VALID_BPB_MEDIA:
        raise InvalidBPB(f"Invalid BPB_Media: 0x{bpb.BPB_Media:x}")

    if bpb.BPB_NumFATs < 1:
        raise InvalidBPB(f"Invalid BPB_NumFATs, must be at least 1: 0x{bpb.BPB_NumFATs:x}")

    root_entry_count = bpb.BPB_RootEntCnt * 32
    root_entry_count %= bpb.BPB_BytsPerSec
    if bpb.BPB_RootEntCnt != 0 and root_entry_count != 0:
        raise InvalidBPB("Root entry count does not align with bytes per sector")

    if bpb.BPB_TotSec16 == 0 and bpb.BPB_TotSec32 == 0:
        raise InvalidBPB(f"Invalid BPB_TotSec16 and BPB_TotSec32: 0x{bpb.BPB_TotSec16:x}, 0x{bpb.BPB_TotSec32:x}")


class FatDirectoryEntry:
    def __init__(self, fs: FATFS, fh: BinaryIO, parent: FatDirectoryEntry | FatRootDirectory | None = None):
        self.fs = fs
        self.parent = parent

        self.dirent = None
        self.ldirents = []

        buf = fh.read(32)
        dirent = c_fat.Dirent(buf)
        self.attr = dirent.DIR_Attr
        self.type = dirent.DIR_Name[0]

        if self.type == 0xE5:
            raise EmptyDirectoryError("Dirent is an empty entry")

        if self.type == 0x0:
            raise LastEmptyDirectoryError("Dirent is the last empty entry")

        if dirent.DIR_Attr & c_fat.ATTR_LONG_NAME_MASK == c_fat.ATTR_LONG_NAME:
            ldirent = c_fat.Ldirent(buf)
            found_last = False
            while ldirent.LDIR_Attr == c_fat.ATTR_LONG_NAME:
                self.ldirents.append(ldirent)
                if ldirent.LDIR_Ord & c_fat.LAST_LONG_ENTRY:
                    if found_last:
                        raise InvalidDirectoryError("Dirent contains multiple last-long entries")
                    found_last = True

                buf = fh.read(32)
                ldirent = c_fat.Ldirent(buf)

            self.dirent = c_fat.Dirent(buf)
            self.attr = self.dirent.DIR_Attr
            self.type = self.dirent.DIR_Name[0]
        else:
            self.dirent = dirent

        self._runlist = None
        self._entries = None

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name}>"

    @property
    def path(self) -> str:
        return "\\".join([self.parent.path if self.parent else "", self.name]).lstrip("\\")

    @property
    def size(self) -> int:
        if self.is_directory():
            return sum(map(itemgetter(1), self.dataruns())) * self.fs.cluster_size
        return self.dirent.DIR_FileSize

    @property
    def cluster(self) -> int:
        return (self.dirent.DIR_FstClusHI << 16) | self.dirent.DIR_FstClusLO

    @property
    def name(self) -> str:
        return self.long_name or self.short_name

    @property
    def long_name(self) -> str | None:
        """Construct long file name (LFN) from LDIR_Name parts."""
        self.ldirents.sort(key=lambda e: e.LDIR_Ord & 0x3F)
        name_parts = (bytes(e.LDIR_Name1 + e.LDIR_Name2 + e.LDIR_Name3) for e in self.ldirents)
        return c_fat.wchar[None](b"".join(name_parts) + b"\x00\x00")

    @property
    def short_name(self) -> str:
        """Construct short file name (SFN) from DIR_Name."""
        dir_name = bytearray(self.dirent.DIR_Name)
        if dir_name[0] == 0x05:
            dir_name[0] = 0xE5

        base = dir_name[:8].decode(self.fs.encoding).rstrip("\x00").rstrip()
        ext = dir_name[8:].decode(self.fs.encoding).rstrip("\x00").rstrip()
        return f"{base}.{ext}" if ext else base

    @property
    def ctime(self) -> datetime.datetime:
        if self.dirent.DIR_CrtDate and self.dirent.DIR_CrtTime:
            return dostimestamp(
                (self.dirent.DIR_CrtDate << 16) | self.dirent.DIR_CrtTime,
                self.dirent.DIR_CrtTimeTenth,
            )
        return datetime.datetime(1980, 1, 1)  # noqa: DTZ001

    @property
    def atime(self) -> datetime.datetime:
        if self.dirent.DIR_LstAccDate:
            return dostimestamp(self.dirent.DIR_LstAccDate << 16)
        return datetime.datetime(1980, 1, 1)  # noqa: DTZ001

    @property
    def mtime(self) -> datetime.datetime:
        return dostimestamp((self.dirent.DIR_WrtDate << 16) | self.dirent.DIR_WrtTime)

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

    def listdir(self) -> list[str]:
        return [entry.name for entry in self.iterdir()]

    def iterdir(self) -> Iterator[FatDirectoryEntry]:
        if not self.is_directory():
            raise NotADirectoryError(self.name)

        if not self._entries:
            entries = []
            for entry in iter_dirent(self.fs, self.open(), self):
                yield entry
                entries.append(entry)
            self._entries = entries
        else:
            yield from self._entries

    def dataruns(self) -> list[tuple[int, int]]:
        if self._runlist is None:
            self._runlist = [] if self.cluster == FREE_CLUSTER else list(self.fs.fat.runlist(self.cluster))
        return self._runlist

    def open(self) -> RunlistStream:
        return RunlistStream(self.fs.data_stream, self.dataruns(), self.size, self.fs.cluster_size)


class FatRootDirectory(FatDirectoryEntry):
    def __init__(self, fs: FATFS):
        self.fs = fs

        self._runlist = None
        self._entries = None

    @property
    def name(self) -> str:
        return "\\"

    @property
    def path(self) -> str:
        return ""

    @property
    def size(self) -> int:
        if self.fs.type in (Fattype.FAT12, Fattype.FAT16):
            return self.fs.bpb.BPB_RootEntCnt * 32
        return sum(map(itemgetter(1), self.dataruns())) * self.fs.cluster_size

    @property
    def cluster(self) -> int | None:
        if self.fs.type == Fattype.FAT32:
            return self.fs.bpb_ext.BPB_RootClus
        return None

    @property
    def ctime(self) -> datetime.datetime:
        return datetime.datetime(1980, 1, 1)  # noqa: DTZ001

    @property
    def atime(self) -> datetime.datetime:
        return datetime.datetime(1980, 1, 1)  # noqa: DTZ001

    @property
    def mtime(self) -> datetime.datetime:
        return datetime.datetime(1980, 1, 1)  # noqa: DTZ001

    def is_readonly(self) -> bool:
        return False

    def is_hidden(self) -> bool:
        return False

    def is_system(self) -> bool:
        return False

    def is_volume_id(self) -> bool:
        return False

    def is_directory(self) -> bool:
        return True

    def is_archive(self) -> bool:
        return False

    def dataruns(self) -> list[tuple[int, int]]:
        if self._runlist is None:
            self._runlist = [] if self.cluster == FREE_CLUSTER else list(self.fs.fat.runlist(self.cluster))
        return self._runlist

    def open(self) -> RangeStream | RunlistStream:
        if self.fs.type in (Fattype.FAT12, Fattype.FAT16):
            root_dir_sector = self.fs.bpb.BPB_RsvdSecCnt + (self.fs.fat_size * self.fs.bpb.BPB_NumFATs)
            offset = root_dir_sector * self.fs.sector_size
            return RangeStream(self.fs.fh, offset, self.size)
        return RunlistStream(self.fs.data_stream, self.dataruns(), self.size, self.fs.cluster_size)


def iter_dirent(
    fs: FATFS,
    fh: BinaryIO,
    parent: FatDirectoryEntry | FatRootDirectory | None = None,
) -> Iterator[FatDirectoryEntry]:
    while True:
        try:
            yield FatDirectoryEntry(fs, fh, parent)
        except EmptyDirectoryError:  # noqa: PERF203
            continue
        except LastEmptyDirectoryError:
            break
        except EOFError:
            break
