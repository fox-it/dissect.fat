# References:
# - https://ogris.de/fatrepair/fat.c
# - https://github.com/nathanhi/pyfatfs
# - https://download.microsoft.com/download/1/6/1/161ba512-40e2-4cc9-843a-923143f3456c/fatgen103.doc
from __future__ import annotations

from functools import cached_property
from typing import TYPE_CHECKING

from dissect.util.stream import RangeStream
from dissect.util.ts import dostimestamp

from dissect.fat.base import FAT, FS, BaseDirectoryEntry, FatType, iter_dirent
from dissect.fat.c_fat import c_fat
from dissect.fat.exception import (
    DeletedDirectoryError,
    InvalidBootSector,
    InvalidDirectoryError,
    LastEmptyDirectoryError,
)

if TYPE_CHECKING:
    import datetime
    from collections.abc import Iterator
    from typing import BinaryIO

    from dissect.util.stream import RunlistStream


class FATFS(FS):
    """FAT filesystem implementation supporting FAT12, FAT16 and FAT32.

    Automatically detects FAT type based on BPB.

    Args:
        fh: File-like object containing the FAT filesystem.
        encoding: Encoding to use for decoding file names. Defaults to "ibm437".
    """

    def __init__(self, fh: BinaryIO, encoding: str = "ibm437"):
        self.fh = fh
        self.encoding = encoding

        fh.seek(0)
        buf = fh.read(512)
        self.boot_sector = c_fat._BOOT_SECTOR(buf)
        if self.boot_sector.Bpb.SectorsPerFat == 0:
            self.boot_sector = c_fat._BOOT_SECTOR_EX(buf)

        validate_boot_sector(self.boot_sector)

        bpb = self.boot_sector.Bpb
        self.fat_size = bpb.SectorsPerFat or bpb.LargeSectorsPerFat
        self.total_sectors = bpb.Sectors or bpb.LargeSectors

        self.sector_size = bpb.BytesPerSector
        self.cluster_size = bpb.BytesPerSector * bpb.SectorsPerCluster

        # Taken from FAT32 spec
        root_dir_sectors = ((bpb.RootEntries * 32) + (self.sector_size - 1)) // self.sector_size
        self.first_data_sector = bpb.ReservedSectors + (bpb.Fats * self.fat_size) + root_dir_sectors

        data_sec = self.total_sectors - self.first_data_sector
        count_of_clusters = data_sec // bpb.SectorsPerCluster
        if count_of_clusters < 4085:
            self.__class__ = FAT12
            self.type = FatType.FAT12
            bits_per_entry = 12
        elif count_of_clusters < 65525:
            self.__class__ = FAT16
            self.type = FatType.FAT16
            bits_per_entry = 16
        else:
            self.__class__ = FAT32
            self.type = FatType.FAT32
            # Yes, FAT32 actually only uses 28 bits for cluster numbers
            bits_per_entry = 28

        # FAT starts after reserved sectors
        # Only parse the first FAT for now
        fat_stream = RangeStream(
            fh,
            bpb.ReservedSectors * self.sector_size,
            self.fat_size * self.sector_size,
        )
        self.fat = FAT(fat_stream, fat_stream.size, bits_per_entry)
        self.data = RangeStream(fh, self.first_data_sector * self.sector_size, data_sec * self.sector_size)

        # Volume label with stripped padding
        self.volume_label = bytes(self.boot_sector.VolumeLabel).strip(b"\x20").decode(encoding)

        # Volume serial number, hex encoded
        self.volume_id = f"{self.boot_sector.Id:x}"

        self.root = RootDirectory(self)

    def _match(self, name: str, dirent: DirectoryEntry) -> bool:
        return name in (dirent.long_name.upper(), dirent.short_name.upper())


class FAT12(FATFS):
    """FAT12 filesystem implementation.

    Enforces that the BPB indicates a FAT12 filesystem.

    Args:
        fh: File-like object containing the FAT filesystem.
        encoding: Encoding to use for decoding file names. Defaults to "ibm437".
    """

    def __init__(self, fh: BinaryIO, encoding: str = "ibm437"):
        super().__init__(fh, encoding)
        if self.type != FatType.FAT12:
            raise InvalidBootSector("BPB does not indicate FAT12 filesystem")


class FAT16(FATFS):
    """FAT16 filesystem implementation.

    Enforces that the BPB indicates a FAT16 filesystem.

    Args:
        fh: File-like object containing the FAT filesystem.
        encoding: Encoding to use for decoding file names. Defaults to "ibm437".
    """

    def __init__(self, fh: BinaryIO, encoding: str = "ibm437"):
        super().__init__(fh, encoding)
        if self.type != FatType.FAT16:
            raise InvalidBootSector("BPB does not indicate FAT16 filesystem")


class FAT32(FATFS):
    """FAT32 filesystem implementation.

    Enforces that the BPB indicates a FAT32 filesystem.

    Args:
        fh: File-like object containing the FAT filesystem.
        encoding: Encoding to use for decoding file names. Defaults to "ibm437".
    """

    def __init__(self, fh: BinaryIO, encoding: str = "ibm437"):
        super().__init__(fh, encoding)
        if self.type != FatType.FAT32:
            raise InvalidBootSector("BPB does not indicate FAT32 filesystem")


class DirectoryEntry(BaseDirectoryEntry):
    """FAT directory entry implementation.

    Args:
        fs: The FAT filesystem this directory entry belongs to.
        fh: File-like object positioned at the start of the directory entry to read.
    """

    fs: FATFS
    dirent: c_fat.DIRENT
    secondary_dirents: list[c_fat.LFN_DIRENT]

    def _read_dirent(self, fh: BinaryIO) -> tuple[c_fat.DIRENT, list[c_fat.LFN_DIRENT]]:
        """Read a directory entry from the given file handle, handling long file name entries if present.

        Args:
            fh: File-like object positioned at the start of the directory entry to read.

        Returns:
            A tuple containing the directory entry and a list of long directory entries.
        """
        buf = fh.read(32)
        dirent = c_fat.DIRENT(buf)
        ldirents = []

        if dirent.FileName[0] == c_fat.FAT_DIRENT_DELETED:
            raise DeletedDirectoryError("Dirent is marked as deleted")

        if dirent.FileName[0] == c_fat.FAT_DIRENT_NEVER_USED:
            raise LastEmptyDirectoryError("Dirent is the last empty entry")

        if dirent.Attributes == c_fat.FAT_DIRENT_ATTR_LFN:
            ldirent = c_fat.LFN_DIRENT(buf)
            found_last = False
            while ldirent.Attributes == c_fat.FAT_DIRENT_ATTR_LFN:
                ldirents.append(ldirent)
                if ldirent.Ordinal & c_fat.FAT_LAST_LONG_ENTRY:
                    if found_last:
                        raise InvalidDirectoryError("Dirent contains multiple last-long entries")
                    found_last = True

                buf = fh.read(32)
                ldirent = c_fat.LFN_DIRENT(buf)

            return c_fat.DIRENT(buf), ldirents

        return dirent, ldirents

    @cached_property
    def name(self) -> str:
        """Return the canonical name of the directory entry."""
        return self.long_name or self.short_name

    @cached_property
    def long_name(self) -> str | None:
        """Construct long file name (LFN) from LDIR_Name parts."""
        ldirents = sorted(self.secondary_dirents, key=lambda e: e.Ordinal & 0x3F)
        name_parts = (bytes(e.Name1 + e.Name2 + e.Name3) for e in ldirents)
        return c_fat.wchar[None](b"".join(name_parts) + b"\x00\x00")

    @cached_property
    def short_name(self) -> str:
        """Construct short file name (SFN) from DIR_Name."""
        dir_name = bytearray(self.dirent.FileName)
        if dir_name[0] == 0x05:
            dir_name[0] = 0xE5

        base = dir_name[:8].decode(self.fs.encoding).rstrip("\x00").rstrip()
        ext = dir_name[8:].decode(self.fs.encoding).rstrip("\x00").rstrip()
        return f"{base}.{ext}" if ext else base

    @cached_property
    def attr(self) -> int:
        """Return the attribute value of the directory entry."""
        return self.dirent.Attributes

    @cached_property
    def size(self) -> int:
        """Return the size of the directory entry in bytes."""
        if self.is_directory():
            return super().size

        return self.dirent.FileSize

    @cached_property
    def cluster(self) -> int:
        """Return the starting cluster number of the directory entry."""
        return (self.dirent.FirstClusterOfFileHi << 16) | self.dirent.FirstClusterOfFile

    @cached_property
    def ctime(self) -> datetime.datetime:
        """Return the creation time of the directory entry."""
        if self.dirent and (self.dirent.CreationDate or self.dirent.CreationTime):
            return dostimestamp(
                (self.dirent.CreationDate << 16) | self.dirent.CreationTime,
                self.dirent.CreationMSec,
            )

        return super().ctime

    @cached_property
    def atime(self) -> datetime.datetime:
        """Return the last access time of the directory entry."""
        if self.dirent and self.dirent.LastAccessDate:
            return dostimestamp(self.dirent.LastAccessDate << 16)

        return super().atime

    @cached_property
    def mtime(self) -> datetime.datetime:
        if self.dirent:
            return dostimestamp((self.dirent.LastWriteDate << 16) | self.dirent.LastWriteTime)

        return super().mtime

    def _iterdir(self, fh: BinaryIO) -> Iterator[DirectoryEntry]:
        yield from iter_dirent(DirectoryEntry, self.fs, fh)


class RootDirectory(DirectoryEntry):
    """Root directory implementation."""

    def __init__(self, fs: FATFS):
        super().__init__(fs, None)

    @cached_property
    def long_name(self) -> str:
        return ""

    @cached_property
    def short_name(self) -> str:
        return ""

    @cached_property
    def attr(self) -> int:
        return c_fat.FAT_DIRENT_ATTR_DIRECTORY

    @cached_property
    def size(self) -> int:
        if self.fs.type in (FatType.FAT12, FatType.FAT16):
            return self.fs.boot_sector.Bpb.RootEntries * 32

        return super().size

    @cached_property
    def cluster(self) -> int:
        if self.fs.type == FatType.FAT32:
            return self.fs.boot_sector.Bpb.RootDirFirstCluster

        return -1

    def open(self) -> RangeStream | RunlistStream:
        if self.fs.type in (FatType.FAT12, FatType.FAT16):
            root_dir_sector = self.fs.boot_sector.Bpb.ReservedSectors + (
                self.fs.fat_size * self.fs.boot_sector.Bpb.Fats
            )
            offset = root_dir_sector * self.fs.sector_size
            return RangeStream(self.fs.fh, offset, self.size)

        return super().open()


VALID_BPB_MEDIA = {0xF0, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF}


def validate_boot_sector(sector: c_fat.BOOT_SECTOR | bytes) -> None:
    """Validate the boot sector according to FAT specification. Raises :class:`InvalidBPB` if any field is invalid.

    Args:
        sector: The boot sector to validate, either as a parsed structure or as raw bytes.
    """
    if isinstance(sector, bytes):
        sector = c_fat.BOOT_SECTOR(sector)

    # Detect a valid x86 JMP opcode
    if not (sector.Jump[0] == 0xEB and sector.Jump[2] == 0x90) and sector.Jump[0] != 0xE9:
        raise InvalidBootSector(f"Invalid Jump: {bytes(sector.Jump)!r}")

    bpb = sector.Bpb
    if bpb.BytesPerSector not in [2**x for x in range(9, 13)]:
        raise InvalidBootSector(f"Invalid Bpb.BytesPerSector: 0x{bpb.BytesPerSector:x}")

    if bpb.SectorsPerCluster not in [2**x for x in range(8)]:
        raise InvalidBootSector(f"Invalid Bpb.SectorsPerCluster: 0x{bpb.SectorsPerCluster:x}")

    if bpb.ReservedSectors == 0:
        raise InvalidBootSector(f"Invalid Bpb.ReservedSectors, must not be 0: 0x{bpb.ReservedSectors:x}")

    if bpb.Fats < 1:
        raise InvalidBootSector(f"Invalid Bpb.Fats, must be at least 1: 0x{bpb.Fats:x}")

    if bpb.Media not in VALID_BPB_MEDIA:
        raise InvalidBootSector(f"Invalid Bpb.Media: 0x{bpb.Media:x}")

    root_entry_count = bpb.RootEntries * 32
    root_entry_count %= bpb.BytesPerSector
    if bpb.RootEntries != 0 and root_entry_count != 0:
        raise InvalidBootSector("Root entry count does not align with bytes per sector")

    if bpb.Sectors == 0 and bpb.LargeSectors == 0:
        raise InvalidBootSector(f"Invalid Bpb.Sectors and Bpb.LargeSectors: 0x{bpb.Sectors:x}, 0x{bpb.LargeSectors:x}")


def is_fat(fh: BinaryIO) -> bool:
    """Check if the given file-like object contains a FAT filesystem by validating the BPB.

    Args:
        fh: File-like object to check.
    """
    fh.seek(0)
    try:
        validate_boot_sector(fh.read(512))
    except InvalidBootSector:
        return False
    else:
        return True
