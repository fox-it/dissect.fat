# Resources:
# - https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification
from __future__ import annotations

import datetime
from functools import cached_property, lru_cache
from typing import TYPE_CHECKING, BinaryIO

from dissect.util.stream import RangeStream
from dissect.util.ts import dostimestamp

from dissect.fat.base import FAT, FS, BaseDirectoryEntry, FatType, iter_dirent
from dissect.fat.c_exfat import c_exfat
from dissect.fat.c_fat import c_fat
from dissect.fat.exception import DeletedDirectoryError, InvalidBootSector, LastEmptyDirectoryError

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.util.stream import RunlistStream

    from dissect.fat.c_exfat import PRIMARY_DIRENT, SECONDARY_DIRENT


# Main boot region is 12 sectors long
BOOT_REGION_SIZE = 512 * 12


class ExFAT(FS):
    """exFAT filesystem implementation.

    Args:
        fh: File-like object containing the FAT filesystem.
    """

    def __init__(self, fh: BinaryIO) -> None:
        self.fh = fh
        self.type = FatType.EXFAT

        fh.seek(0)
        boot_region = fh.read(BOOT_REGION_SIZE)
        self.boot_sector = c_exfat.BOOT_SECTOR(boot_region)
        validate_boot_sector(self.boot_sector)

        # Checksum is calculated over the first 11 sectors
        self.checksum = _checksum32(boot_region[: BOOT_REGION_SIZE - 512])
        # Read the stored checksum
        if self.checksum != c_exfat.uint32(boot_region[BOOT_REGION_SIZE - 512 : BOOT_REGION_SIZE]):
            raise InvalidBootSector("Invalid exFAT boot region checksum")

        # Sector size in bytes
        self.sector_size = 1 << self.boot_sector.BytesPerSectorShift
        # Cluster size in bytes
        self.cluster_size = self.sector_size * (1 << self.boot_sector.SectorsPerClusterShift)

        fat_stream = RangeStream(
            fh,
            # FatOffset is stored in sectors
            self.boot_sector.FatOffset * self.sector_size,
            # FatLength is stored in sectors
            self.boot_sector.FatLength * self.sector_size,
        )
        self.fat = FAT(fat_stream, fat_stream.size, 32)
        self.data = RangeStream(
            fh,
            # ClusterHeapOffset is stored in sectors
            self.boot_sector.ClusterHeapOffset * self.sector_size,
            # ClusterCount is stored in clusters
            self.boot_sector.ClusterCount * self.cluster_size,
        )

        self.root = RootDirectory(self)

        self.volume_label = ""
        with self.root.open() as rootfh:
            dirent = c_exfat.VOLUME_LABEL_DIRENT(rootfh)
            if dirent.EntryType == c_exfat.EXFAT_DIRENT_TYPE_VOLUME_LABEL:
                self.volume_label = bytes(dirent.VolumeLabel).decode("utf-16").rstrip("\x00")

        # Volume serial number, hex encoded
        self.volume_id = f"{self.boot_sector.VolumeSerialNumber:x}"


class DirectoryEntry(BaseDirectoryEntry):
    """exFAT directory entry implementation.

    Args:
        fs: The exFAT filesystem this directory entry belongs to.
        fh: File-like object positioned at the start of the directory entry to read.
    """

    fs: ExFAT
    dirent: PRIMARY_DIRENT
    secondary_dirents: list[SECONDARY_DIRENT]

    def __init__(self, fs: ExFAT, fh: BinaryIO | None):
        super().__init__(fs, fh)
        self.streament = None

        if self.type in (c_exfat.EXFAT_DIRENT_TYPE_ALLOC_BITMAP, c_exfat.EXFAT_DIRENT_TYPE_VOLUME_LABEL):
            self.streament = self.dirent
        elif self.type == c_exfat.EXFAT_DIRENT_TYPE_FILE:
            for entry in self.secondary_dirents:
                if entry.EntryType == c_exfat.EXFAT_DIRENT_TYPE_STREAM_EXT:
                    self.streament = entry
                    break

    def _read_dirent(self, fh: BinaryIO) -> tuple[PRIMARY_DIRENT, list[SECONDARY_DIRENT]]:
        """Read a directory entry from the given file handle, handling secondary entries if present.

        Args:
            fh: File-like object positioned at the start of the directory entry to read.

        Returns:
            A tuple containing the primary directory entry and a list of secondary directory entries.
        """
        buf = fh.read(c_exfat.EXFAT_DIRENT_SIZE)
        secondary_dirents = []

        if not buf or buf[0] == c_exfat.EXFAT_DIRENT_TYPE_END:
            raise LastEmptyDirectoryError("Dirent is the last empty entry")

        if buf[0] < c_exfat.EXFAT_DIRENT_TYPE_UNUSED:
            raise DeletedDirectoryError("Dirent is marked as deleted")

        match buf[0]:
            case c_exfat.EXFAT_DIRENT_TYPE_ALLOC_BITMAP:
                dirent = c_exfat.ALLOC_BITMAP_DIRENT(buf)
            case c_exfat.EXFAT_DIRENT_TYPE_UPCASE:
                dirent = c_exfat.UPCASE_DIRENT(buf)
            case c_exfat.EXFAT_DIRENT_TYPE_VOLUME_LABEL:
                dirent = c_exfat.VOLUME_LABEL_DIRENT(buf)
            case c_exfat.EXFAT_DIRENT_TYPE_FILE:
                dirent = c_exfat.FILE_DIRENT(buf)
            case c_exfat.EXFAT_DIRENT_TYPE_VOLUME_GUID:
                dirent = c_exfat.VOLUME_GUID_DIRENT(buf)
            case _:
                dirent = c_exfat.GENERIC_PRIMARY_DIRENT(buf)

        for _ in range(getattr(dirent, "SecondaryCount", 0)):
            buf = fh.read(c_exfat.EXFAT_DIRENT_SIZE)
            match buf[0]:
                case c_exfat.EXFAT_DIRENT_TYPE_STREAM_EXT:
                    secondary = c_exfat.STREAM_EXT_DIRENT(buf)
                case c_exfat.EXFAT_DIRENT_TYPE_FILE_NAME:
                    secondary = c_exfat.FILE_NAME_DIRENT(buf)
                case c_exfat.EXFAT_DIRENT_TYPE_VENDOR_EXT:
                    secondary = c_exfat.VENDOR_EXT_DIRENT(buf)
                case c_exfat.EXFAT_DIRENT_TYPE_VENDOR_ALLOC:
                    secondary = c_exfat.VENDOR_ALLOC_DIRENT(buf)
                case _:
                    secondary = c_exfat.GENERIC_SECONDARY_DIRENT(buf)
            secondary_dirents.append(secondary)

        return dirent, secondary_dirents

    @cached_property
    def type(self) -> int:
        """Return the type of the directory entry."""
        return self.dirent.EntryType

    @cached_property
    def flags(self) -> int:
        """Return the flags of the directory entry."""
        if (flags := getattr(self.dirent, "GeneralPrimaryFlags", None)) is not None:
            return flags

        if self.streament is not None and (flags := getattr(self.streament, "GeneralSecondaryFlags", None)) is not None:
            return flags

        return 0

    @cached_property
    def name(self) -> str:
        """Return the name of the directory entry."""
        if self.type == c_exfat.EXFAT_DIRENT_TYPE_ALLOC_BITMAP:
            return "$ALLOC_BITMAP"

        if self.type == c_exfat.EXFAT_DIRENT_TYPE_UPCASE:
            return "$UPCASE_TABLE"

        name_entries: list[c_exfat.FILE_NAME_DIRENT] = [
            e for e in self.secondary_dirents if e.EntryType == c_exfat.EXFAT_DIRENT_TYPE_FILE_NAME
        ]
        return b"".join([bytes(e.FileName) for e in name_entries]).decode("utf-16").rstrip("\x00")

    @cached_property
    def attr(self) -> int:
        """Return the attribute value of the directory entry."""
        return self.dirent.FileAttributes if self.type == c_exfat.EXFAT_DIRENT_TYPE_FILE else 0

    @cached_property
    def size(self) -> int:
        """Return the size of the directory entry in bytes."""
        if self.streament is None:
            return super().size

        return self.streament.DataLength

    @cached_property
    def cluster(self) -> int:
        """Return the starting cluster number of the directory entry."""
        return self.streament.FirstCluster

    @cached_property
    def ctime(self) -> datetime.datetime:
        """Return the creation time of the directory entry."""
        if self.type == c_exfat.EXFAT_DIRENT_TYPE_FILE:
            return dostimestamp(
                self.dirent.CreateTimestamp,
                self.dirent.Create10msIncrement,
            ).replace(tzinfo=_timezone(self.dirent.CreateUtcOffset))

        return super().ctime

    @cached_property
    def atime(self) -> datetime.datetime:
        """Return the last access time of the directory entry."""
        if self.type == c_exfat.EXFAT_DIRENT_TYPE_FILE:
            return dostimestamp(
                self.dirent.LastAccessedTimestamp,
            ).replace(tzinfo=_timezone(self.dirent.LastAccessedUtcOffset))

        return super().atime

    @cached_property
    def mtime(self) -> datetime.datetime:
        """Return the last modification time of the directory entry."""
        if self.type == c_exfat.EXFAT_DIRENT_TYPE_FILE:
            return dostimestamp(
                self.dirent.LastModifiedTimestamp,
                self.dirent.LastModified10msIncrement,
            ).replace(tzinfo=_timezone(self.dirent.LastModifiedUtcOffset))

        return super().mtime

    def _iterdir(self, fh: BinaryIO) -> Iterator[DirectoryEntry]:
        for entry in iter_dirent(DirectoryEntry, self.fs, fh):
            if entry.type == c_exfat.EXFAT_DIRENT_TYPE_VOLUME_LABEL:
                continue

            yield entry

    def open(self) -> RunlistStream | RangeStream:
        if self.flags & c_exfat.EXFAT_DIRENT_FLAG_NO_FAT_CHAIN:
            return RangeStream(
                self.fs.data,
                (self.cluster - 2) * self.fs.cluster_size,
                self.size,
                self.fs.cluster_size,
            )

        return super().open()


class RootDirectory(DirectoryEntry):
    """Root directory implementation."""

    def __init__(self, fs: ExFAT):
        super().__init__(fs, None)

    @cached_property
    def type(self) -> int:
        return c_exfat.EXFAT_DIRENT_TYPE_UNUSED

    @cached_property
    def name(self) -> str:
        return ""

    @cached_property
    def attr(self) -> int:
        return c_fat.FAT_DIRENT_ATTR_DIRECTORY

    @cached_property
    def cluster(self) -> int:
        return self.fs.boot_sector.FirstClusterOfRootDirectory


def _checksum32(data: bytes) -> int:
    checksum = 0
    for idx, byte in enumerate(data):
        if idx in (106, 107, 112):  # skip VolumeFlags, PercentInUse
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


def validate_boot_sector(sector: c_exfat.BOOT_SECTOR | bytes) -> None:
    """Validate the boot sector fields according to exFAT specification.

    Args:
        sector: The boot sector to validate, either as a parsed structure or as raw bytes.

    Raises:
        InvalidBootSector: If any field in the boot sector is invalid according to exFAT specification.
    """
    if isinstance(sector, bytes):
        sector = c_exfat.BOOT_SECTOR(sector)

    if any(byte != 0 for byte in sector.MustBeZero):
        raise InvalidBootSector("exFAT BPB must be all zeros")

    if not (sector.JumpBoot[0] == 0xEB and sector.JumpBoot[1] == 0x76 and sector.JumpBoot[2] == 0x90):
        raise InvalidBootSector(f"Invalid exFAT JumpBoot: {sector.JumpBoot!r}")

    if sector.NumberOfFats not in (1, 2):
        raise InvalidBootSector(f"Invalid exFAT NumberOfFats, must be 1 or 2: {sector.NumberOfFats}")

    if sector.BytesPerSectorShift not in range(9, 13):
        raise InvalidBootSector(
            f"Invalid exFAT BytesPerSectorShift, must be between 9 and 12: {sector.BytesPerSectorShift}"
        )

    if sector.SectorsPerClusterShift not in range(25 - sector.BytesPerSectorShift):
        raise InvalidBootSector(
            f"Invalid exFAT SectorsPerClusterShift, must be between 0 and {25 - sector.BytesPerSectorShift}: "
            f"{sector.SectorsPerClusterShift}"
        )

    max_fat_offset = sector.ClusterHeapOffset - (sector.FatLength * sector.NumberOfFats)
    if 24 < sector.FatOffset > max_fat_offset:
        raise InvalidBootSector(f"Invalid exFAT FatOffset, must be between 24 and {max_fat_offset}: {sector.FatOffset}")

    if sector.ClusterCount > 0x0FFFFFF5:
        raise InvalidBootSector(f"Invalid exFAT ClusterCount, must be less than 0x0FFFFFF5: 0x{sector.ClusterCount:x}")

    vol_length_min = 1 << (20 - sector.BytesPerSectorShift)
    if sector.VolumeLength < vol_length_min:
        raise InvalidBootSector(f"Invalid exFAT VolumeLength, must be at least 1 MiB: {sector.VolumeLength}")


def is_exfat(fh: BinaryIO) -> bool:
    """Check if the given file-like object contains an exFAT filesystem by validating the BPB.

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
