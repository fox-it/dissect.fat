# References:
# - https://github.com/mborgerson/fatx
from __future__ import annotations

import io
from functools import cached_property
from typing import TYPE_CHECKING, BinaryIO

from dissect.util.stream import RangeStream
from dissect.util.ts import dostimestamp

from dissect.fat.base import FAT, FS, BaseDirectoryEntry, iter_dirent
from dissect.fat.c_fat import c_fat
from dissect.fat.c_fatx import c_fatx
from dissect.fat.exception import DeletedDirectoryError, LastEmptyDirectoryError

if TYPE_CHECKING:
    import datetime
    from collections.abc import Iterator


class FATX(FS):
    """FATX filesystem implementation.

    Args:
        fh: File-like object containing the FATX filesystem.
    """

    def __init__(self, fh: BinaryIO, sector_size: int = 512):
        self.fh = fh

        fh.seek(0)
        self.metadata = c_fatx.FAT_VOLUME_METADATA(self.fh)

        if self.metadata.Signature != c_fatx.FAT_VOLUME_SIGNATURE:
            raise ValueError(
                f"Invalid FATX signature: {self.metadata.Signature:#0{10}x} "
                f"(expected {c_fatx.FAT_VOLUME_SIGNATURE:#0{10}x})"
            )

        self.sector_size = sector_size
        self.cluster_size = self.metadata.SectorsPerCluster * self.sector_size

        size = fh.seek(0, io.SEEK_END)
        fat_size = (size // self.cluster_size) + c_fatx.FAT_RESERVED_FAT_ENTRIES

        if self.metadata.RootDirFirstCluster >= fat_size:
            raise ValueError(f"Invalid root cluster: {self.metadata.RootDirFirstCluster} (exceeds FAT size {fat_size})")

        if fat_size < 0xFFF0:
            bits_per_entry = 16
            fat_size *= 2
        else:
            bits_per_entry = 32
            fat_size *= 4

        # Round FAT size up to nearest 4k boundary.
        if fat_size % 4096:
            fat_size += 4096 - fat_size % 4096

        fat_stream = RangeStream(fh, c_fatx.FAT_METADATA_BLOCK_SIZE, fat_size)
        self.fat = FAT(fat_stream, fat_stream.size, bits_per_entry)
        self.data = RangeStream(
            fh,
            c_fatx.FAT_METADATA_BLOCK_SIZE + fat_size,
            size - fat_size - c_fatx.FAT_METADATA_BLOCK_SIZE + (c_fatx.FAT_RESERVED_FAT_ENTRIES * self.cluster_size),
        )

        self.volume_label = bytes(self.metadata.VolumeName).decode("utf-16-le").split("\x00", 1)[0]
        self.volume_id = f"{self.metadata.SerialNumber:x}"

        self.root = RootDirectory(self)


def is_fatx(fh: BinaryIO) -> bool:
    """Check if the given file-like object contains a FATX filesystem.

    Args:
        fh: File-like object to check.
    """
    fh.seek(0)

    buf = fh.read(c_fatx.FAT_METADATA_BLOCK_SIZE)

    if len(buf) != c_fatx.FAT_METADATA_BLOCK_SIZE:
        return False

    return c_fatx.uint32_t(buf) == c_fatx.FAT_VOLUME_SIGNATURE


class DirectoryEntry(BaseDirectoryEntry):
    """FATX directory entry implementation.

    Args:
        fs: The FATX filesystem this directory entry belongs to.
        fh: File-like object positioned at the start of the directory entry to read.
    """

    def _read_dirent(self, fh: BinaryIO | None) -> tuple[c_fatx.DIRENT, list]:
        dirent = c_fatx.DIRENT(fh)
        if dirent.FileNameLength in (c_fatx.FAT_DIRENT_NEVER_USED, c_fatx.FAT_DIRENT_NEVER_USED2):
            raise LastEmptyDirectoryError("Dirent is the last empty entry")

        if dirent.FileNameLength == c_fatx.FAT_DIRENT_DELETED:
            raise DeletedDirectoryError("Dirent is a deleted entry")

        return dirent, []

    @cached_property
    def name(self) -> str:
        return bytes(self.dirent.FileName[: self.dirent.FileNameLength]).decode("ascii")

    @cached_property
    def attr(self) -> int:
        return self.dirent.FileAttributes

    @cached_property
    def size(self) -> int:
        if self.dirent is None:
            return super().size

        return self.dirent.FileSize

    @cached_property
    def cluster(self) -> int:
        return self.dirent.FirstCluster

    @cached_property
    def ctime(self) -> datetime.datetime:
        if self.dirent and self.dirent.CreationTime:
            return dostimestamp(self.dirent.CreationTime)

        return super().ctime

    @cached_property
    def atime(self) -> datetime.datetime:
        if self.dirent and self.dirent.LastAccessTime:
            return dostimestamp(self.dirent.LastAccessTime)

        return super().atime

    @cached_property
    def mtime(self) -> datetime.datetime:
        if self.dirent and self.dirent.LastWriteTime:
            return dostimestamp(self.dirent.LastWriteTime)

        return super().mtime

    def _iterdir(self, fh: BinaryIO) -> Iterator[DirectoryEntry]:
        yield from iter_dirent(DirectoryEntry, self.fs, fh)

    def dataruns(self) -> list[tuple[int, int]]:
        return (
            []
            if self.cluster == FAT.FREE_CLUSTER
            else list(self.fs.fat.runlist(self.cluster, reserved=c_fatx.FAT_RESERVED_FAT_ENTRIES))
        )


class RootDirectory(DirectoryEntry):
    """Root directory implementation."""

    def __init__(self, fs: FATX):
        super().__init__(fs, None)

    @cached_property
    def name(self) -> str:
        return ""

    @cached_property
    def attr(self) -> int:
        return c_fat.FAT_DIRENT_ATTR_DIRECTORY

    @property
    def cluster(self) -> int:
        return self.fs.metadata.RootDirFirstCluster
