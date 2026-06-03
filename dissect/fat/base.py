from __future__ import annotations

import datetime
import math
import struct
from enum import Enum, auto
from functools import cache, cached_property, lru_cache
from operator import itemgetter
from typing import TYPE_CHECKING, Any, BinaryIO, TypeVar

from dissect.util.stream import RunlistStream

from dissect.fat.c_fat import c_fat
from dissect.fat.exception import (
    BadClusterError,
    DeletedDirectoryError,
    FreeClusterError,
    LastEmptyDirectoryError,
)

if TYPE_CHECKING:
    from collections.abc import Iterator


class FatType(Enum):
    FAT12 = auto()
    FAT16 = auto()
    FAT32 = auto()
    EXFAT = auto()


class FS:
    type: FatType

    sector_size: int
    cluster_size: int

    fat: FAT
    data: BinaryIO

    volume_label: str
    volume_id: str

    root: BaseDirectoryEntry

    def get(self, path: str, dirent: BaseDirectoryEntry | None = None) -> BaseDirectoryEntry:
        """Get a directory entry by path.

        Args:
            path: The path to the directory entry.
            dirent: The directory entry to start the search from. Defaults to the root directory.
        """
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
                if self._match(part_upper, child):
                    dirent = child
                    break
            else:
                raise FileNotFoundError(f"File not found: {path}")

        return dirent

    def _match(self, name: str, dirent: BaseDirectoryEntry) -> bool:
        """Return whether the given name matches the directory entry's name."""
        return name == dirent.name.upper()


class BaseDirectoryEntry:
    """Base class for FAT directory entries.

    Args:
        fs: The filesystem this directory entry belongs to.
        fh: File-like object positioned at the start of the directory entry to read.
    """

    def __init__(self, fs: FS, fh: BinaryIO | None):
        self.fs = fs

        if fh is not None:
            self.dirent, self.secondary_dirents = self._read_dirent(fh)
        else:
            self.dirent, self.secondary_dirents = None, []

        self.dataruns = cache(self.dataruns)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r}>"

    def _read_dirent(self, fh: BinaryIO | None) -> tuple[Any | None, list[Any]]:
        """Read a directory entry from the given file handle, handling secondary entries if present.

        Args:
            fh: File-like object positioned at the start of the directory entry to read.

        Returns:
            A tuple containing the directory entry and a list of secondary directory entries.
        """
        raise NotImplementedError

    @cached_property
    def name(self) -> str:
        """Return the canonical name of the directory entry."""
        raise NotImplementedError

    @cached_property
    def attr(self) -> int:
        """Return the attribute value of the directory entry."""
        raise NotImplementedError

    @cached_property
    def size(self) -> int:
        """Return the size of the directory entry in bytes."""
        return sum(map(itemgetter(1), self.dataruns())) * self.fs.cluster_size

    @cached_property
    def cluster(self) -> int:
        """Return the starting cluster number of the directory entry."""
        raise NotImplementedError

    @cached_property
    def ctime(self) -> datetime.datetime:
        """Return the creation time of the directory entry."""
        return datetime.datetime(1980, 1, 1)  # noqa: DTZ001

    @cached_property
    def atime(self) -> datetime.datetime:
        """Return the last access time of the directory entry."""
        return datetime.datetime(1980, 1, 1)  # noqa: DTZ001

    @cached_property
    def mtime(self) -> datetime.datetime:
        """Return the last modification time of the directory entry."""
        return datetime.datetime(1980, 1, 1)  # noqa: DTZ001

    def is_readonly(self) -> bool:
        """Return whether the directory entry is read-only."""
        return bool(self.attr & c_fat.FAT_DIRENT_ATTR_READ_ONLY)

    def is_hidden(self) -> bool:
        """Return whether the directory entry is hidden."""
        return bool(self.attr & c_fat.FAT_DIRENT_ATTR_HIDDEN)

    def is_system(self) -> bool:
        """Return whether the directory entry is a system file."""
        return bool(self.attr & c_fat.FAT_DIRENT_ATTR_SYSTEM)

    def is_volume_id(self) -> bool:
        """Return whether the directory entry is a volume ID."""
        return bool(self.attr & c_fat.FAT_DIRENT_ATTR_VOLUME_ID)

    def is_directory(self) -> bool:
        """Return whether the directory entry is a directory."""
        return bool(self.attr & c_fat.FAT_DIRENT_ATTR_DIRECTORY)

    def is_archive(self) -> bool:
        """Return whether the directory entry has the archive attribute set."""
        return bool(self.attr & c_fat.FAT_DIRENT_ATTR_ARCHIVE)

    def listdir(self) -> list[str]:
        """Return a list of names of the entries in the directory."""
        return [entry.name for entry in self.iterdir()]

    def iterdir(self) -> Iterator[BaseDirectoryEntry]:
        """Yield the directory entries in the directory."""
        if not self.is_directory():
            raise NotADirectoryError(self.name)

        with self.open() as fh:
            yield from self._iterdir(fh)

    def _iterdir(self, fh: BinaryIO) -> Iterator[BaseDirectoryEntry]:
        """Yield the directory entries in the directory from the given file handle.

        Args:
            fh: File-like object positioned at the start of the directory data to read.
        """
        raise NotImplementedError

    def dataruns(self) -> list[tuple[int, int]]:
        """Return the runlist of the directory entry."""
        return [] if self.cluster == FAT.FREE_CLUSTER else list(self.fs.fat.runlist(self.cluster))

    def open(self) -> RunlistStream:
        """Open the directory entry for reading."""
        return RunlistStream(self.fs.data, self.dataruns(), self.size, self.fs.cluster_size)


T = TypeVar("T", bound=BaseDirectoryEntry)


def iter_dirent(cls: type[T], fs: FS, fh: BinaryIO) -> Iterator[T]:
    while True:
        try:
            yield cls(fs, fh)
        except DeletedDirectoryError:  # noqa: PERF203
            continue
        except (LastEmptyDirectoryError, EOFError):
            break


_H = struct.Struct("<H")
_I = struct.Struct("<I")


class FAT:
    """File Allocation Table (FAT) implementation.

    Args:
        fh: File-like object containing the FAT.
        size: Size of the FAT in bytes.
        bits_per_entry: Number of bits per FAT entry.
    """

    DATA_CLUSTER_MIN = 0x00000002
    DATA_CLUSTER_MAX = 0xFFFFFFEF
    END_OF_CLUSTER_MIN = 0xFFFFFFF8
    END_OF_CLUSTER_MAX = 0xFFFFFFFF
    BAD_CLUSTER = 0xFFFFFFF7
    FREE_CLUSTER = 0x00000000

    FAT12_EOC = 0x000000FF0

    def __init__(self, fh: BinaryIO, size: int, bits_per_entry: int):
        self.fh = fh
        self.bits_per_entry = bits_per_entry
        self.entry_count = int(size // math.ceil(self.bits_per_entry / 8))

        self.get = lru_cache(4096)(self.get)

    def get(self, cluster: int) -> int | None:
        """Get the FAT entry for a given cluster.

        Args:
            cluster: The cluster number to get the FAT entry for.
        """
        if cluster >= self.entry_count:
            raise ValueError(f"Cluster exceeds FAT entry count: {cluster} >= {self.entry_count}")

        if self.bits_per_entry == 12:
            offset_in_fat = cluster + (cluster // 2)
            self.fh.seek(offset_in_fat)
            value = _H.unpack(self.fh.read(2))[0]
            return value >> 4 if cluster & 1 else value & 0x0FFF

        if self.bits_per_entry == 16:
            offset_in_fat = cluster * 2
            self.fh.seek(offset_in_fat)
            return _H.unpack(self.fh.read(2))[0]

        if self.bits_per_entry == 28:
            offset_in_fat = cluster * 4
            self.fh.seek(offset_in_fat)
            return _I.unpack(self.fh.read(4))[0] & 0x0FFFFFFF

        if self.bits_per_entry == 32:
            offset_in_fat = cluster * 4
            self.fh.seek(offset_in_fat)
            return _I.unpack(self.fh.read(4))[0]

        raise ValueError("Unsupported FAT type")

    def chain(self, cluster: int) -> Iterator[int]:
        """Yield the cluster chain starting from a given cluster.

        Args:
            cluster: The starting cluster number.
        """
        bits = self.bits_per_entry

        while True:
            value = self.get(cluster)
            if self.DATA_CLUSTER_MIN <= value <= mask(self.DATA_CLUSTER_MAX, bits):
                yield cluster

            # FAT12 special EOC
            if self.bits_per_entry == 12 and value == self.FAT12_EOC:
                yield cluster
                break

            if mask(self.END_OF_CLUSTER_MIN, bits) <= value <= mask(self.END_OF_CLUSTER_MAX, bits):
                yield cluster
                break

            if value == mask(self.BAD_CLUSTER, bits):
                raise BadClusterError(cluster)

            if value == self.FREE_CLUSTER:
                raise FreeClusterError(cluster)

            cluster = value

    def runlist(self, cluster: int, *, reserved: int = 2) -> Iterator[tuple[int, int]]:
        """Create a runlist from a cluster chain.

        On normal FAT filesystems, the first two clusters are reserved, so substract those.
        Also combine consecutive clusters for a more efficient runlist.

        Args:
            cluster: The starting cluster number.
        """
        chain = self.chain(cluster)

        run_start = next(chain) - reserved
        run_size = 1

        for cl in chain:
            if cl == run_start + run_size:
                run_size += 1
            else:
                yield (run_start, run_size)
                run_start = cl - reserved
                run_size = 1
        else:
            yield (run_start, run_size)


@lru_cache(128)
def mask(v: int, bits: int) -> int:
    return v & ((1 << bits) - 1)
