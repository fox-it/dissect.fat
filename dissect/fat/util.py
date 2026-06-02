from __future__ import annotations

import math
import struct
from enum import Enum, auto
from functools import lru_cache
from typing import TYPE_CHECKING, BinaryIO

from dissect.fat.exception import BadClusterError, FreeClusterError

if TYPE_CHECKING:
    from collections.abc import Iterator


class FatType(Enum):
    FAT12 = auto()
    FAT16 = auto()
    FAT32 = auto()
    EXFAT = auto()


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
            value = struct.unpack("<H", self.fh.read(2))[0]
            return value >> 4 if cluster & 1 else value & 0x0FFF

        if self.bits_per_entry == 16:
            offset_in_fat = cluster * 2
            self.fh.seek(offset_in_fat)
            return struct.unpack("<H", self.fh.read(2))[0]

        if self.bits_per_entry == 28:
            offset_in_fat = cluster * 4
            self.fh.seek(offset_in_fat)
            return struct.unpack("<I", self.fh.read(4))[0] & 0x0FFFFFFF

        if self.bits_per_entry == 32:
            offset_in_fat = cluster * 4
            self.fh.seek(offset_in_fat)
            return struct.unpack("<I", self.fh.read(4))[0]

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

    def runlist(self, cluster: int) -> Iterator[tuple[int, int]]:
        """Create a runlist from a cluster chain.

        First two clusters are reserved, so substract those.
        Also combine consecutive clusters for a more efficient runlist.

        Args:
            cluster: The starting cluster number.
        """
        chain = self.chain(cluster)

        run_start = next(chain) - 2
        run_size = 1

        for cl in chain:
            if cl == run_start + run_size:
                run_size += 1
            else:
                yield (run_start, run_size)
                run_start = cl - 2
                run_size = 1
        else:
            yield (run_start, run_size)


@lru_cache(128)
def mask(v: int, bits: int) -> int:
    return v & ((1 << bits) - 1)
