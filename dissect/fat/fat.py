from __future__ import annotations

import struct
from functools import lru_cache
from typing import TYPE_CHECKING

from dissect.fat import exfatfs, fatfs
from dissect.fat.c_fat import (
    BAD_CLUSTER,
    DATA_CLUSTER_MAX,
    DATA_CLUSTER_MIN,
    END_OF_CLUSTER_MAX,
    END_OF_CLUSTER_MIN,
    FAT12_EOC,
    FREE_CLUSTER,
    Fattype,
)
from dissect.fat.exceptions import (
    BadClusterError,
    Error,
    FreeClusterError,
    InvalidBPB,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from typing import BinaryIO

DirectoryEntry = fatfs.FatDirectoryEntry | exfatfs.ExfatDirectoryEntry
RootDirectory = fatfs.FatRootDirectory | exfatfs.ExfatRootDirectory


def FATFS(fh: BinaryIO) -> exfatfs.ExFATFS | fatfs.FATFS:
    try:
        return fatfs.FATFS(fh)
    except InvalidBPB:
        pass

    try:
        return exfatfs.ExFATFS(fh)
    except InvalidBPB:
        pass

    raise Error("Not a valid FAT file system")


def is_fatfs(fh: BinaryIO) -> bool:
    """Check if the file handle points to a valid FAT or exFAT file system."""
    sector = fh.read(512)
    try:
        fatfs.validate_bpb(sector)
    except InvalidBPB:
        pass
    else:
        return True

    try:
        exfatfs.validate_bpb(sector)
    except InvalidBPB:
        pass
    else:
        return True

    return False


class FAT:
    def __init__(self, fh: BinaryIO, fattype: Fattype):
        self.fh = fh
        self.fattype = fattype

        if fattype == Fattype.FAT12:
            self.bits_per_entry = 12
        elif fattype == Fattype.FAT16:
            self.bits_per_entry = 16
        elif fattype in (Fattype.FAT32, Fattype.EXFAT):
            self.bits_per_entry = 32
        else:
            raise TypeError("Unsupported FAT type")

        self.entry_count = int(self.fh.size // (self.bits_per_entry / 8))

        self.get = lru_cache(4096)(self.get)

    def get(self, cluster: int) -> int | None:
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

        if self.bits_per_entry == 32:
            offset_in_fat = cluster * 4
            self.fh.seek(offset_in_fat)
            value = struct.unpack("<I", self.fh.read(4))[0]
            # FAT32 uses 28 bits for cluster numbers
            return value if self.fattype == Fattype.EXFAT else value & 0x0FFFFFFF

        raise ValueError("Unsupported FAT type")

    def chain(self, cluster: int) -> Iterator[int]:
        # FAT32 uses 28 bits for cluster numbers
        bits = 28 if self.fattype == Fattype.FAT32 else self.bits_per_entry

        while True:
            value = self.get(cluster)
            if DATA_CLUSTER_MIN <= value <= mask(DATA_CLUSTER_MAX, bits):
                yield cluster

            # FAT12 special EOC
            if self.bits_per_entry == 12 and value == FAT12_EOC:
                yield cluster
                break

            if mask(END_OF_CLUSTER_MIN, bits) <= value <= mask(END_OF_CLUSTER_MAX, bits):
                yield cluster
                break

            if value == mask(BAD_CLUSTER, bits):
                raise BadClusterError(cluster)

            if value == FREE_CLUSTER:
                raise FreeClusterError(cluster)

            cluster = value

    def runlist(self, cluster: int) -> Iterator[tuple[int, int]]:
        """Create a runlist from a cluster chain.

        First two clusters are reserved, so substract those.
        Also combine consecutive clusters for a more efficient runlist.
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


def mask(v: int, bits: int) -> int:
    return v & ((1 << bits) - 1)
