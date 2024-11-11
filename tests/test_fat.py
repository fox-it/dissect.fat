from typing import BinaryIO

from dissect.fat import fat


def test_fat12(fat12: BinaryIO) -> None:
    volume_label = "VOLLAB1"

    fs = fat.FATFS(fat12)

    assert fs.fat.bits_per_entry == 12

    assert fs.volume_label == volume_label
    assert fs.volume_id == "e038bb7c"
    assert fs.cluster_size == 512

    verify_fs_content(fs, volume_label)


def test_fat16(fat16: BinaryIO) -> None:
    volume_label = "LABFAT16"

    fs = fat.FATFS(fat16)

    assert fs.fat.bits_per_entry == 16

    assert fs.volume_label == volume_label
    assert fs.volume_id == "88fa453f"
    assert fs.cluster_size == 512

    verify_fs_content(fs, volume_label)


def test_fat32(fat32: BinaryIO) -> None:
    volume_label = "LABFAT32"

    fs = fat.FATFS(fat32)

    assert fs.fat.bits_per_entry == 32

    assert fs.volume_label == volume_label
    assert fs.volume_id == "4368dbb7"
    assert fs.cluster_size == 512

    verify_fs_content(fs, volume_label)


def verify_fs_content(fs: fat.FATFS, volume_label: str) -> None:
    entries_map = {e.name: e for e in fs.root.iterdir()}

    assert set(entries_map.keys()) == {volume_label, "file1.txt", "file2.txt", "subdir1"}

    file1 = entries_map["file1.txt"]
    assert not file1.is_directory()
    assert file1.size == 20
    assert file1.nblocks == 1
    assert file1.blksize == 512

    file2 = entries_map["file2.txt"]
    assert not file2.is_directory()
    assert file2.size == 23
    assert file2.nblocks == 1
    assert file2.blksize == 512

    subdir = entries_map["subdir1"]
    assert subdir.is_directory()
    assert subdir.size == 512
    assert subdir.nblocks == 1
    assert subdir.blksize == 512

    subdir_entries_map = {e.name: e for e in list(subdir.iterdir())}

    assert set(subdir_entries_map.keys()) == {".", "..", "file3.txt"}

    file3 = subdir_entries_map["file3.txt"]
    assert not file3.is_directory()
    assert file3.size == 27
    assert file3.nblocks == 1
    assert file3.blksize == 512


def test_fat3_file_2_cluster(disk2: BinaryIO) -> None:
    fs = fat.FATFS(disk2)
    entries_map = {e.name: e for e in fs.root.iterdir()}

    file1 = entries_map["rand.txt"]
    assert not file1.is_directory()
    assert file1.size == 1024
    assert file1.nblocks == 2
    assert file1.blksize == 512


def test_fat3_file_blksize_1024(disk3: BinaryIO) -> None:
    fs = fat.FATFS(disk3)
    entries_map = {e.name: e for e in fs.root.iterdir()}
    file1 = entries_map["rand.txt"]
    assert not file1.is_directory()
    assert file1.size == 1024
    assert file1.nblocks == 1
    assert file1.blksize == 1024
