from __future__ import annotations

import datetime
from typing import BinaryIO

import pytest

from dissect.fat.fat import FATFS


@pytest.mark.parametrize(
    ("name", "bits_per_entry", "volume_label", "volume_id", "cluster_size"),
    [
        ("fat12", 12, "VOLLAB1", "e038bb7c", 512),
        ("fat16", 16, "LABFAT16", "88fa453f", 512),
        ("fat32", 28, "LABFAT32", "4368dbb7", 512),
    ],
    ids=["fat12", "fat16", "fat32"],
)
def test_fat(
    name: BinaryIO,
    bits_per_entry: int,
    volume_label: str,
    volume_id: str,
    cluster_size: int,
    request: pytest.FixtureRequest,
) -> None:
    fs = FATFS(request.getfixturevalue(name))

    assert fs.fat.bits_per_entry == bits_per_entry

    assert fs.volume_label == volume_label
    assert fs.volume_id == volume_id
    assert fs.cluster_size == cluster_size

    assert fs.root.is_directory()
    assert fs.root.name == ""
    assert fs.root.ctime == datetime.datetime(1980, 1, 1, 0, 0, 0)  # noqa: DTZ001
    assert fs.root.mtime == datetime.datetime(1980, 1, 1, 0, 0, 0)  # noqa: DTZ001
    assert fs.root.atime == datetime.datetime(1980, 1, 1, 0, 0, 0)  # noqa: DTZ001

    entries_map = {e.name: e for e in fs.root.iterdir()}

    assert set(entries_map.keys()) == {volume_label, "file1.txt", "file2.txt", "subdir1"}

    file1 = entries_map["file1.txt"]
    assert not file1.is_directory()
    assert file1.size == 20
    match name:
        case "fat12":
            assert file1.ctime == datetime.datetime(2021, 7, 15, 10, 30, 0, 650000)  # noqa: DTZ001
            assert file1.mtime == datetime.datetime(2021, 7, 15, 10, 30)  # noqa: DTZ001
            assert file1.atime == datetime.datetime(2021, 7, 15, 0, 0)  # noqa: DTZ001
        case "fat16":
            assert file1.ctime == datetime.datetime(2021, 7, 15, 14, 43, 51, 600000)  # noqa: DTZ001
            assert file1.mtime == datetime.datetime(2021, 7, 15, 14, 43, 50)  # noqa: DTZ001
            assert file1.atime == datetime.datetime(2021, 7, 15, 0, 0)  # noqa: DTZ001
        case "fat32":
            assert file1.ctime == datetime.datetime(2021, 7, 15, 14, 43, 56, 30000)  # noqa: DTZ001
            assert file1.mtime == datetime.datetime(2021, 7, 15, 14, 43, 56)  # noqa: DTZ001
            assert file1.atime == datetime.datetime(2021, 7, 15, 0, 0)  # noqa: DTZ001

    file2 = entries_map["file2.txt"]
    assert not file2.is_directory()
    assert file2.size == 23
    match name:
        case "fat12":
            assert file2.ctime == datetime.datetime(2021, 7, 15, 13, 17, 56, 250000)  # noqa: DTZ001
            assert file2.mtime == datetime.datetime(2021, 7, 15, 13, 17, 56)  # noqa: DTZ001
            assert file2.atime == datetime.datetime(2021, 7, 15, 0, 0)  # noqa: DTZ001
        case "fat16":
            assert file2.ctime == datetime.datetime(2021, 7, 15, 14, 43, 51, 620000)  # noqa: DTZ001
            assert file2.mtime == datetime.datetime(2021, 7, 15, 14, 43, 50)  # noqa: DTZ001
            assert file2.atime == datetime.datetime(2021, 7, 15, 0, 0)  # noqa: DTZ001
        case "fat32":
            assert file2.ctime == datetime.datetime(2021, 7, 15, 14, 43, 56, 30000)  # noqa: DTZ001
            assert file2.mtime == datetime.datetime(2021, 7, 15, 14, 43, 56)  # noqa: DTZ001
            assert file2.atime == datetime.datetime(2021, 7, 15, 0, 0)  # noqa: DTZ001

    subdir = entries_map["subdir1"]
    assert subdir.is_directory()
    assert subdir.size == 512
    match name:
        case "fat12":
            assert subdir.ctime == datetime.datetime(2021, 7, 15, 10, 30, 40, 530000)  # noqa: DTZ001
            assert subdir.mtime == datetime.datetime(2021, 7, 15, 10, 30, 40)  # noqa: DTZ001
            assert subdir.atime == datetime.datetime(2021, 7, 15, 0, 0)  # noqa: DTZ001
        case "fat16":
            assert subdir.ctime == datetime.datetime(2021, 7, 15, 14, 43, 51, 620000)  # noqa: DTZ001
            assert subdir.mtime == datetime.datetime(2021, 7, 15, 14, 43, 50)  # noqa: DTZ001
            assert subdir.atime == datetime.datetime(2021, 7, 15, 0, 0)  # noqa: DTZ001
        case "fat32":
            assert subdir.ctime == datetime.datetime(2021, 7, 15, 14, 43, 56, 30000)  # noqa: DTZ001
            assert subdir.mtime == datetime.datetime(2021, 7, 15, 14, 43, 56)  # noqa: DTZ001
            assert subdir.atime == datetime.datetime(2021, 7, 15, 0, 0)  # noqa: DTZ001

    subdir_entries_map = {e.name: e for e in list(subdir.iterdir())}

    assert set(subdir_entries_map.keys()) == {".", "..", "file3.txt"}

    file3 = subdir_entries_map["file3.txt"]
    assert not file3.is_directory()
    assert file3.size == 27
    match name:
        case "fat12":
            assert file3.ctime == datetime.datetime(2021, 7, 15, 10, 30, 40, 530000)  # noqa: DTZ001
            assert file3.mtime == datetime.datetime(2021, 7, 15, 10, 30, 40)  # noqa: DTZ001
            assert file3.atime == datetime.datetime(2021, 7, 15, 0, 0)  # noqa: DTZ001
        case "fat16":
            assert file3.ctime == datetime.datetime(2021, 7, 15, 14, 43, 51, 620000)  # noqa: DTZ001
            assert file3.mtime == datetime.datetime(2021, 7, 15, 14, 43, 50)  # noqa: DTZ001
            assert file3.atime == datetime.datetime(2021, 7, 15, 0, 0)  # noqa: DTZ001
        case "fat32":
            assert file3.ctime == datetime.datetime(2021, 7, 15, 14, 43, 56, 30000)  # noqa: DTZ001
            assert file3.mtime == datetime.datetime(2021, 7, 15, 14, 43, 56)  # noqa: DTZ001
            assert file3.atime == datetime.datetime(2021, 7, 15, 0, 0)  # noqa: DTZ001
