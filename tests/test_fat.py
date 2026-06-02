from __future__ import annotations

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

    entries_map = {e.name: e for e in fs.root.iterdir()}

    assert set(entries_map.keys()) == {volume_label, "file1.txt", "file2.txt", "subdir1"}

    file1 = entries_map["file1.txt"]
    assert not file1.is_directory()
    assert file1.size == 20

    file2 = entries_map["file2.txt"]
    assert not file2.is_directory()
    assert file2.size == 23

    subdir = entries_map["subdir1"]
    assert subdir.is_directory()
    assert subdir.size == 512

    subdir_entries_map = {e.name: e for e in list(subdir.iterdir())}

    assert set(subdir_entries_map.keys()) == {".", "..", "file3.txt"}

    file3 = subdir_entries_map["file3.txt"]
    assert not file3.is_directory()
    assert file3.size == 27
