from __future__ import annotations

from typing import BinaryIO

from dissect.fat import exfat


def test_exfat(exfat_simple: BinaryIO) -> None:
    e = exfat.ExFAT(exfat_simple)

    assert e.volume_label == "THESIS"
    assert e.cluster_count == 1792
    assert e.sector_size == e.cluster_size
    assert e.fat_sector == 128
    assert e.root_dir_cluster == 15
    assert e.root_dir_sector == 269
    assert e.runlist(e.root_dir_cluster) == [(e.root_dir_sector, 1)]

    files = e.files
    assert sorted(files.keys()) == ["/"]

    root = files["/"][0]
    assert root.metadata.attributes.directory == 1
    assert root.stream.flags.not_fragmented == 0
    assert root.stream.data_length == 512

    cat = files["/"][1]["cat.jpg"][0]
    assert cat.metadata.attributes.directory == 0
    assert cat.stream.flags.not_fragmented == 1
    assert cat.stream.data_length == 88786

    find_me = files["/"][1]["find_me.txt"][0]
    assert find_me.metadata.attributes.directory == 0
    assert find_me.stream.flags.not_fragmented == 1
    assert find_me.stream.data_length == 9

    directory = files["/"][1]["directory"][0]
    assert directory.metadata.attributes.directory == 1
    assert directory.stream.flags.not_fragmented == 1
    assert directory.stream.data_length == 512

    sysvol = files["/"][1]["System Volume Information"][0]
    assert sysvol.metadata.attributes.directory == 1
    assert sysvol.stream.flags.not_fragmented == 1
    assert sysvol.stream.data_length == 512


def test_exfat_4m(exfat_4m: BinaryIO) -> None:
    e = exfat.ExFAT(exfat_4m)

    assert e.volume_label == ""
    assert e.cluster_count == 512
    assert e.sector_size == 512
    assert e.cluster_size == 4096
    assert e.fat_sector == 2048
    assert e.root_dir_cluster == 5
    assert e.root_dir_sector == 4120
    assert e.runlist(e.root_dir_cluster) == [(e.root_dir_sector, 8)]

    files = e.files
    assert sorted(files.keys()) == ["/"]

    root = files["/"][0]
    assert root.metadata.attributes.directory == 1
    assert root.stream.flags.not_fragmented == 0
    assert root.stream.data_length == 4096

    empty_file = files["/"][1]["file.txt"][0]
    assert empty_file.metadata.attributes.directory == 0
    assert empty_file.stream.flags.not_fragmented == 0
    assert empty_file.stream.data_length == 0

    subdir = files["/"][1]["subdir"][0]
    assert subdir.metadata.attributes.directory == 1
    assert subdir.stream.flags.not_fragmented == 1
    assert subdir.stream.data_length == 4096

    assert sorted(files["/"][1]["subdir"][1].keys()) == ["sub.txt"]
