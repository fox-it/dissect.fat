from __future__ import annotations

import datetime
from typing import BinaryIO

from dissect.fat import c_fat
from dissect.fat.exfatfs import ExFATFS


def test_exfat_4m(exfat_4m: BinaryIO) -> None:
    volume_label = ""

    fs = ExFATFS(exfat_4m)

    assert fs.type == c_fat.Fattype.EXFAT
    assert fs.checksum == 0x89266CBE

    assert fs.volume_label == volume_label
    assert fs.cluster_size == 4096
    assert fs.bpb.clu_count == 512
    assert fs.volume_id == 0xE79529BB
    assert fs.root.name == "\\"

    root = fs.get("/")
    dir_list = sorted(root.listdir())
    assert dir_list == [
        "$ALLOC_BITMAP",
        "$UPCASE_TABLE",
        "file.txt",
        "subdir",
    ]
    assert dir_list == sorted(fs.root.listdir())
    assert root.is_directory()
    assert not root.in_fat

    dir = fs.get("subdir")
    assert dir.is_directory()
    assert not dir.in_fat
    assert sorted(dir.listdir()) == ["sub.txt"]

    file = fs.get("subdir/sub.txt")
    assert not file.is_directory()
    assert file.in_fat
    assert file.size == 0
    assert file.cluster == 0
    assert len(file.open().read()) == file.size


def test_exfat(exfat_simple: BinaryIO) -> None:
    volume_label = "THESIS"

    fs = ExFATFS(exfat_simple)

    assert fs.type == c_fat.Fattype.EXFAT
    assert fs.checksum == 0xF3AFC687

    assert fs.volume_label == volume_label
    assert fs.cluster_size == 512
    assert fs.bpb.clu_count == 1792
    assert fs.volume_id == 0x6859A296
    assert fs.root.name == "\\"

    root = fs.get("/")
    dir_list = sorted(root.listdir())
    assert dir_list == [
        "$ALLOC_BITMAP",
        "$UPCASE_TABLE",
        "System Volume Information",
        "cat.jpg",
        "directory",
        "find_me.txt",
    ]
    assert dir_list == sorted(fs.root.listdir())
    assert root.is_directory()
    assert not root.in_fat
    assert root.mtime == datetime.datetime(1980, 1, 1, 0, 0)  # noqa: DTZ001
    assert root.atime == datetime.datetime(1980, 1, 1, 0, 0)  # noqa: DTZ001
    assert root.ctime == datetime.datetime(1980, 1, 1, 0, 0)  # noqa: DTZ001

    dir = fs.get("directory")
    assert dir.is_directory()
    assert not dir.in_fat
    assert sorted(dir.listdir()) == ["putty.exe"]
    assert dir.mtime == datetime.datetime(
        2019, 4, 17, 10, 32, 42, tzinfo=datetime.timezone(datetime.timedelta(seconds=7200))
    )
    assert dir.atime == datetime.datetime(
        2019, 4, 17, 10, 56, 22, tzinfo=datetime.timezone(datetime.timedelta(seconds=7200))
    )
    assert dir.ctime == datetime.datetime(
        2019, 4, 17, 10, 56, 23, 310000, tzinfo=datetime.timezone(datetime.timedelta(seconds=7200))
    )

    file = fs.get("directory/putty.exe")
    assert not file.is_directory()
    assert not file.in_fat
    assert file.size == 454657
    assert file.cluster == 195
    assert file.mtime == datetime.datetime(
        2019, 3, 21, 14, 52, tzinfo=datetime.timezone(datetime.timedelta(seconds=7200))
    )
    assert file.atime == datetime.datetime(
        2019, 4, 17, 10, 56, 28, tzinfo=datetime.timezone(datetime.timedelta(seconds=7200))
    )
    assert file.ctime == datetime.datetime(
        2019, 4, 17, 10, 56, 28, 130000, tzinfo=datetime.timezone(datetime.timedelta(seconds=7200))
    )
    assert len(file.open().read()) == file.size
