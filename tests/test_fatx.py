from __future__ import annotations

import datetime
import hashlib
from typing import BinaryIO

from dissect.fat.fatx import FATX


def test_fatx(fatx_c: BinaryIO) -> None:
    fs = FATX(fatx_c)

    assert fs.volume_label == ""
    assert fs.volume_id == "d032e"
    assert fs.cluster_size == 16384

    assert fs.root.is_directory()
    assert fs.root.name == ""
    assert fs.root.ctime == datetime.datetime(1980, 1, 1, 0, 0)  # noqa: DTZ001
    assert fs.root.atime == datetime.datetime(1980, 1, 1, 0, 0)  # noqa: DTZ001
    assert fs.root.mtime == datetime.datetime(1980, 1, 1, 0, 0)  # noqa: DTZ001

    entries_map = {e.name: e for e in fs.root.iterdir()}

    assert set(entries_map.keys()) == {"xboxdash.xbe"}

    file1 = entries_map["xboxdash.xbe"]
    assert not file1.is_directory()
    assert file1.size == 1916928
    assert file1.ctime == datetime.datetime(2006, 5, 16, 9, 25, 8)  # noqa: DTZ001
    assert file1.atime == datetime.datetime(2006, 5, 16, 9, 25, 8)  # noqa: DTZ001
    assert file1.mtime == datetime.datetime(2006, 5, 16, 9, 25, 8)  # noqa: DTZ001

    assert (
        hashlib.sha256(file1.open().read()).hexdigest()
        == "d004c3867a890dd0190e3fede692f0b4f85a3e8e8f44a67a3add62a8e253c5e2"
    )
