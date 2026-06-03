from __future__ import annotations

import gzip
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator


def absolute_path(filename: str) -> Path:
    return Path(__file__).parent / filename


def open_file(name: str, mode: str = "rb") -> Iterator[BinaryIO]:
    with absolute_path(name).open(mode) as f:
        yield f


def open_file_gz(name: str, mode: str = "rb") -> Iterator[BinaryIO]:
    with gzip.GzipFile(absolute_path(name), mode) as fh:
        yield fh


@pytest.fixture
def exfat_simple() -> Iterator[BinaryIO]:
    yield from open_file("_data/exfat.bin")


@pytest.fixture
def exfat_4m() -> Iterator[BinaryIO]:
    yield from open_file("_data/exfat4m.bin")


@pytest.fixture
def fat12() -> Iterator[BinaryIO]:
    yield from open_file("_data/fat12.bin")


@pytest.fixture
def fat16() -> Iterator[BinaryIO]:
    yield from open_file("_data/fat16.bin")


@pytest.fixture
def fat32() -> Iterator[BinaryIO]:
    yield from open_file("_data/fat32.bin")


@pytest.fixture
def fatx_c() -> Iterator[BinaryIO]:
    # https://github.com/xemu-project/xemu-dashboard
    yield from open_file_gz("_data/fatx_c.bin.gz")
