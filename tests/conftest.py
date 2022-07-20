import os
import pytest


def absolute_path(filename):
    return os.path.join(os.path.dirname(__file__), filename)


@pytest.fixture
def exfat_simple():
    name = "data/exfat.bin"
    with open(absolute_path(name), "rb") as f:
        yield f


@pytest.fixture
def fat12():
    name = "data/fat12.bin"
    with open(absolute_path(name), "rb") as f:
        yield f


@pytest.fixture
def fat16():
    name = "data/fat16.bin"
    with open(absolute_path(name), "rb") as f:
        yield f


@pytest.fixture
def fat32():
    name = "data/fat32.bin"
    with open(absolute_path(name), "rb") as f:
        yield f
