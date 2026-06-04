from __future__ import annotations


class Error(Exception):
    pass


class InvalidHeaderMagic(Error):
    pass


class InvalidBootSector(Error):
    pass


class BadClusterError(Error):
    pass


class FreeClusterError(Error):
    pass


class DeletedDirectoryError(Error):
    pass


class LastEmptyDirectoryError(Error):
    pass


class InvalidDirectoryError(Error):
    pass


class FileNotFoundError(Error, FileNotFoundError):
    pass


class IsADirectoryError(Error, IsADirectoryError):
    pass


class NotADirectoryError(Error, NotADirectoryError):
    pass
