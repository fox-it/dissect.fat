class Error(Exception):
    pass


class InvalidHeaderMagic(Error):
    pass


class InvalidBPB(Error):
    pass


class BadClusterError(Error):
    pass


class FreeClusterError(Error):
    pass


class EmptyDirectoryError(Error):
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
