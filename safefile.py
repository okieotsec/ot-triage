"""Open an input file once and check the open file itself, not the name it was reached by (no GUI)."""
import os
import stat

MB = 1024 * 1024


def open_regular(path, binary=False, limit=None, error=ValueError, too_large=None, action="read", **options):
    """Open a file to read, after checking the opened file itself.

    It must be a regular file, so a folder, a named pipe (which would block for ever) or a device is refused, and it
    must not be over `limit` bytes, judged on the same open file so it cannot be swapped between the check and the
    read. A refusal raises `error` and closes the file again; a file that cannot be opened raises OSError as open()
    would. The caller closes the returned file.
    """
    name = os.path.basename(str(path))
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise error(f"{name} is not a regular file (a folder, a pipe or a device cannot be {action})")
        if limit is not None and info.st_size > limit:
            raise error(too_large or f"{name} is larger than {limit // MB} MB")
        return os.fdopen(fd, "rb" if binary else "r", **options)
    except BaseException:
        os.close(fd)
        raise


def read_regular(path, limit, error=ValueError, too_large=None, action="read"):
    """Return the bytes of a regular file of at most `limit` bytes (a file that grows while being read is refused)."""
    with open_regular(path, True, limit, error, too_large, action) as fh:
        data = fh.read(limit + 1)
    if len(data) > limit:
        raise error(too_large or f"{os.path.basename(str(path))} is larger than {limit // MB} MB")
    return data
