"""Strict reading and atomic writing of small JSON files (no GUI dependencies)."""
import json
import os
import tempfile
from pathlib import Path


def _reject_constant(name):
    raise ValueError(f"invalid number {name}")


def _reject_duplicates(pairs):
    keys = [k for k, _v in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate keys")
    return dict(pairs)


def read_json(path, max_bytes):
    """Read a small UTF-8 JSON file, rejecting oversized files, NaN and duplicate keys."""
    path = Path(path)
    if not path.is_file():
        raise ValueError("not a regular file")
    if path.stat().st_size > max_bytes:
        raise ValueError(f"file is larger than {max_bytes // 1024} KB")
    text = path.read_bytes().decode("utf-8-sig")
    return json.loads(text, parse_constant=_reject_constant, object_pairs_hook=_reject_duplicates)


def write_json_atomic(path, data):
    """Write JSON next to its destination and swap it in, with user-only permissions."""
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(dir=path.parent, prefix=".json-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temp_name, path)
    except BaseException:
        try:
            os.remove(temp_name)
        except OSError:
            pass
        raise
