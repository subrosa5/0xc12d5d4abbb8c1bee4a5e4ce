"""Exclusive, bounded file I/O. Never overwrite an existing destination."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from x12.vault import VaultError


def read_bounded(path: Path, limit: int) -> bytes:
    with path.open("rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise VaultError(f"Input exceeds supported size: {path.name}")
    return data


def atomic_write(path: Path, data: bytes) -> None:
    """Publish an fsynced 0600 file via an exclusive hard link on the same filesystem."""
    fd, temporary = tempfile.mkstemp(prefix=".x12-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)  # Atomic creation; fails if a file or symlink exists.
        if os.name == "posix":
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        os.unlink(temporary)
