"""Exclusive, bounded file I/O. Never overwrite an existing destination."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO

from x12.vault import VaultError


def read_bounded(path: Path, limit: int) -> bytes:
    with path.open("rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise VaultError(f"Input exceeds supported size: {path.name}")
    return data


@contextmanager
def atomic_output(path: Path, hook: Callable[[str], None] | None = None) -> Iterator[BinaryIO]:
    """Stage bounded streaming output; publish exclusively only on successful completion."""

    def event(stage: str) -> None:
        if hook is not None:
            hook(stage)

    fd, temporary = tempfile.mkstemp(prefix=".x12-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            event("opened")
            yield handle
            event("written")
            handle.flush()
            os.fsync(handle.fileno())
            event("fsynced")
        event("before-publish")
        os.link(temporary, path)  # Atomic creation; fails if a file or symlink exists.
        event("published")
        if os.name == "posix":
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        os.unlink(temporary)


def atomic_write(path: Path, data: bytes) -> None:
    """Publish an fsynced 0600 file via an exclusive hard link on the same filesystem."""
    with atomic_output(path) as handle:
        handle.write(data)
