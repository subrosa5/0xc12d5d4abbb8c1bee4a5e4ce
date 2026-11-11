import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from x12.lab import crash_before_publish
from x12.storage import atomic_write, read_bounded
from x12.vault import VaultError


def test_exclusive_output_permissions_and_cleanup(tmp_path):
    target = tmp_path / "output"
    atomic_write(target, b"original")
    with pytest.raises(FileExistsError):
        atomic_write(target, b"replacement")
    assert target.read_bytes() == b"original"
    assert not list(tmp_path.glob(".x12-*"))
    if os.name == "posix":
        assert target.stat().st_mode & 0o777 == 0o600


def test_symlink_destination_not_followed(tmp_path):
    original = tmp_path / "original"
    original.write_bytes(b"untouched")
    link = tmp_path / "link"
    link.symlink_to(original)
    with pytest.raises(FileExistsError):
        atomic_write(link, b"replacement")
    assert original.read_bytes() == b"untouched"
    assert link.is_symlink()


def test_bounded_input(tmp_path):
    target = tmp_path / "input"
    target.write_bytes(b"12345")
    assert read_bounded(target, 5) == b"12345"
    with pytest.raises(VaultError):
        read_bounded(target, 4)


def test_failed_fsync_never_publishes(tmp_path, monkeypatch):
    def fail(_fd):
        raise OSError("simulated disk failure")

    monkeypatch.setattr(os, "fsync", fail)
    with pytest.raises(OSError):
        atomic_write(tmp_path / "output", b"data")
    assert not (tmp_path / "output").exists()
    assert not list(tmp_path.glob(".x12-*"))


def test_process_death_before_publish(tmp_path: Path):
    crash_before_publish(tmp_path)
    assert (tmp_path / "output").read_bytes() == b"synthetic retry fixture"


def test_concurrent_publish_has_exactly_one_winner(tmp_path):
    target = tmp_path / "shared-output"

    def write(index):
        try:
            atomic_write(target, str(index).encode())
            return index
        except FileExistsError:
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(write, range(20)))
    winners = [result for result in results if result is not None]
    assert len(winners) == 1
    assert target.read_bytes() == str(winners[0]).encode()
    assert not list(tmp_path.glob(".x12-*"))
