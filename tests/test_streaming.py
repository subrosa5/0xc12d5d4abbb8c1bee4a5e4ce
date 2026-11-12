import base64
import itertools
import json
from pathlib import Path

import pytest

from x12.streaming import (
    CHUNK,
    checkpoint_file,
    create_file,
    inspect_file,
    recover_file,
    rekey_file,
    verify_checkpoint,
)
from x12.vault import VaultError, recover

PASSWORDS = [b"first-holder-password", b"second-holder-password", b"third-holder-password"]


@pytest.fixture
def bundle(tmp_path):
    source = tmp_path / "input"
    source.write_bytes(bytes(range(256)) * 17)
    output = tmp_path / "bundle"
    create_file(source, output, PASSWORDS, 2, 3)
    return source, output, [p.read_bytes() for p in sorted(output.glob("*.x12share"))]


def test_v1_reference_vector_from_old_crypto_library():
    vector = json.loads((Path(__file__).parent / "vectors/v1.json").read_text())
    assert recover(
        base64.b64decode(vector["container"]),
        [base64.b64decode(s) for s in vector["shares"][:2]],
        vector["password"].encode(),
    ) == base64.b64decode(vector["plaintext"])


def test_independent_holder_passwords_all_quorums(bundle, tmp_path):
    source, output, shares = bundle
    for indices in itertools.combinations(range(3), 2):
        destination = tmp_path / f"restored-{indices}"
        recover_file(
            output / "vault.x12",
            [shares[i] for i in indices],
            [PASSWORDS[i] for i in indices],
            destination,
        )
        assert destination.read_bytes() == source.read_bytes()
    with pytest.raises(VaultError):
        recover_file(
            output / "vault.x12", shares[:2], [PASSWORDS[1], PASSWORDS[0]], tmp_path / "wrong"
        )


@pytest.mark.parametrize("size", [0, 1, CHUNK, CHUNK + 1, CHUNK * 2 + 7])
def test_chunk_boundaries(tmp_path, size):
    source = tmp_path / "input"
    source.write_bytes(b"x" * size)
    output = tmp_path / "bundle"
    create_file(source, output, PASSWORDS[:2], 2, 2)
    shares = [p.read_bytes() for p in sorted(output.glob("*.x12share"))]
    recover_file(output / "vault.x12", shares, PASSWORDS[:2], tmp_path / "restored")
    assert (tmp_path / "restored").read_bytes() == source.read_bytes()


def test_corruption_and_completion_marker_never_publish(bundle, tmp_path):
    _, output, shares = bundle
    original = (output / "vault.x12").read_bytes()
    for index, corrupted in enumerate(
        [
            original[:-16],
            original[:-1],
            original + b"extra",
            original[:-1] + bytes([original[-1] ^ 1]),
        ]
    ):
        source = tmp_path / f"corrupt-{index}"
        source.write_bytes(corrupted)
        destination = tmp_path / f"unpublished-{index}"
        with pytest.raises(VaultError):
            recover_file(source, shares[:2], PASSWORDS[:2], destination)
        assert not destination.exists()
        assert not list(tmp_path.glob(".x12-*"))


def test_rekey_new_generation_and_old_share_rejection(bundle, tmp_path):
    source, output, shares = bundle
    rotated = tmp_path / "rotated"
    new_passwords = [b"new-holder-password-1", b"new-holder-password-2"]
    rekey_file(output / "vault.x12", shares[:2], PASSWORDS[:2], rotated, new_passwords, 2, 2)
    old = inspect_file(output / "vault.x12")
    new = inspect_file(rotated / "vault.x12")
    assert old["vault_id"] == new["vault_id"]
    assert new["generation"] == old["generation"] + 1
    assert new["recovery_id"] != old["recovery_id"]
    new_shares = [p.read_bytes() for p in sorted(rotated.glob("*.x12share"))]
    recover_file(rotated / "vault.x12", new_shares, new_passwords, tmp_path / "restored")
    assert (tmp_path / "restored").read_bytes() == source.read_bytes()
    with pytest.raises(VaultError):
        recover_file(rotated / "vault.x12", shares[:2], PASSWORDS[:2], tmp_path / "old-shares")
    # Existing copies remain readable: no fictitious retroactive revocation.
    recover_file(output / "vault.x12", shares[:2], PASSWORDS[:2], tmp_path / "old-copy")


def test_checkpoint_binds_exact_version(bundle, tmp_path):
    _, output, shares = bundle
    checkpoint = tmp_path / "external.checkpoint"
    checkpoint_file(output / "vault.x12", checkpoint)
    verify_checkpoint(output / "vault.x12", checkpoint)
    recover_file(
        output / "vault.x12",
        shares[:2],
        PASSWORDS[:2],
        tmp_path / "restored",
        checkpoint=checkpoint,
    )
    rotated = tmp_path / "rotated"
    rekey_file(output / "vault.x12", shares[:2], PASSWORDS[:2], rotated, PASSWORDS[:2], 2, 2)
    new_shares = [p.read_bytes() for p in sorted(rotated.glob("*.x12share"))]
    with pytest.raises(VaultError, match="checkpoint"):
        recover_file(
            rotated / "vault.x12",
            new_shares,
            PASSWORDS[:2],
            tmp_path / "wrong-version",
            checkpoint=checkpoint,
        )
    assert not (tmp_path / "wrong-version").exists()


def test_wrong_footer_during_rekey_does_not_publish(bundle, tmp_path):
    _, output, shares = bundle
    source = output / "vault.x12"
    raw = source.read_bytes()
    source.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
    with pytest.raises(VaultError):
        rekey_file(
            source, shares[:2], PASSWORDS[:2], tmp_path / "bad-rotation", PASSWORDS[:2], 2, 2
        )
    assert not (tmp_path / "bad-rotation/vault.x12").exists()
    assert not (tmp_path / "bad-rotation/COMPLETE").exists()


def test_larger_than_old_limit_with_bounded_python_memory(tmp_path):
    import tracemalloc

    from x12.streaming import file_digest

    source = tmp_path / "large"
    with source.open("wb") as handle:
        for _ in range(65):
            handle.write(b"x" * CHUNK)
    output = tmp_path / "large-bundle"
    tracemalloc.start()
    try:
        create_file(source, output, PASSWORDS[:2], 2, 2)
        shares = [p.read_bytes() for p in sorted(output.glob("*.x12share"))]
        recovered = tmp_path / "large-restored"
        recover_file(output / "vault.x12", shares, PASSWORDS[:2], recovered)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 16 * CHUNK
    assert file_digest(recovered) == file_digest(source)


def test_disk_full_during_stream_creation_never_publishes(tmp_path, monkeypatch):
    import errno

    from x12 import streaming

    source = tmp_path / "input"
    source.write_bytes(b"x" * (CHUNK + 1))
    original = streaming._seal
    calls = 0

    def fail_on_second(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError(errno.ENOSPC, "simulated disk full")
        return original(*args, **kwargs)

    monkeypatch.setattr(streaming, "_seal", fail_on_second)
    with pytest.raises(OSError):
        create_file(source, tmp_path / "failed", PASSWORDS[:2], 2, 2)
    assert not (tmp_path / "failed/vault.x12").exists()
    assert not (tmp_path / "failed/COMPLETE").exists()
    assert not list((tmp_path / "failed").glob(".x12-*"))


def test_swapping_stream_chunks_rejected(tmp_path):
    from x12.streaming import read_header

    source = tmp_path / "source"
    source.write_bytes(b"a" * CHUNK + b"b" * CHUNK)
    output = tmp_path / "bundle"
    create_file(source, output, PASSWORDS[:2], 2, 2)
    path = output / "vault.x12"
    with path.open("rb") as handle:
        _, prefix = read_header(handle)
    data = path.read_bytes()
    offset, record_size = len(prefix), CHUNK + 16
    swapped = (
        data[:offset]
        + data[offset + record_size : offset + record_size * 2]
        + data[offset : offset + record_size]
        + data[offset + record_size * 2 :]
    )
    path.write_bytes(swapped)
    shares = [p.read_bytes() for p in sorted(output.glob("*.x12share"))]
    with pytest.raises(VaultError):
        recover_file(path, shares, PASSWORDS[:2], tmp_path / "restored")
    assert not (tmp_path / "restored").exists()


def test_source_metadata_change_aborts_creation(tmp_path, monkeypatch):
    import os

    from x12 import streaming

    source = tmp_path / "source"
    source.write_bytes(b"synthetic mutable source")
    original = streaming._file_chunks

    def mutate(handle, size):
        yield from original(handle, size)
        state = source.stat()
        os.utime(source, ns=(state.st_atime_ns, state.st_mtime_ns + 1_000_000))

    monkeypatch.setattr(streaming, "_file_chunks", mutate)
    with pytest.raises(VaultError, match="Input changed"):
        create_file(source, tmp_path / "changed", PASSWORDS[:2], 2, 2)
    assert not (tmp_path / "changed/vault.x12").exists()


def test_rekey_digest_change_does_not_publish(bundle, tmp_path, monkeypatch):
    from x12 import streaming

    _, output, shares = bundle
    monkeypatch.setattr(streaming, "file_digest", lambda _path: "0" * 64)
    with pytest.raises(VaultError, match="Source changed"):
        rekey_file(
            output / "vault.x12",
            shares[:2],
            PASSWORDS[:2],
            tmp_path / "changed",
            PASSWORDS[:2],
            2,
            2,
        )
    assert not (tmp_path / "changed/vault.x12").exists()
