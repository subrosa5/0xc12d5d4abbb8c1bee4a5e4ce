"""Version 2 immutable chunked containers, rekeying, and external checkpoints."""

from __future__ import annotations

import hashlib
import os
import secrets
import stat
import struct
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import BinaryIO

from x12.storage import atomic_output, atomic_write, read_bounded
from x12.vault import (
    MAGIC,
    MAX_CONTAINER,
    MAX_HEADER,
    VaultError,
    _hex,
    _integer,
    _open,
    _seal,
    canonical,
    inspect,
    parse_json,
    protect_shares,
    reconstruct_key,
    recover,
    validate_passwords,
)

MAGIC_V2 = b"X12VAULT\x02"
CHUNK = 1024 * 1024
MAX_FILE = 1 << 40


def read_exact(handle: BinaryIO, count: int) -> bytes:
    result = handle.read(count)
    if len(result) != count:
        raise VaultError("Truncated container or changing input")
    return result


def read_header(handle: BinaryIO) -> tuple[dict, bytes]:
    magic = read_exact(handle, len(MAGIC_V2))
    if magic != MAGIC_V2:
        raise VaultError("Expected a version 2 container")
    encoded_size = read_exact(handle, 4)
    length = struct.unpack(">I", encoded_size)[0]
    if not 0 < length <= MAX_HEADER:
        raise VaultError("Invalid stream header length")
    raw = read_exact(handle, length)
    header = parse_json(raw)
    expected = {
        "format",
        "version",
        "cipher",
        "vault_id",
        "recovery_id",
        "threshold",
        "shares",
        "size",
        "chunk_size",
        "nonce_prefix",
        "generation",
        "parent_sha256",
    }
    if set(header) != expected or raw != canonical(header):
        raise VaultError("Invalid or non-canonical stream header")
    if (
        header["format"] != "x12-vault"
        or type(header["version"]) is not int
        or header["version"] != 2
        or header["cipher"] != "AES-256-GCM-STREAM"
    ):
        raise VaultError("Unsupported stream format")
    _hex(header["vault_id"], 32)
    _hex(header["recovery_id"], 32)
    _hex(header["nonce_prefix"], 16)
    _hex(header["parent_sha256"], 64)
    _integer(header["shares"], 2, 255)
    _integer(header["threshold"], 2, header["shares"])
    _integer(header["size"], 0, MAX_FILE)
    _integer(header["generation"], 1, 2**32 - 1)
    if type(header["chunk_size"]) is not int or header["chunk_size"] != CHUNK:
        raise VaultError("Unsupported chunk size")
    return header, magic + encoded_size + raw


def inspect_file(path: Path) -> dict:
    with path.open("rb") as handle:
        magic = handle.read(len(MAGIC_V2))
        handle.seek(0)
        if magic == MAGIC_V2:
            return read_header(handle)[0]
    return inspect(read_bounded(path, MAX_CONTAINER))[0]


def _nonce(header: dict, index: int) -> bytes:
    return bytes.fromhex(header["nonce_prefix"]) + struct.pack(">I", index)


def _aad(prefix: bytes, index: int, length: int, final: bool = False) -> bytes:
    return prefix + (b"F" if final else b"D") + struct.pack(">QI", index, length)


def _write_stream(
    handle: BinaryIO, chunks: Iterator[bytes], header: dict, prefix: bytes, key: bytes
) -> None:
    handle.write(prefix)
    count = 0
    total = 0
    for plaintext in chunks:
        expected = min(CHUNK, header["size"] - total)
        if not expected or len(plaintext) != expected:
            raise VaultError("Input size changed or invalid chunk boundary")
        ciphertext, tag = _seal(
            key, _nonce(header, count), plaintext, _aad(prefix, count, len(plaintext))
        )
        handle.write(ciphertext + tag)
        total += len(plaintext)
        count += 1
    if total != header["size"]:
        raise VaultError("Input size changed")
    _, tag = _seal(key, _nonce(header, count), b"", _aad(prefix, count, 0, final=True))
    handle.write(tag)


def _plain_chunks(handle: BinaryIO, header: dict, prefix: bytes, key: bytes) -> Iterator[bytes]:
    count = 0
    remaining = header["size"]
    while remaining:
        length = min(CHUNK, remaining)
        ciphertext = read_exact(handle, length)
        tag = read_exact(handle, 16)
        yield _open(key, _nonce(header, count), ciphertext, tag, _aad(prefix, count, length))
        remaining -= length
        count += 1
    _open(
        key, _nonce(header, count), b"", read_exact(handle, 16), _aad(prefix, count, 0, final=True)
    )
    if handle.read(1):
        raise VaultError("Trailing data after authenticated completion marker")


def _file_chunks(handle: BinaryIO, size: int) -> Iterator[bytes]:
    remaining = size
    while remaining:
        data = read_exact(handle, min(CHUNK, remaining))
        remaining -= len(data)
        yield data
    if handle.read(1):
        raise VaultError("Input grew during encryption")


def _new_header(
    size: int,
    threshold: int,
    total: int,
    generation: int = 1,
    parent_sha256: str = "0" * 64,
    vault_id: str | None = None,
) -> tuple[dict, bytes]:
    _integer(size, 0, MAX_FILE)
    _integer(total, 2, 255)
    _integer(threshold, 2, total)
    _integer(generation, 1, 2**32 - 1)
    header = {
        "format": "x12-vault",
        "version": 2,
        "cipher": "AES-256-GCM-STREAM",
        "vault_id": vault_id or secrets.token_hex(16),
        "recovery_id": secrets.token_hex(16),
        "threshold": threshold,
        "shares": total,
        "size": size,
        "chunk_size": CHUNK,
        "nonce_prefix": secrets.token_hex(8),
        "generation": generation,
        "parent_sha256": parent_sha256,
    }
    raw = canonical(header)
    return header, MAGIC_V2 + struct.pack(">I", len(raw)) + raw


def _write_bundle(
    output: Path,
    header: dict,
    prefix: bytes,
    key: bytes,
    passwords: bytes | list[bytes],
    chunks: Iterator[bytes],
    hook: Callable[[str], None] | None = None,
) -> None:
    protected = protect_shares(header, prefix, key, passwords)
    output.mkdir(mode=0o700)
    with atomic_output(output / "vault.x12", hook) as handle:
        _write_stream(handle, chunks, header, prefix, key)
    for index, share in enumerate(protected, 1):
        atomic_write(output / f"share-{index:03d}.x12share", share)
    atomic_write(output / "COMPLETE", b"x12 bundle complete\n")


def create_file(
    source: Path,
    output: Path,
    passwords: bytes | list[bytes],
    threshold: int = 3,
    total: int = 5,
    hook: Callable[[str], None] | None = None,
) -> None:
    validate_passwords(passwords, total)
    with source.open("rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise VaultError("Streaming input must be a regular file")
        header, prefix = _new_header(info.st_size, threshold, total)

        def unchanged_input():
            yield from _file_chunks(handle, info.st_size)
            current = os.fstat(handle.fileno())
            if (current.st_size, current.st_mtime_ns, current.st_ctime_ns) != (
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
            ):
                raise VaultError("Input changed during encryption")

        _write_bundle(
            output,
            header,
            prefix,
            secrets.token_bytes(32),
            passwords,
            unchanged_input(),
            hook,
        )


def recover_file(
    source: Path,
    shares: list[bytes],
    passwords: bytes | list[bytes],
    output: Path,
    checkpoint: Path | None = None,
    hook: Callable[[str], None] | None = None,
) -> None:
    commitment = _read_checkpoint(checkpoint) if checkpoint is not None else None
    with source.open("rb") as handle:
        magic = handle.read(len(MAGIC_V2))
        handle.seek(0)
        if magic == MAGIC:
            # Legacy v1 retains its original memory bound.
            data = handle.read(MAX_CONTAINER + 1)
            plaintext = recover(data, shares, passwords)
            if commitment is not None:
                _check_commitment(hashlib.sha256(data).hexdigest(), inspect(data)[0], commitment)
            with atomic_output(output, hook) as result:
                result.write(plaintext)
            return
        observed = _HashingReader(handle)
        header, prefix = read_header(observed)
        key = reconstruct_key(header, prefix, shares, passwords)
        with atomic_output(output, hook) as result:
            for plaintext in _plain_chunks(observed, header, prefix, key):
                result.write(plaintext)
            if commitment is not None:
                _check_commitment(observed.digest.hexdigest(), header, commitment)


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def checkpoint_file(source: Path, output: Path) -> None:
    # This records a commitment, not independent freshness or authentication.
    header = inspect_file(source)
    checkpoint = {
        "format": "x12-checkpoint",
        "version": 1,
        "vault_id": header["vault_id"],
        "sha256": file_digest(source),
    }
    atomic_write(output, canonical(checkpoint))


def _read_checkpoint(checkpoint: Path) -> dict:
    record = parse_json(read_bounded(checkpoint, MAX_HEADER))
    if (
        set(record) != {"format", "version", "vault_id", "sha256"}
        or record["format"] != "x12-checkpoint"
        or type(record["version"]) is not int
        or record["version"] != 1
    ):
        raise VaultError("Invalid checkpoint")
    _hex(record["vault_id"], 32)
    _hex(record["sha256"], 64)
    return record


def _check_commitment(digest: str, header: dict, record: dict) -> None:
    if not secrets.compare_digest(digest, record["sha256"]):
        raise VaultError("Container differs from independently retained checkpoint")
    if header["vault_id"] != record["vault_id"]:
        raise VaultError("Checkpoint vault identifier mismatch")


def verify_checkpoint(source: Path, checkpoint: Path) -> None:
    _check_commitment(file_digest(source), inspect_file(source), _read_checkpoint(checkpoint))


class _HashingReader:
    def __init__(self, handle: BinaryIO):
        self.handle = handle
        self.digest = hashlib.sha256()

    def read(self, count: int) -> bytes:
        data = self.handle.read(count)
        self.digest.update(data)
        return data


def rekey_file(
    source: Path,
    shares: list[bytes],
    old_passwords: bytes | list[bytes],
    output: Path,
    new_passwords: bytes | list[bytes],
    threshold: int,
    total: int,
    checkpoint: Path | None = None,
) -> None:
    validate_passwords(new_passwords, total)
    commitment = _read_checkpoint(checkpoint) if checkpoint is not None else None
    parent = file_digest(source)
    with source.open("rb") as handle:
        magic = handle.read(len(MAGIC_V2))
        handle.seek(0)
        if magic == MAGIC:
            data = handle.read(MAX_CONTAINER + 1)
            old_header = inspect(data)[0]
            if hashlib.sha256(data).hexdigest() != parent:
                raise VaultError("Source changed during rekeying")
            plaintext = recover(data, shares, old_passwords)
            if commitment is not None:
                _check_commitment(hashlib.sha256(data).hexdigest(), old_header, commitment)
            chunks = (plaintext[i : i + CHUNK] for i in range(0, len(plaintext), CHUNK))
        else:
            observed = _HashingReader(handle)
            old_header, old_prefix = read_header(observed)
            old_key = reconstruct_key(old_header, old_prefix, shares, old_passwords)

            def authenticated_chunks():
                yield from _plain_chunks(observed, old_header, old_prefix, old_key)
                if observed.digest.hexdigest() != parent:
                    raise VaultError("Source changed during rekeying")
                if commitment is not None:
                    _check_commitment(observed.digest.hexdigest(), old_header, commitment)

            chunks = authenticated_chunks()
        header, prefix = _new_header(
            old_header["size"],
            threshold,
            total,
            old_header.get("generation", 0) + 1,
            parent,
            old_header["vault_id"],
        )
        _write_bundle(output, header, prefix, secrets.token_bytes(32), new_passwords, chunks)
