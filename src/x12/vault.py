"""Bounded, authenticated offline containers and password-protected recovery shares."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import struct
from dataclasses import dataclass
from typing import Any

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Protocol.SecretSharing import Shamir

MAGIC = b"X12VAULT\x01"
MAX_DATA = 64 * 1024 * 1024
MAX_HEADER = 4096
MAX_SHARE = 8192
MAX_CONTAINER = len(MAGIC) + 4 + MAX_HEADER + 12 + MAX_DATA + 16
SCRYPT_N = 32768


class VaultError(ValueError):
    """An input failed validation or authentication."""


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise VaultError("Duplicate JSON field")
        result[key] = value
    return result


def parse_json(raw: bytes) -> dict[str, Any]:
    try:
        result = json.loads(raw, object_pairs_hook=_no_duplicates)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise VaultError("Invalid JSON document") from exc
    if type(result) is not dict:
        raise VaultError("Expected a JSON object")
    return result


def _hex(value: Any, length: int) -> None:
    if (
        type(value) is not str
        or len(value) != length
        or any(c not in "0123456789abcdef" for c in value)
    ):
        raise VaultError("Invalid identifier")


def _integer(value: Any, low: int, high: int) -> None:
    if type(value) is not int or not low <= value <= high:
        raise VaultError("Integer parameter outside supported bounds")


def _validate_header(header: dict[str, Any]) -> None:
    if set(header) != {
        "format",
        "version",
        "cipher",
        "vault_id",
        "recovery_id",
        "threshold",
        "shares",
        "size",
    }:
        raise VaultError("Unexpected vault header fields")
    if (
        header["format"] != "x12-vault"
        or type(header["version"]) is not int
        or header["version"] != 1
    ):
        raise VaultError("Unsupported vault version")
    if header["cipher"] != "AES-256-GCM":
        raise VaultError("Unsupported cipher")
    _hex(header["vault_id"], 32)
    _hex(header["recovery_id"], 32)
    _integer(header["shares"], 2, 255)
    _integer(header["threshold"], 2, header["shares"])
    _integer(header["size"], 0, MAX_DATA)


def inspect(container: bytes) -> tuple[dict[str, Any], bytes, bytes, bytes, bytes]:
    """Parse untrusted public metadata. This does NOT authenticate it."""
    if len(container) > MAX_CONTAINER or not container.startswith(MAGIC):
        raise VaultError("Not a supported x12 container")
    offset = len(MAGIC)
    if len(container) < offset + 4:
        raise VaultError("Truncated container")
    size = struct.unpack(">I", container[offset : offset + 4])[0]
    if not 0 < size <= MAX_HEADER:
        raise VaultError("Invalid header size")
    end = offset + 4 + size
    raw = container[offset + 4 : end]
    header = parse_json(raw)
    _validate_header(header)
    if raw != canonical(header):
        raise VaultError("Non-canonical vault header")
    if len(container) != end + 12 + header["size"] + 16:
        raise VaultError("Container length mismatch (truncated or trailing data)")
    return (
        header,
        container[:end],
        container[end : end + 12],
        container[end + 12 : -16],
        container[-16:],
    )


def _seal(key: bytes, nonce: bytes, data: bytes, aad: bytes) -> tuple[bytes, bytes]:
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
    cipher.update(aad)
    return cipher.encrypt_and_digest(data)


def _open(key: bytes, nonce: bytes, data: bytes, tag: bytes, aad: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
    cipher.update(aad)
    try:
        return cipher.decrypt_and_verify(data, tag)
    except ValueError as exc:
        raise VaultError("Authentication failed: wrong password, share, or modified data") from exc


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(value: Any, length: int) -> bytes:
    if type(value) is not str or len(value) > MAX_SHARE:
        raise VaultError("Invalid encoded field")
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise VaultError("Invalid base64") from exc
    if len(raw) != length or _b64(raw) != value:
        raise VaultError("Unexpected encoded field length")
    return raw


def _password_key(password: bytes, salt: bytes) -> bytes:
    if not isinstance(password, bytes) or not 12 <= len(password) <= 1024:
        raise VaultError("Share password must contain 12 to 1024 UTF-8 bytes")
    return scrypt(password, salt, 32, N=SCRYPT_N, r=8, p=1)


@dataclass(frozen=True)
class Bundle:
    container: bytes
    shares: tuple[bytes, ...]


def create(
    data: bytes, password: bytes | list[bytes], threshold: int = 3, total: int = 5
) -> Bundle:
    """Create a legacy v1 vault, with either a common password or per-holder passwords."""
    _integer(total, 2, 255)
    _integer(threshold, 2, total)
    if len(data) > MAX_DATA:
        raise VaultError("Version 1 supports files up to 64 MiB")
    validate_passwords(password, total)
    key = secrets.token_bytes(32)
    header = {
        "format": "x12-vault",
        "version": 1,
        "cipher": "AES-256-GCM",
        "vault_id": secrets.token_hex(16),
        "recovery_id": secrets.token_hex(16),
        "threshold": threshold,
        "shares": total,
        "size": len(data),
    }
    raw_header = canonical(header)
    prefix = MAGIC + struct.pack(">I", len(raw_header)) + raw_header
    nonce = secrets.token_bytes(12)
    ciphertext, tag = _seal(key, nonce, data, prefix)
    return Bundle(prefix + nonce + ciphertext + tag, protect_shares(header, prefix, key, password))


def validate_passwords(password: bytes | list[bytes], count: int) -> list[bytes]:
    passwords = [password] * count if isinstance(password, bytes) else password
    if not isinstance(passwords, list) or len(passwords) != count:
        raise VaultError("Provide exactly one password per share, in share order")
    for item in passwords:
        if not isinstance(item, bytes) or not 12 <= len(item) <= 1024:
            raise VaultError("Each share password must contain 12 to 1024 bytes")
    return passwords


def protect_shares(
    header: dict[str, Any], prefix: bytes, key: bytes, password: bytes | list[bytes]
) -> tuple[bytes, ...]:
    threshold, total = header["threshold"], header["shares"]
    passwords = validate_passwords(password, total)
    # PyCryptodome Shamir operates on 128-bit secrets. Independent polynomials
    # share each half of the uniformly random AES-256 key at matching indices.
    left = Shamir.split(threshold, total, key[:16])
    right = Shamir.split(threshold, total, key[16:])
    protected = []
    for (index, a), (other_index, b), password in zip(left, right, passwords, strict=True):
        assert index == other_index
        metadata = {
            "format": "x12-share",
            "version": 1,
            "index": index,
            "header_sha256": hashlib.sha256(prefix).hexdigest(),
            "vault_id": header["vault_id"],
            "recovery_id": header["recovery_id"],
            "threshold": threshold,
            "shares": total,
            "kdf": "scrypt-N32768-r8-p1",
            "salt": _b64(secrets.token_bytes(16)),
            "nonce": _b64(secrets.token_bytes(12)),
        }
        wrapping_key = _password_key(password, _unb64(metadata["salt"], 16))
        encrypted, share_tag = _seal(
            wrapping_key, _unb64(metadata["nonce"], 12), a + b, canonical(metadata)
        )
        protected.append(
            canonical({"metadata": metadata, "ciphertext": _b64(encrypted), "tag": _b64(share_tag)})
        )
    return tuple(protected)


def recover(container: bytes, shares: list[bytes], password: bytes | list[bytes]) -> bytes:
    """Authenticate every supplied share, reconstruct, then authenticate the whole file."""
    header, prefix, nonce, ciphertext, tag = inspect(container)
    key = reconstruct_key(header, prefix, shares, password)
    return _open(key, nonce, ciphertext, tag, prefix)


def reconstruct_key(
    header: dict[str, Any], prefix: bytes, shares: list[bytes], password: bytes | list[bytes]
) -> bytes:
    if not header["threshold"] <= len(shares) <= header["shares"]:
        raise VaultError("Incorrect number of recovery shares")
    passwords = validate_passwords(password, len(shares))
    expected_hash = hashlib.sha256(prefix).hexdigest()
    seen = set()
    left, right = [], []
    for raw, password in zip(shares, passwords, strict=True):
        metadata, payload = unprotect_share(raw, password)
        for field in ("vault_id", "recovery_id", "threshold", "shares"):
            if type(metadata[field]) is not type(header[field]) or metadata[field] != header[field]:
                raise VaultError("Share belongs to another vault or recovery generation")
        if metadata["header_sha256"] != expected_hash:
            raise VaultError("Share does not match this container header")
        index = metadata["index"]
        _integer(index, 1, header["shares"])
        if index in seen:
            raise VaultError("Duplicate share index")
        seen.add(index)
        left.append((index, payload[:16]))
        right.append((index, payload[16:]))
    return Shamir.combine(left) + Shamir.combine(right)


def unprotect_share(raw: bytes, password: bytes) -> tuple[dict[str, Any], bytes]:
    if len(raw) > MAX_SHARE:
        raise VaultError("Share exceeds size limit")
    envelope = parse_json(raw)
    if set(envelope) != {"metadata", "ciphertext", "tag"}:
        raise VaultError("Unexpected share fields")
    metadata = envelope["metadata"]
    validate_share_metadata(metadata)
    wrapping_key = _password_key(password, _unb64(metadata["salt"], 16))
    value = _open(
        wrapping_key,
        _unb64(metadata["nonce"], 12),
        _unb64(envelope["ciphertext"], 32),
        _unb64(envelope["tag"], 16),
        canonical(metadata),
    )
    return metadata, value


def validate_share_metadata(metadata: Any) -> None:
    if type(metadata) is not dict or set(metadata) != {
        "format",
        "version",
        "index",
        "header_sha256",
        "vault_id",
        "recovery_id",
        "threshold",
        "shares",
        "kdf",
        "salt",
        "nonce",
    }:
        raise VaultError("Invalid share metadata")
    if (
        metadata["format"] != "x12-share"
        or type(metadata["version"]) is not int
        or metadata["version"] != 1
        or metadata["kdf"] != "scrypt-N32768-r8-p1"
    ):
        raise VaultError("Unsupported share format or KDF")
    _hex(metadata["vault_id"], 32)
    _hex(metadata["recovery_id"], 32)
    _hex(metadata["header_sha256"], 64)
    _integer(metadata["shares"], 2, 255)
    _integer(metadata["threshold"], 2, metadata["shares"])
    _integer(metadata["index"], 1, metadata["shares"])
    _unb64(metadata["salt"], 16)
    _unb64(metadata["nonce"], 12)


def rewrap_share(metadata: dict[str, Any], value: bytes, password: bytes) -> bytes:
    validate_share_metadata(metadata)
    if len(value) != 32:
        raise VaultError("Invalid share payload size")
    updated = {
        **metadata,
        "salt": _b64(secrets.token_bytes(16)),
        "nonce": _b64(secrets.token_bytes(12)),
    }
    wrapping_key = _password_key(password, _unb64(updated["salt"], 16))
    encrypted, tag = _seal(wrapping_key, _unb64(updated["nonce"], 12), value, canonical(updated))
    return canonical({"metadata": updated, "ciphertext": _b64(encrypted), "tag": _b64(tag)})
