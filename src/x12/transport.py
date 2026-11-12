"""Experimental, pinned-identity offline approval capsules using library HPKE/signatures.

This is an application protocol, not an audited messaging protocol. No network server
is involved: signed requests and encrypted responses can travel over any file channel.
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
import sqlite3
import time
from contextlib import closing
from pathlib import Path

from Crypto.Protocol import HPKE
from Crypto.Protocol.DH import import_x25519_public_key
from Crypto.PublicKey import ECC, MLDSA, MLKEM
from Crypto.Signature import eddsa, mldsa

from x12.storage import atomic_write, read_bounded
from x12.streaming import MAGIC_V2, file_digest, read_header
from x12.vault import (
    MAX_CONTAINER,
    VaultError,
    _b64,
    _hex,
    _integer,
    _open,
    _password_key,
    _seal,
    _unb64,
    canonical,
    inspect,
    parse_json,
    rewrap_share,
    unprotect_share,
    validate_share_metadata,
)

MAX_MESSAGE = 64 * 1024
SIGN_CONTEXT = b"x12/device-file-protocol/v1"
INFO_PQ = b"x12/approval/pq/v1"
INFO_X = b"x12/approval/x25519/v1"


def _decode(value: object, maximum: int = 16384) -> bytes:
    if type(value) is not str or len(value) > maximum * 2:
        raise VaultError("Invalid transport encoding")
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise VaultError("Invalid transport base64") from exc
    if len(raw) > maximum or _b64(raw) != value:
        raise VaultError("Non-canonical or oversized transport encoding")
    return raw


def _public(public: dict) -> dict:
    if type(public) is not dict or set(public) != {
        "format",
        "version",
        "mlkem",
        "x25519",
        "mldsa",
        "ed25519",
    }:
        raise VaultError("Invalid device public identity")
    if (
        public["format"] != "x12-device"
        or type(public["version"]) is not int
        or public["version"] != 1
    ):
        raise VaultError("Unsupported device identity")
    _unb64(public["mlkem"], 1184)
    _unb64(public["x25519"], 32)
    _unb64(public["mldsa"], 1952)
    _unb64(public["ed25519"], 32)
    return public


def fingerprint(public: dict) -> str:
    return hashlib.sha256(canonical(_public(public))).hexdigest()


def load_public(path: Path, expected_fingerprint: str) -> dict:
    _hex(expected_fingerprint, 64)
    public = _public(parse_json(read_bounded(path, MAX_MESSAGE)))
    if not secrets.compare_digest(fingerprint(public), expected_fingerprint):
        raise VaultError("Device fingerprint differs from the independently verified value")
    return public


def create_identity(output: Path, password: bytes) -> str:
    x = ECC.generate(curve="Curve25519")
    ed = ECC.generate(curve="Ed25519")
    pq = MLKEM.generate(param_set=MLKEM.ML_KEM_768)
    sig = MLDSA.generate(param_set=MLDSA.ML_DSA_65)
    public = {
        "format": "x12-device",
        "version": 1,
        "mlkem": _b64(pq.ek),
        "x25519": _b64(x.public_key().export_key(format="raw")),
        "mldsa": _b64(sig.pk),
        "ed25519": _b64(ed.public_key().export_key(format="raw")),
    }
    metadata = {
        "format": "x12-device-private",
        "version": 1,
        "public": public,
        "kdf": "scrypt-N32768-r8-p1",
        "salt": _b64(secrets.token_bytes(16)),
        "nonce": _b64(secrets.token_bytes(12)),
    }
    payload = canonical(
        {"x": _b64(x.seed), "ed": _b64(ed.seed), "pq": _b64(pq.seed), "sig": _b64(sig.seed)}
    )
    key = _password_key(password, _unb64(metadata["salt"], 16))
    ciphertext, tag = _seal(key, _unb64(metadata["nonce"], 12), payload, canonical(metadata))
    output.mkdir(mode=0o700)
    atomic_write(
        output / "identity.private.json",
        canonical({"metadata": metadata, "ciphertext": _b64(ciphertext), "tag": _b64(tag)}),
    )
    atomic_write(output / "identity.public.json", canonical(public))
    value = fingerprint(public)
    atomic_write(output / "fingerprint.txt", (value + "\n").encode())
    return value


def load_identity(path: Path, password: bytes) -> dict:
    envelope = parse_json(read_bounded(path, MAX_MESSAGE))
    if set(envelope) != {"metadata", "ciphertext", "tag"}:
        raise VaultError("Invalid private identity envelope")
    meta = envelope["metadata"]
    if (
        type(meta) is not dict
        or set(meta) != {"format", "version", "public", "kdf", "salt", "nonce"}
        or meta["format"] != "x12-device-private"
        or type(meta["version"]) is not int
        or meta["version"] != 1
        or meta["kdf"] != "scrypt-N32768-r8-p1"
    ):
        raise VaultError("Unsupported private identity")
    public = _public(meta["public"])
    key = _password_key(password, _unb64(meta["salt"], 16))
    payload = parse_json(
        _open(
            key,
            _unb64(meta["nonce"], 12),
            _decode(envelope["ciphertext"]),
            _unb64(envelope["tag"], 16),
            canonical(meta),
        )
    )
    if set(payload) != {"x", "ed", "pq", "sig"}:
        raise VaultError("Invalid private identity payload")
    identity = {
        "public": public,
        "x": ECC.construct(curve="Curve25519", seed=_unb64(payload["x"], 32)),
        "ed": ECC.construct(curve="Ed25519", seed=_unb64(payload["ed"], 32)),
        "pq": MLKEM.construct(param_set=MLKEM.ML_KEM_768, seed=_unb64(payload["pq"], 64)),
        "sig": MLDSA.construct(param_set=MLDSA.ML_DSA_65, seed=_unb64(payload["sig"], 32)),
    }
    derived = {
        "format": "x12-device",
        "version": 1,
        "mlkem": _b64(identity["pq"].ek),
        "x25519": _b64(identity["x"].public_key().export_key(format="raw")),
        "mldsa": _b64(identity["sig"].pk),
        "ed25519": _b64(identity["ed"].public_key().export_key(format="raw")),
    }
    if derived != public:
        raise VaultError("Private identity does not match its public keys")
    return identity


def _signed(body: dict, identity: dict) -> dict:
    message = canonical(body)
    return {
        "body": body,
        "ed_signature": _b64(
            eddsa.new(identity["ed"], "rfc8032", context=SIGN_CONTEXT).sign(message)
        ),
        "pq_signature": _b64(mldsa.new(identity["sig"], context=SIGN_CONTEXT).sign(message)),
    }


def _verify(envelope: dict, public: dict) -> dict:
    if (
        set(envelope) != {"body", "ed_signature", "pq_signature"}
        or type(envelope["body"]) is not dict
    ):
        raise VaultError("Invalid signed message")
    message = canonical(envelope["body"])
    try:
        ed = eddsa.import_public_key(_unb64(public["ed25519"], 32))
        sig = MLDSA.construct(param_set=MLDSA.ML_DSA_65, pk=_unb64(public["mldsa"], 1952))
        eddsa.new(ed, "rfc8032", context=SIGN_CONTEXT).verify(
            message, _unb64(envelope["ed_signature"], 64)
        )
        mldsa.new(sig, context=SIGN_CONTEXT).verify(message, _unb64(envelope["pq_signature"], 3309))
    except ValueError as exc:
        raise VaultError("Device signature verification failed") from exc
    return envelope["body"]


def _request(envelope: dict, public: dict, holder: str) -> dict:
    body = _verify(envelope, public)
    if set(body) != {
        "format",
        "version",
        "id",
        "requester",
        "holder",
        "vault_id",
        "header_sha256",
        "vault_sha256",
        "threshold",
        "shares",
        "expires",
    }:
        raise VaultError("Invalid approval request fields")
    if (
        body["format"] != "x12-request"
        or type(body["version"]) is not int
        or body["version"] != 1
        or body["requester"] != fingerprint(public)
        or body["holder"] != holder
    ):
        raise VaultError("Approval request identity mismatch")
    for field, size in [
        ("id", 32),
        ("vault_id", 32),
        ("header_sha256", 64),
        ("vault_sha256", 64),
        ("requester", 64),
        ("holder", 64),
    ]:
        _hex(body[field], size)
    _integer(body["shares"], 2, 255)
    _integer(body["threshold"], 2, body["shares"])
    _integer(body["expires"], 1, 2**63 - 1)
    if not 0 < body["expires"] - int(time.time()) <= 3600:
        raise VaultError("Approval request expired or exceeds one-hour lifetime")
    return body


def _ledger(path: Path) -> sqlite3.Connection:
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        if os.name == "posix":
            os.fchmod(fd, 0o600)
    finally:
        os.close(fd)
    database = sqlite3.connect(path, timeout=10)
    database.execute("PRAGMA synchronous=FULL")
    database.execute(
        "CREATE TABLE IF NOT EXISTS requests (id TEXT PRIMARY KEY, digest TEXT NOT NULL, "
        "consumed INTEGER NOT NULL DEFAULT 0)"
    )
    database.commit()
    return database


def make_request(
    identity: dict, holder: dict, vault: Path, output: Path, state: Path, lifetime: int = 600
) -> None:
    _integer(lifetime, 1, 3600)
    with vault.open("rb") as handle:
        magic = handle.read(len(MAGIC_V2))
        handle.seek(0)
        if magic == MAGIC_V2:
            header, prefix = read_header(handle)
        else:
            header, prefix, *_ = inspect(handle.read(MAX_CONTAINER + 1))
    body = {
        "format": "x12-request",
        "version": 1,
        "id": secrets.token_hex(16),
        "requester": fingerprint(identity["public"]),
        "holder": fingerprint(holder),
        "vault_id": header["vault_id"],
        "header_sha256": hashlib.sha256(prefix).hexdigest(),
        "vault_sha256": file_digest(vault),
        "threshold": header["threshold"],
        "shares": header["shares"],
        "expires": int(time.time()) + lifetime,
    }
    envelope = _signed(body, identity)
    digest = hashlib.sha256(canonical(envelope)).hexdigest()
    with closing(_ledger(state)) as database:
        with database:
            database.execute("INSERT INTO requests(id,digest) VALUES (?,?)", (body["id"], digest))
    atomic_write(output, canonical(envelope))


def approve(
    identity: dict,
    requester: dict,
    request_file: Path,
    share: bytes,
    share_password: bytes,
    output: Path,
) -> None:
    request_envelope = parse_json(read_bounded(request_file, MAX_MESSAGE))
    request = _request(request_envelope, requester, fingerprint(identity["public"]))
    share_meta, value = unprotect_share(share, share_password)
    for field in ("vault_id", "header_sha256", "threshold", "shares"):
        if share_meta[field] != request[field]:
            raise VaultError("Share does not belong to the requested vault")
    metadata = {
        "format": "x12-approval",
        "version": 1,
        "request_id": request["id"],
        "request_sha256": hashlib.sha256(canonical(request_envelope)).hexdigest(),
        "sender": fingerprint(identity["public"]),
        "recipient": fingerprint(requester),
        "expires": request["expires"],
    }
    aad = canonical(metadata)
    context = hashlib.sha256(aad).digest()
    pq = MLKEM.construct(param_set=MLKEM.ML_KEM_768, ek=_unb64(requester["mlkem"], 1184))
    inner = HPKE.new(receiver_key=pq, aead_id=HPKE.AEAD.AES256_GCM, info=INFO_PQ + context)
    plaintext = canonical({"metadata": share_meta, "value": _b64(value)})
    inner_ciphertext = inner.seal(plaintext, auth_data=aad)
    x = import_x25519_public_key(_unb64(requester["x25519"], 32))
    outer = HPKE.new(receiver_key=x, aead_id=HPKE.AEAD.AES256_GCM, info=INFO_X + context)
    bound_aad = canonical({"metadata": metadata, "pq_enc": _b64(inner.enc)})
    ciphertext = outer.seal(inner_ciphertext, auth_data=bound_aad)
    body = {
        "metadata": metadata,
        "pq_enc": _b64(inner.enc),
        "x_enc": _b64(outer.enc),
        "ciphertext": _b64(ciphertext),
    }
    atomic_write(output, canonical(_signed(body, identity)))


def receive(
    identity: dict,
    holder: dict,
    request_file: Path,
    capsule_file: Path,
    state: Path,
    output: Path,
    new_password: bytes,
) -> None:
    request_envelope = parse_json(read_bounded(request_file, MAX_MESSAGE))
    request = _request(request_envelope, identity["public"], fingerprint(holder))
    request_digest = hashlib.sha256(canonical(request_envelope)).hexdigest()
    body = _verify(parse_json(read_bounded(capsule_file, MAX_MESSAGE)), holder)
    if set(body) != {"metadata", "pq_enc", "x_enc", "ciphertext"}:
        raise VaultError("Invalid approval capsule")
    expected = {
        "format": "x12-approval",
        "version": 1,
        "request_id": request["id"],
        "request_sha256": request_digest,
        "sender": fingerprint(holder),
        "recipient": fingerprint(identity["public"]),
        "expires": request["expires"],
    }
    if type(body["metadata"]) is not dict or canonical(body["metadata"]) != canonical(expected):
        raise VaultError("Approval context mismatch")
    aad = canonical(expected)
    context = hashlib.sha256(aad).digest()
    bound_aad = canonical({"metadata": expected, "pq_enc": body["pq_enc"]})
    try:
        outer = HPKE.new(
            receiver_key=identity["x"],
            aead_id=HPKE.AEAD.AES256_GCM,
            enc=_unb64(body["x_enc"], 32),
            info=INFO_X + context,
        )
        inner_ciphertext = outer.unseal(_decode(body["ciphertext"]), auth_data=bound_aad)
        inner = HPKE.new(
            receiver_key=identity["pq"],
            aead_id=HPKE.AEAD.AES256_GCM,
            enc=_unb64(body["pq_enc"], 1088),
            info=INFO_PQ + context,
        )
        payload = parse_json(inner.unseal(inner_ciphertext, auth_data=aad))
    except ValueError as exc:
        raise VaultError("Approval capsule authentication failed") from exc
    if set(payload) != {"metadata", "value"}:
        raise VaultError("Invalid approved share payload")
    validate_share_metadata(payload["metadata"])
    for field in ("vault_id", "header_sha256", "threshold", "shares"):
        if payload["metadata"][field] != request[field]:
            raise VaultError("Approved share does not match the requested vault")
    protected = rewrap_share(payload["metadata"], _unb64(payload["value"], 32), new_password)
    if output.exists() or output.is_symlink():
        raise FileExistsError(output)
    with closing(_ledger(state)) as database:
        with database:
            database.execute("BEGIN IMMEDIATE")
            row = database.execute(
                "SELECT digest,consumed FROM requests WHERE id=?", (request["id"],)
            ).fetchone()
            if row is None or row[0] != request_digest or row[1] != 0:
                raise VaultError("Unknown or already consumed approval request")
            database.execute("UPDATE requests SET consumed=1 WHERE id=?", (request["id"],))
        # Consumption commits BEFORE publication. A crash here fails closed;
        # issue a new request if output could not be written. Do not reset state.
    atomic_write(output, protected)
