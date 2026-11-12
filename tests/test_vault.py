from __future__ import annotations

import base64
import itertools
import json
import random
import struct

import pytest

from x12.vault import (
    MAGIC,
    MAX_HEADER,
    VaultError,
    canonical,
    create,
    inspect,
    parse_json,
    recover,
)

PASSWORD = b"test-fixture-password-only"
DATA = bytes(range(256)) * 4 + "Привет, vault!".encode()


@pytest.fixture(scope="module")
def bundle():
    return create(DATA, PASSWORD, 3, 5)


def test_every_three_of_five_quorum_and_larger_sets(bundle):
    for subset in itertools.combinations(bundle.shares, 3):
        assert recover(bundle.container, list(subset), PASSWORD) == DATA
    assert recover(bundle.container, list(reversed(bundle.shares)), PASSWORD) == DATA
    assert recover(bundle.container, list(bundle.shares[:4]), PASSWORD) == DATA


@pytest.mark.parametrize("data", [b"", b"\x00", b"x" * (1024 * 1024)])
def test_empty_and_binary_inputs(data):
    result = create(data, PASSWORD, 2, 2)
    assert recover(result.container, list(result.shares), PASSWORD) == data


def test_randomized_containers_and_encrypted_shares(bundle):
    other = create(DATA, PASSWORD, 3, 5)
    assert bundle.container != other.container
    assert bundle.shares != other.shares
    assert DATA not in bundle.container
    for raw in bundle.shares:
        envelope = parse_json(raw)
        assert len(base64.b64decode(envelope["ciphertext"])) == 32
        assert set(envelope) == {"metadata", "ciphertext", "tag"}


@pytest.mark.parametrize("threshold,total", [(1, 5), (4, 3), (2, 256), (True, 5), (2, 1)])
def test_invalid_quorum_parameters(threshold, total):
    with pytest.raises(VaultError):
        create(b"fixture", PASSWORD, threshold, total)


@pytest.mark.parametrize("password", [b"", b"short", b"x" * 1025])
def test_invalid_password_lengths(password):
    with pytest.raises(VaultError):
        create(b"fixture", password, 2, 2)


def test_wrong_password(bundle):
    with pytest.raises(VaultError, match="Authentication failed"):
        recover(bundle.container, list(bundle.shares[:3]), b"incorrect-password")


def test_insufficient_or_duplicate_shares(bundle):
    with pytest.raises(VaultError, match="number"):
        recover(bundle.container, list(bundle.shares[:2]), PASSWORD)
    with pytest.raises(VaultError, match="Duplicate"):
        recover(bundle.container, [bundle.shares[0]] * 3, PASSWORD)


def test_cross_vault_shares(bundle):
    other = create(b"other", PASSWORD, 3, 5)
    with pytest.raises(VaultError, match="another vault"):
        recover(bundle.container, [*bundle.shares[:2], other.shares[2]], PASSWORD)


@pytest.mark.parametrize(
    "field,value",
    [
        ("index", 4),
        ("threshold", 2),
        ("shares", True),
        ("vault_id", "0" * 32),
        ("recovery_id", "0" * 32),
        ("kdf", "scrypt-N999999999"),
        ("nonce", "AA=="),
        ("salt", "AA=="),
    ],
)
def test_modified_share_metadata_rejected(bundle, field, value):
    share = parse_json(bundle.shares[0])
    share["metadata"][field] = value
    with pytest.raises(VaultError):
        recover(bundle.container, [canonical(share), *bundle.shares[1:3]], PASSWORD)


@pytest.mark.parametrize("field", ["tag", "ciphertext"])
def test_modified_share_ciphertext_rejected(bundle, field):
    share = parse_json(bundle.shares[0])
    raw = bytearray(base64.b64decode(share[field]))
    raw[0] ^= 1
    share[field] = base64.b64encode(raw).decode()
    with pytest.raises(VaultError, match="Authentication failed"):
        recover(bundle.container, [canonical(share), *bundle.shares[1:3]], PASSWORD)


def test_malformed_share_json(bundle):
    for raw in [b"[]", b"null", b'{"tag":1,"tag":2}', b"\xff", b"{" * 9000]:
        with pytest.raises(VaultError):
            recover(bundle.container, [raw, *bundle.shares[1:3]], PASSWORD)


def test_container_bit_flips_and_truncation(bundle):
    _, prefix, *_ = inspect(bundle.container)
    positions = [0, len(prefix) - 1, len(prefix), len(prefix) + 12, len(bundle.container) - 1]
    for position in positions:
        damaged = bytearray(bundle.container)
        damaged[position] ^= 1
        with pytest.raises(VaultError):
            recover(bytes(damaged), list(bundle.shares[:3]), PASSWORD)
    for size in [0, 1, len(MAGIC), len(MAGIC) + 3, len(prefix), len(bundle.container) - 1]:
        with pytest.raises(VaultError):
            recover(bundle.container[:size], list(bundle.shares[:3]), PASSWORD)
    with pytest.raises(VaultError):
        recover(bundle.container + b"trailing", list(bundle.shares[:3]), PASSWORD)


def test_header_limit_and_duplicate_fields():
    with pytest.raises(VaultError):
        inspect(MAGIC + struct.pack(">I", MAX_HEADER + 1))
    with pytest.raises(VaultError):
        parse_json(b'{"version":1,"version":1}')


def test_untrusted_parser_inputs_fail_cleanly():
    rng = random.Random(12)
    for _ in range(200):
        data = rng.randbytes(rng.randrange(512))
        with pytest.raises(VaultError):
            inspect(data)
        with pytest.raises(VaultError):
            inspect(MAGIC + struct.pack(">I", len(data)) + data)


def test_noncanonical_or_invalid_headers(bundle):
    header, prefix, *_ = inspect(bundle.container)
    tail = bundle.container[len(prefix) :]
    for field, value in [("version", True), ("size", -1), ("shares", 1000), ("threshold", 0)]:
        changed = {**header, field: value}
        raw = canonical(changed)
        with pytest.raises(VaultError):
            inspect(MAGIC + struct.pack(">I", len(raw)) + raw + tail)
    raw = json.dumps(header, indent=2).encode()
    with pytest.raises(VaultError, match="canonical"):
        inspect(MAGIC + struct.pack(">I", len(raw)) + raw + tail)


@pytest.mark.parametrize("count", [0, 1, 256, True])
def test_password_expansion_rejects_unbounded_holder_counts(count):
    from x12.vault import validate_passwords

    with pytest.raises(VaultError):
        validate_passwords(PASSWORD, count)
