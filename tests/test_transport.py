import pytest

from x12.storage import read_bounded
from x12.streaming import create_file, recover_file
from x12.transport import (
    MAX_MESSAGE,
    approve,
    create_identity,
    fingerprint,
    load_identity,
    load_public,
    make_request,
    receive,
)
from x12.vault import VaultError, canonical, parse_json

IDENTITY_PASSWORD = b"device-identity-fixture-password"
HOLDER_PASSWORDS = [b"holder-one-fixture-password", b"holder-two-fixture-password"]
RECIPIENT_PASSWORD = b"recipient-rewrapped-share-password"


@pytest.fixture(scope="module")
def devices(tmp_path_factory):
    root = tmp_path_factory.mktemp("devices")
    identities = []
    for name in ["requester", "holder1", "holder2", "outsider"]:
        folder = root / name
        pin = create_identity(folder, IDENTITY_PASSWORD)
        private = load_identity(folder / "identity.private.json", IDENTITY_PASSWORD)
        public = load_public(folder / "identity.public.json", pin)
        identities.append((folder, private, public, pin))
    return identities


@pytest.fixture
def handoff(tmp_path, devices):
    source = tmp_path / "source"
    source.write_bytes(b"public synthetic device-handoff fixture")
    bundle = tmp_path / "bundle"
    create_file(source, bundle, HOLDER_PASSWORDS, 2, 2)
    requester, holder = devices[:2]
    state = tmp_path / "requests.sqlite"
    request = tmp_path / "request.json"
    make_request(requester[1], holder[2], bundle / "vault.x12", request, state)
    capsule = tmp_path / "capsule.json"
    approve(
        holder[1],
        requester[2],
        request,
        (bundle / "share-001.x12share").read_bytes(),
        HOLDER_PASSWORDS[0],
        capsule,
    )
    return source, bundle, requester, holder, state, request, capsule


def test_wrong_identity_password_and_unverified_fingerprint(devices):
    folder, _, _, pin = devices[0]
    with pytest.raises(VaultError):
        load_identity(folder / "identity.private.json", b"incorrect-identity-password")
    with pytest.raises(VaultError, match="fingerprint"):
        load_public(folder / "identity.public.json", "0" * 64)
    assert fingerprint(load_public(folder / "identity.public.json", pin)) == pin


def test_two_holders_approve_and_recipient_recovers(handoff, devices, tmp_path):
    source, bundle, requester, holder, state, request, capsule = handoff
    first = tmp_path / "received1.x12share"
    receive(requester[1], holder[2], request, capsule, state, first, RECIPIENT_PASSWORD)
    second_holder = devices[2]
    second_request = tmp_path / "request2.json"
    make_request(requester[1], second_holder[2], bundle / "vault.x12", second_request, state)
    second_capsule = tmp_path / "capsule2.json"
    approve(
        second_holder[1],
        requester[2],
        second_request,
        (bundle / "share-002.x12share").read_bytes(),
        HOLDER_PASSWORDS[1],
        second_capsule,
    )
    second = tmp_path / "received2.x12share"
    receive(
        requester[1],
        second_holder[2],
        second_request,
        second_capsule,
        state,
        second,
        RECIPIENT_PASSWORD,
    )
    recover_file(
        bundle / "vault.x12",
        [first.read_bytes(), second.read_bytes()],
        RECIPIENT_PASSWORD,
        tmp_path / "restored",
    )
    assert (tmp_path / "restored").read_bytes() == source.read_bytes()


def test_capsule_replay_rejected(handoff, tmp_path):
    _, _, requester, holder, state, request, capsule = handoff
    receive(
        requester[1], holder[2], request, capsule, state, tmp_path / "first", RECIPIENT_PASSWORD
    )
    with pytest.raises(VaultError, match="consumed"):
        receive(
            requester[1],
            holder[2],
            request,
            capsule,
            state,
            tmp_path / "second",
            RECIPIENT_PASSWORD,
        )
    assert not (tmp_path / "second").exists()


@pytest.mark.parametrize("field", ["ed_signature", "pq_signature", "ciphertext", "pq_enc", "x_enc"])
def test_tamper_rejected_without_consuming_request(handoff, tmp_path, field):
    _, _, requester, holder, state, request, capsule = handoff
    envelope = parse_json(read_bounded(capsule, MAX_MESSAGE))
    target = envelope if field.endswith("signature") else envelope["body"]
    value = target[field]
    target[field] = ("A" if value[0] != "A" else "B") + value[1:]
    damaged = tmp_path / "damaged.json"
    damaged.write_bytes(canonical(envelope))
    with pytest.raises(VaultError):
        receive(
            requester[1], holder[2], request, damaged, state, tmp_path / "bad", RECIPIENT_PASSWORD
        )
    assert not (tmp_path / "bad").exists()
    receive(requester[1], holder[2], request, capsule, state, tmp_path / "good", RECIPIENT_PASSWORD)


def test_wrong_device_and_unknown_request_rejected(handoff, devices, tmp_path):
    _, _, requester, holder, state, request, capsule = handoff
    with pytest.raises(VaultError):
        receive(
            devices[3][1],
            holder[2],
            request,
            capsule,
            state,
            tmp_path / "wrong",
            RECIPIENT_PASSWORD,
        )
    with pytest.raises(VaultError, match="Unknown"):
        receive(
            requester[1],
            holder[2],
            request,
            capsule,
            tmp_path / "unknown.sqlite",
            tmp_path / "unknown",
            RECIPIENT_PASSWORD,
        )


def test_expired_request_rejected(handoff, tmp_path, monkeypatch):
    _, _, requester, holder, state, request, capsule = handoff
    from x12 import transport

    original = transport.time.time
    current = original()
    monkeypatch.setattr(transport.time, "time", lambda: current + 7200)
    with pytest.raises(VaultError, match="expired"):
        receive(
            requester[1],
            holder[2],
            request,
            capsule,
            state,
            tmp_path / "expired",
            RECIPIENT_PASSWORD,
        )


def test_different_vault_share_not_released(handoff, tmp_path):
    _, _, requester, holder, _, request, _ = handoff
    source = tmp_path / "other-source"
    source.write_bytes(b"different vault")
    other = tmp_path / "other"
    create_file(source, other, HOLDER_PASSWORDS, 2, 2)
    with pytest.raises(VaultError, match="requested vault"):
        approve(
            holder[1],
            requester[2],
            request,
            (other / "share-001.x12share").read_bytes(),
            HOLDER_PASSWORDS[0],
            tmp_path / "must-not-exist",
        )


def test_ledger_consumes_before_failed_publish(handoff, tmp_path, monkeypatch):
    _, _, requester, holder, state, request, capsule = handoff
    from x12 import transport

    def fail(_path, _data):
        raise OSError("simulated output failure")

    original = transport.atomic_write
    monkeypatch.setattr(transport, "atomic_write", fail)
    with pytest.raises(OSError):
        receive(
            requester[1],
            holder[2],
            request,
            capsule,
            state,
            tmp_path / "failed",
            RECIPIENT_PASSWORD,
        )
    monkeypatch.setattr(transport, "atomic_write", original)
    with pytest.raises(VaultError, match="consumed"):
        receive(
            requester[1], holder[2], request, capsule, state, tmp_path / "retry", RECIPIENT_PASSWORD
        )
