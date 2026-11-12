"""Validate packaged binaries with real offline create/recover/rekey and a v1 vector."""

import argparse
import base64
import json
import os
import subprocess
import tempfile
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--cli", type=Path, required=True)
parser.add_argument("--recover", type=Path, required=True)
parser.add_argument("--desktop", type=Path)
args = parser.parse_args()
cli, recovery = args.cli.resolve(), args.recover.resolve()
root = Path(__file__).resolve().parent.parent


def run(binary: Path, *arguments: str) -> str:
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in {"PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV"}
    }
    result = subprocess.run(
        [str(binary), *map(str, arguments)],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
        env=environment,
    )
    if result.returncode:
        raise RuntimeError(f"Packaged command failed: {result.stderr}")
    return result.stdout.strip()


with tempfile.TemporaryDirectory(prefix="x12-native-") as temporary:
    work = Path(temporary)
    source = work / "source"
    source.write_bytes(b"native offline fixture\x00" * 60000)
    passwords = []
    for index in range(2):
        path = work / f"password-{index}"
        path.write_bytes(f"public-native-fixture-password-{index}".encode())
        passwords.append(path)
    bundle = work / "bundle"
    run(
        cli,
        "create",
        source,
        "--out",
        bundle,
        "--threshold",
        "2",
        "--shares",
        "2",
        "--holder-password-file",
        passwords[0],
        "--holder-password-file",
        passwords[1],
    )
    common = [
        "--share",
        bundle / "share-001.x12share",
        "--share",
        bundle / "share-002.x12share",
        "--share-password-file",
        passwords[0],
        "--share-password-file",
        passwords[1],
    ]
    restored = work / "restored"
    run(recovery, bundle / "vault.x12", *common, "--out", restored)
    assert restored.read_bytes() == source.read_bytes()
    rotated = work / "rotated"
    run(
        cli,
        "rekey",
        bundle / "vault.x12",
        *common,
        "--out",
        rotated,
        "--threshold",
        "2",
        "--shares",
        "2",
        "--new-password-file",
        passwords[0],
    )
    run(
        recovery,
        rotated / "vault.x12",
        "--share",
        rotated / "share-001.x12share",
        "--share",
        rotated / "share-002.x12share",
        "--password-file",
        passwords[0],
        "--out",
        work / "rotated-restored",
    )
    assert (work / "rotated-restored").read_bytes() == source.read_bytes()
    vector = json.loads((root / "tests/vectors/v1.json").read_text())
    old = work / "legacy.x12"
    old.write_bytes(base64.b64decode(vector["container"]))
    old_shares = []
    for index, value in enumerate(vector["shares"][:2]):
        path = work / f"legacy-share-{index}"
        path.write_bytes(base64.b64decode(value))
        old_shares.extend(["--share", path])
    password = work / "legacy-password"
    password.write_bytes(vector["password"].encode())
    run(recovery, old, *old_shares, "--password-file", password, "--out", work / "legacy-restored")
    assert (work / "legacy-restored").read_bytes() == base64.b64decode(vector["plaintext"])

    requester, holder = work / "requester", work / "holder"
    run(cli, "identity", "--out", requester, "--password-file", passwords[0])
    run(cli, "identity", "--out", holder, "--password-file", passwords[1])
    requester_pin = run(cli, "fingerprint", requester / "identity.public.json")
    holder_pin = run(cli, "fingerprint", holder / "identity.public.json")
    request, state = work / "request.json", work / "state.sqlite"
    capsule, received = work / "approval.json", work / "received-share"
    run(
        cli,
        "request",
        "--identity",
        requester / "identity.private.json",
        "--password-file",
        passwords[0],
        "--peer-public",
        holder / "identity.public.json",
        "--peer-fingerprint",
        holder_pin,
        "--vault",
        bundle / "vault.x12",
        "--state",
        state,
        "--out",
        request,
    )
    run(
        cli,
        "approve",
        "--identity",
        holder / "identity.private.json",
        "--password-file",
        passwords[1],
        "--peer-public",
        requester / "identity.public.json",
        "--peer-fingerprint",
        requester_pin,
        "--request",
        request,
        "--share",
        bundle / "share-001.x12share",
        "--share-password-file",
        passwords[0],
        "--confirm",
        "--out",
        capsule,
    )
    run(
        cli,
        "receive",
        "--identity",
        requester / "identity.private.json",
        "--password-file",
        passwords[0],
        "--peer-public",
        holder / "identity.public.json",
        "--peer-fingerprint",
        holder_pin,
        "--request",
        request,
        "--capsule",
        capsule,
        "--state",
        state,
        "--new-password-file",
        passwords[1],
        "--out",
        received,
    )
    run(
        recovery,
        bundle / "vault.x12",
        "--share",
        received,
        "--share",
        bundle / "share-002.x12share",
        "--password-file",
        passwords[1],
        "--out",
        work / "handoff-restored",
    )
    assert (work / "handoff-restored").read_bytes() == source.read_bytes()
    run(cli, "lab", "--report", work / "lab")
    if args.desktop:
        run(args.desktop.resolve(), "--smoke-test")
print("Native CLI, recovery, rotation, v1, PQC device handoff, GUI and crash lab passed.")
