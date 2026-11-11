"""Isolated synthetic experiments and data-only replay manifests."""

from __future__ import annotations

import hashlib
import itertools
import json
import random
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Lock
from unittest.mock import patch

import x12.vault as vault_module
from x12 import __version__
from x12.storage import atomic_write, read_bounded
from x12.vault import VaultError, canonical, create, parse_json, recover

LAB_PASSWORD = b"synthetic-lab-password-only"
MAX_REPORT = 128 * 1024


def _reject(action: Callable[[], object]) -> None:
    try:
        action()
    except VaultError:
        return
    raise AssertionError("Invalid input was accepted")


def crash_before_publish(root: Path) -> None:
    """Kill a real worker at the storage publish boundary; inspect resulting files."""
    process = subprocess.Popen(
        [sys.executable, "-m", "x12._crash_worker", str(root)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 10
        while not (root / "ready").exists():
            if process.poll() is not None or time.monotonic() > deadline:
                raise AssertionError("Crash worker did not reach the publish boundary")
            time.sleep(0.01)
        process.kill()
        process.wait(timeout=5)
        if (root / "output").exists():
            raise AssertionError("Interrupted write published a destination")
        leftovers = list(root.glob(".x12-*"))
        if len(leftovers) != 1 or leftovers[0].read_bytes() != b"synthetic crash fixture":
            raise AssertionError("Unexpected staged-write state")
        atomic_write(root / "output", b"synthetic retry fixture")
        if (root / "output").read_bytes() != b"synthetic retry fixture":
            raise AssertionError("Retry after interruption failed")
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)


def nonce_reuse(actions: list[str]) -> bool:
    """Intentionally broken COUNTER MODEL, not the vault's nonce implementation."""
    counter = 0
    snapshot = None
    observed = set()
    for action in actions:
        if action == "encrypt":
            if counter in observed:
                return True
            observed.add(counter)
            counter += 1
        elif action == "restart":
            counter = 0
        elif action == "snapshot":
            snapshot = counter
        elif action == "restore" and snapshot is not None:
            counter = snapshot
    return False


def minimize(actions: list[str], fails: Callable[[list[str]], bool]) -> list[str]:
    """Deletion reducer: return a 1-minimal sequence for the supplied predicate."""
    if not fails(actions):
        raise VaultError("The supplied sequence does not reproduce a failure")
    result = list(actions)
    index = 0
    while index < len(result):
        candidate = result[:index] + result[index + 1 :]
        if fails(candidate):
            result = candidate
            index = 0
        else:
            index += 1
    return result


def run_lab(output: Path, seed: int = 12) -> int:
    if type(seed) is not int or not 0 <= seed < 2**64:
        raise VaultError("Lab seed must be an unsigned 64-bit integer")
    output.mkdir(mode=0o700)
    # Determinism applies only to public fixture data. Cryptographic keys, salts,
    # nonces and Shamir randomness ALWAYS come from the cryptographic library/OS.
    data = random.Random(seed).randbytes(4096)
    bundle = create(data, LAB_PASSWORD, 3, 5)
    results = []

    def check(name: str, action: Callable[[], None]) -> None:
        try:
            action()
            results.append({"scenario": name, "passed": True})
        except (AssertionError, VaultError, OSError, subprocess.SubprocessError) as exc:
            # Only fixed error classes go into the artifact, not arbitrary
            # exception text, paths, logs, keys, environment, or user content.
            results.append({"scenario": name, "passed": False, "error": type(exc).__name__})

    def all_quorums() -> None:
        for shares in itertools.combinations(bundle.shares, 3):
            if recover(bundle.container, list(shares), LAB_PASSWORD) != data:
                raise AssertionError("Quorum recovery changed the fixture")

    check("all-10-three-of-five-quorums", all_quorums)
    check(
        "insufficient-shares",
        lambda: _reject(lambda: recover(bundle.container, list(bundle.shares[:2]), LAB_PASSWORD)),
    )
    check(
        "duplicate-share",
        lambda: _reject(lambda: recover(bundle.container, [bundle.shares[0]] * 3, LAB_PASSWORD)),
    )
    check(
        "wrong-password",
        lambda: _reject(
            lambda: recover(bundle.container, list(bundle.shares[:3]), b"wrong-synthetic-password")
        ),
    )
    check(
        "truncated-container",
        lambda: _reject(
            lambda: recover(bundle.container[:-1], list(bundle.shares[:3]), LAB_PASSWORD)
        ),
    )
    damaged = bundle.container[:-1] + bytes([bundle.container[-1] ^ 1])
    check(
        "modified-authentication-tag",
        lambda: _reject(lambda: recover(damaged, list(bundle.shares[:3]), LAB_PASSWORD)),
    )
    check(
        "trailing-data",
        lambda: _reject(
            lambda: recover(bundle.container + b"extra", list(bundle.shares[:3]), LAB_PASSWORD)
        ),
    )

    def mixed_generation() -> None:
        other = create(b"different synthetic file", LAB_PASSWORD, 2, 2)
        _reject(
            lambda: recover(
                bundle.container,
                [bundle.shares[0], bundle.shares[1], other.shares[0]],
                LAB_PASSWORD,
            )
        )

    check("mixed-vault-shares", mixed_generation)

    def damaged_share() -> None:
        share = parse_json(bundle.shares[0])
        share["tag"] = "AAAAAAAAAAAAAAAAAAAAAA=="
        _reject(
            lambda: recover(bundle.container, [canonical(share), *bundle.shares[1:3]], LAB_PASSWORD)
        )

    check("modified-share", damaged_share)

    def interrupted_write() -> None:
        with tempfile.TemporaryDirectory(prefix="x12-lab-") as temporary:
            crash_before_publish(Path(temporary))

    check("process-killed-before-publish", interrupted_write)

    def exclusive_output() -> None:
        with tempfile.TemporaryDirectory(prefix="x12-lab-") as temporary:
            target = Path(temporary) / "existing"
            atomic_write(target, b"original synthetic version")
            try:
                atomic_write(target, b"replacement")
            except FileExistsError:
                pass
            else:
                raise AssertionError("Existing output overwritten")
            if target.read_bytes() != b"original synthetic version":
                raise AssertionError("Existing output damaged")

    check("existing-output-preserved", exclusive_output)

    def parallel_creation() -> None:
        observed = set()
        lock = Lock()
        original_seal = vault_module._seal

        def observe(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes):
            # Fingerprints live only in this experiment's memory, never reports.
            pair = (hashlib.sha256(key).digest(), nonce)
            with lock:
                if pair in observed:
                    raise AssertionError("Repeated key/nonce pair")
                observed.add(pair)
            return original_seal(key, nonce, plaintext, aad)

        def make_one(_index: int):
            return create(data, LAB_PASSWORD, 2, 2)

        with patch("x12.vault._seal", side_effect=observe):
            with ThreadPoolExecutor(max_workers=3) as executor:
                parallel = list(executor.map(make_one, range(3)))
        if len(observed) != 9:
            raise AssertionError("Not all expected encryption calls were observed")
        for item in parallel:
            if recover(item.container, list(item.shares), LAB_PASSWORD) != data:
                raise AssertionError("Concurrent creation changed the fixture")

    check("concurrent-creation-and-observed-nonce-uniqueness", parallel_creation)

    def restored_snapshot() -> None:
        # Old valid immutable containers intentionally remain valid. This is an
        # availability check, NOT rollback detection or old-share revocation.
        with tempfile.TemporaryDirectory(prefix="x12-lab-") as temporary:
            root = Path(temporary)
            atomic_write(root / "snapshot", bundle.container)
            saved = read_bounded(root / "snapshot", len(bundle.container))
            atomic_write(root / "restored", saved)
            if (
                recover((root / "restored").read_bytes(), list(bundle.shares[:3]), LAB_PASSWORD)
                != data
            ):
                raise AssertionError("Restored immutable snapshot failed recovery")

    check("restored-immutable-snapshot-readable", restored_snapshot)
    original = ["snapshot", "encrypt", "encrypt", "restart", "snapshot", "encrypt"]
    reduced = minimize(original, nonce_reuse)
    report = {
        "format": "x12-lab-report",
        "version": 1,
        "tool_version": __version__,
        "seed": seed,
        "synthetic_only": True,
        "fixture_sha256": hashlib.sha256(data).hexdigest(),
        "results": results,
        "counter_model_demo": {
            "intentionally_broken": True,
            "vault_implementation": False,
            "original_actions": original,
            "minimal_actions": reduced,
            "failure": "nonce-reuse-after-restart",
        },
        "limits": [
            "No full-history rollback detection without an independent freshness anchor.",
            "Replay regenerates synthetic input and experiments, not identical ciphertext.",
            "Crash coverage is one controlled process-termination boundary, not power loss.",
            "Counter minimization is a demonstration model, not a discovered vault defect.",
        ],
    }
    atomic_write(output / "report.json", json.dumps(report, indent=2).encode() + b"\n")
    rows = ["# Synthetic recovery lab", "", f"Fixture seed: {seed}", ""]
    rows += [f"- {'PASS' if row['passed'] else 'FAIL'}: {row['scenario']}" for row in results]
    rows += [
        "",
        "## Intentionally broken counter model",
        "",
        "This is a separate demonstration, not the vault's nonce generator.",
        "",
        "Minimal failure: `" + " -> ".join(reduced) + "`",
        "",
        "## Replay",
        "",
        "From this directory:",
        "",
        "```sh",
        "x12 replay report.json --out ../replayed-lab",
        "```",
        "",
        "## Limits",
        "",
        *[f"- {item}" for item in report["limits"]],
        "",
    ]
    atomic_write(output / "report.md", "\n".join(rows).encode())
    for row in results:
        print(f"{'PASS' if row['passed'] else 'FAIL'} {row['scenario']}")
    print(f"Synthetic report: {output / 'report.json'}")
    return 0 if all(row["passed"] for row in results) else 1


def replay_report(source: Path, output: Path) -> int:
    report = parse_json(read_bounded(source, MAX_REPORT))
    if (
        report.get("format") != "x12-lab-report"
        or type(report.get("version")) is not int
        or report["version"] != 1
        or report.get("synthetic_only") is not True
        or report.get("tool_version") != __version__
    ):
        raise VaultError("Unsupported replay report or tool version")
    seed = report.get("seed")
    if type(seed) is not int or not 0 <= seed < 2**64:
        raise VaultError("Invalid replay seed")
    expected = hashlib.sha256(random.Random(seed).randbytes(4096)).hexdigest()
    if report.get("fixture_sha256") != expected:
        raise VaultError("Replay fixture checksum mismatch")
    # A replay file supplies ONLY a validated seed. It never supplies commands,
    # paths, imports, pickle data or executable scripts.
    return run_lab(output, seed)
