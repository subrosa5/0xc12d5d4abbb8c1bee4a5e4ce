"""Minimize actual recovery failures against fresh synthetic streaming vaults."""

from __future__ import annotations

import json
import random
import tempfile
from pathlib import Path

from x12 import __version__
from x12.storage import atomic_write, read_bounded
from x12.streaming import create_file, recover_file
from x12.vault import VaultError, _integer, parse_json

PASSWORDS = [b"synthetic-trace-password-one", b"synthetic-trace-password-two"]
OPERATIONS = {
    "snapshot",
    "restore",
    "flip-footer",
    "truncate",
    "drop-share",
    "duplicate-share",
    "recover",
}


def validate_trace(trace: dict) -> tuple[int, list[str]]:
    if (
        set(trace) != {"format", "version", "seed", "actions"}
        or trace["format"] != "x12-trace"
        or type(trace["version"]) is not int
        or trace["version"] != 1
    ):
        raise VaultError("Invalid synthetic trace")
    _integer(trace["seed"], 0, 2**64 - 1)
    actions = trace["actions"]
    if (
        type(actions) is not list
        or not 1 <= len(actions) <= 32
        or any(type(action) is not str or action not in OPERATIONS for action in actions)
    ):
        raise VaultError("Unsupported trace actions (only fixed synthetic operations are accepted)")
    return trace["seed"], actions


def evaluate(seed: int, actions: list[str]) -> dict | None:
    with tempfile.TemporaryDirectory(prefix="x12-trace-") as temporary:
        root = Path(temporary)
        source = root / "synthetic-source"
        source.write_bytes(random.Random(seed).randbytes(8192))
        bundle = root / "bundle"
        create_file(source, bundle, PASSWORDS, 2, 2)
        vault = bundle / "vault.x12"
        shares = [p.read_bytes() for p in sorted(bundle.glob("*.x12share"))]
        snapshot = None
        for index, action in enumerate(actions):
            if action == "snapshot":
                snapshot = vault.read_bytes()
            elif action == "restore" and snapshot is not None:
                vault.write_bytes(snapshot)
            elif action == "flip-footer":
                value = vault.read_bytes()
                if value:
                    vault.write_bytes(value[:-1] + bytes([value[-1] ^ 1]))
            elif action == "truncate":
                vault.write_bytes(vault.read_bytes()[:-1])
            elif action == "drop-share":
                shares = shares[:-1]
            elif action == "duplicate-share" and shares:
                shares = [shares[0]] * 2
            elif action == "recover":
                try:
                    recover_file(vault, shares, PASSWORDS[: len(shares)], root / f"result-{index}")
                except VaultError as exc:
                    # This engine reads only generated fixtures. Messages are
                    # fixed validation errors, not captured user logs or paths.
                    return {"type": "VaultError", "reason": str(exc)}
    return None


def reduce_trace(source: Path, output: Path) -> dict:
    from x12.lab import minimize

    seed, actions = validate_trace(parse_json(read_bounded(source, 16384)))
    failure = evaluate(seed, actions)
    if failure is None:
        raise VaultError("Trace does not produce a recovery error")
    reduced = minimize(actions, lambda candidate: evaluate(seed, candidate) == failure)
    output.mkdir(mode=0o700)
    minimal = {"format": "x12-trace", "version": 1, "seed": seed, "actions": reduced}
    atomic_write(output / "trace.json", json.dumps(minimal, indent=2).encode() + b"\n")
    report = {
        "tool_version": __version__,
        "synthetic_only": True,
        "original_actions": actions,
        "minimal_actions": reduced,
        "failure": failure,
        "interpretation": (
            "An actual recovery error; expected corruption rejection is not a vulnerability."
        ),
    }
    atomic_write(output / "report.json", json.dumps(report, indent=2).encode() + b"\n")
    atomic_write(
        output / "report.md",
        (
            "# Minimal synthetic recovery error\n\n"
            + " -> ".join(reduced)
            + "\n\n"
            + failure["reason"]
            + "\n\n"
            + "Expected rejection of corruption is not a security defect.\n"
            + "Replay: x12 replay-trace trace.json\n"
        ).encode(),
    )
    return report


def replay_trace(source: Path) -> dict | None:
    seed, actions = validate_trace(parse_json(read_bounded(source, 16384)))
    return evaluate(seed, actions)
