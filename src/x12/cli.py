"""Local-only command line interface."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from x12 import __version__
from x12.storage import atomic_write, read_bounded
from x12.vault import MAX_CONTAINER, MAX_DATA, MAX_SHARE, VaultError, create, inspect, recover


def _password(args: argparse.Namespace, confirm: bool = False) -> bytes:
    if args.password_file:
        raw = read_bounded(args.password_file, 1026)
        if raw.endswith(b"\n"):
            return raw[:-1].removesuffix(b"\r")
        return raw
    first = getpass.getpass("Recovery-share password (at least 12 bytes): ")
    if confirm and first != getpass.getpass("Confirm password: "):
        raise VaultError("Passwords do not match")
    return first.encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="x12", description="Experimental offline threshold vault and recovery crash lab"
    )
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    seal = commands.add_parser("create", help="Encrypt a file and write protected recovery shares")
    seal.add_argument("input", type=Path)
    seal.add_argument("--out", type=Path, required=True, help="New private bundle directory")
    seal.add_argument("--threshold", type=int, default=3)
    seal.add_argument("--shares", type=int, default=5)
    seal.add_argument("--password-file", type=Path, help="Local password file; otherwise prompt")
    unlock = commands.add_parser("recover", help="Recover a file from a quorum of protected shares")
    unlock.add_argument("vault", type=Path)
    unlock.add_argument("--share", type=Path, action="append", required=True)
    unlock.add_argument("--out", type=Path, required=True)
    unlock.add_argument("--password-file", type=Path)
    info = commands.add_parser("inspect", help="Show public metadata WITHOUT authentication")
    info.add_argument("vault", type=Path)
    lab = commands.add_parser("lab", help="Run isolated synthetic recovery experiments")
    lab.add_argument("--report", type=Path, required=True, help="New report directory")
    lab.add_argument("--seed", type=int, default=12)
    replay = commands.add_parser("replay", help="Replay a synthetic lab report")
    replay.add_argument("report", type=Path)
    replay.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            data = read_bounded(args.input, MAX_DATA)
            bundle = create(data, _password(args, confirm=True), args.threshold, args.shares)
            args.out.mkdir(mode=0o700)  # Never reuse a destination or follow an existing symlink.
            atomic_write(args.out / "vault.x12", bundle.container)
            for index, share in enumerate(bundle.shares, 1):
                atomic_write(args.out / f"share-{index:03d}.x12share", share)
            atomic_write(args.out / "COMPLETE", b"x12 bundle complete\n")
            print(f"Created {args.out}: {args.threshold}-of-{args.shares} recovery.")
            print("Distribute shares separately; store the recovery password independently.")
        elif args.command == "recover":
            data = recover(
                read_bounded(args.vault, MAX_CONTAINER),
                [read_bounded(p, MAX_SHARE) for p in args.share],
                _password(args),
            )
            atomic_write(args.out, data)
            print(f"Authenticated and recovered: {args.out}")
        elif args.command == "inspect":
            header, *_ = inspect(read_bounded(args.vault, MAX_CONTAINER))
            print(json.dumps({"authenticated": False, "header": header}, indent=2))
        elif args.command == "lab":
            from x12.lab import run_lab

            return run_lab(args.report, args.seed)
        elif args.command == "replay":
            from x12.lab import replay_report

            return replay_report(args.report, args.out)
    except (VaultError, OSError, EOFError) as exc:
        print(f"x12: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("x12: interrupted; incomplete bundles have no COMPLETE marker", file=sys.stderr)
        return 130
    return 0
