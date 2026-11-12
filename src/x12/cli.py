"""Local-only command line interface."""

from __future__ import annotations

import argparse
import getpass
import json
import sqlite3
import sys
from pathlib import Path

from x12 import __version__
from x12.storage import read_bounded
from x12.streaming import checkpoint_file, create_file, inspect_file, recover_file, rekey_file
from x12.vault import MAX_SHARE, VaultError


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


def _read_password(path: Path) -> bytes:
    return _password(argparse.Namespace(password_file=path))


def _recovery_passwords(args: argparse.Namespace) -> bytes | list[bytes]:
    if args.share_password_file:
        return [_read_password(p) for p in args.share_password_file]
    if args.per_holder:
        return [getpass.getpass(f"Password for {p.name}: ").encode() for p in args.share]
    return _password(args)


def _creation_passwords(args: argparse.Namespace, *, new: bool = False) -> bytes | list[bytes]:
    files = args.new_holder_password_file if new else args.holder_password_file
    individual = args.new_per_holder if new else args.per_holder
    password_file = args.new_password_file if new else args.password_file
    if files:
        return [_read_password(p) for p in files]
    if individual:
        values = []
        for index in range(1, args.shares + 1):
            first = getpass.getpass(f"New password for holder {index}: ")
            if first != getpass.getpass(f"Confirm holder {index}: "):
                raise VaultError("Passwords do not match")
            values.append(first.encode())
        return values
    return _password(argparse.Namespace(password_file=password_file), confirm=True)


def _recovery_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("vault", type=Path)
    parser.add_argument("--share", type=Path, action="append", required=True)
    parser.add_argument("--out", type=Path, required=True)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--password-file", type=Path)
    group.add_argument(
        "--share-password-file",
        type=Path,
        action="append",
        help="One password file per supplied share, in matching order",
    )
    group.add_argument("--per-holder", action="store_true", help="Prompt for each share password")
    parser.add_argument(
        "--checkpoint", type=Path, help="Independently retained exact-version checkpoint"
    )


def main(argv: list[str] | None = None) -> int:
    raw_args = sys.argv[1:] if argv is None else argv
    if raw_args[:1] == ["__crash-worker"]:
        from x12._crash_worker import main as crash_worker

        crash_worker(raw_args[1:])
        return 0
    parser = argparse.ArgumentParser(prog="x12", description="Experimental threshold vault")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    seal = commands.add_parser(
        "create", help="Stream-encrypt a file with protected recovery shares"
    )
    seal.add_argument("input", type=Path)
    seal.add_argument("--out", type=Path, required=True)
    seal.add_argument("--threshold", type=int, default=3)
    seal.add_argument("--shares", type=int, default=5)
    group = seal.add_mutually_exclusive_group()
    group.add_argument("--password-file", type=Path)
    group.add_argument("--holder-password-file", type=Path, action="append")
    group.add_argument("--per-holder", action="store_true")
    unlock = commands.add_parser("recover", help="Recover v1 or streaming v2 offline")
    _recovery_arguments(unlock)
    rotate = commands.add_parser("rekey", help="Create a fresh-key generation for new holders")
    _recovery_arguments(rotate)
    rotate.add_argument("--threshold", type=int, default=3)
    rotate.add_argument("--shares", type=int, default=5)
    group = rotate.add_mutually_exclusive_group()
    group.add_argument("--new-password-file", type=Path)
    group.add_argument("--new-holder-password-file", type=Path, action="append")
    group.add_argument("--new-per-holder", action="store_true")
    info = commands.add_parser("inspect", help="Show public metadata WITHOUT authentication")
    info.add_argument("vault", type=Path)
    anchor = commands.add_parser("checkpoint", help="Commit to one exact container version")
    anchor.add_argument("vault", type=Path)
    anchor.add_argument("--out", type=Path, required=True)
    lab = commands.add_parser("lab", help="Run isolated synthetic recovery experiments")
    lab.add_argument("--report", type=Path, required=True)
    lab.add_argument("--seed", type=int, default=12)
    replay = commands.add_parser("replay", help="Replay a synthetic lab report")
    replay.add_argument("report", type=Path)
    replay.add_argument("--out", type=Path, required=True)
    reduce = commands.add_parser("reduce", help="Minimize a real synthetic vault recovery error")
    reduce.add_argument("trace", type=Path)
    reduce.add_argument("--out", type=Path, required=True)
    trace = commands.add_parser(
        "replay-trace", help="Replay a bounded synthetic vault failure trace"
    )
    trace.add_argument("trace", type=Path)
    commands.add_parser("desktop", help="Open the local desktop interface")
    from x12.transport_cli import add_commands

    add_commands(commands)
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            create_file(
                args.input, args.out, _creation_passwords(args), args.threshold, args.shares
            )
            print(f"Created {args.out}: {args.threshold}-of-{args.shares} recovery.")
            print("Distribute shares separately and retain each holder's password.")
        elif args.command in {"recover", "rekey"}:
            shares = [read_bounded(p, MAX_SHARE) for p in args.share]
            passwords = _recovery_passwords(args)
            if args.command == "recover":
                recover_file(args.vault, shares, passwords, args.out, args.checkpoint)
                print(f"Authenticated and recovered: {args.out}")
            else:
                rekey_file(
                    args.vault,
                    shares,
                    passwords,
                    args.out,
                    _creation_passwords(args, new=True),
                    args.threshold,
                    args.shares,
                    args.checkpoint,
                )
                print(f"New generation created: {args.out}. Old copies remain usable.")
        elif args.command == "inspect":
            print(
                json.dumps({"authenticated": False, "header": inspect_file(args.vault)}, indent=2)
            )
        elif args.command == "checkpoint":
            checkpoint_file(args.vault, args.out)
            print(
                f"Retain independently: {args.out}. This is a commitment, not a freshness service."
            )
        elif args.command == "lab":
            from x12.lab import run_lab

            return run_lab(args.report, args.seed)
        elif args.command == "replay":
            from x12.lab import replay_report

            return replay_report(args.report, args.out)
        elif args.command == "desktop":
            from x12.desktop import main as desktop

            return desktop()
        elif args.command == "reduce":
            from x12.traces import reduce_trace

            print(json.dumps(reduce_trace(args.trace, args.out), indent=2))
        elif args.command == "replay-trace":
            from x12.traces import replay_trace

            print(
                json.dumps(
                    {"synthetic_only": True, "recovery_error": replay_trace(args.trace)}, indent=2
                )
            )
        else:
            from x12.transport_cli import dispatch

            return dispatch(args)
    except (ValueError, OSError, EOFError, sqlite3.Error) as exc:
        print(f"x12: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("x12: interrupted; incomplete bundles have no COMPLETE marker", file=sys.stderr)
        return 130
    return 0
