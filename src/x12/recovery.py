"""Small standalone offline recovery entry point, including legacy v1 support."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from x12 import __version__
from x12.storage import read_bounded
from x12.streaming import recover_file
from x12.vault import MAX_SHARE, _integer


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="x12-recover", description="Offline x12 vault recovery")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("vault", type=Path)
    parser.add_argument("--share", type=Path, action="append", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--checkpoint", type=Path)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--password-file", type=Path)
    group.add_argument("--share-password-file", type=Path, action="append")
    args = parser.parse_args(argv)
    try:
        _integer(len(args.share), 2, 255)
        files = args.share_password_file
        if args.password_file:
            files = [args.password_file] * len(args.share)
        if files:
            passwords = []
            for path in files:
                value = read_bounded(path, 1026)
                if value.endswith(b"\n"):
                    value = value[:-1].removesuffix(b"\r")
                passwords.append(value)
        else:
            passwords = [getpass.getpass(f"Password for {p.name}: ").encode() for p in args.share]
        recover_file(
            args.vault,
            [read_bounded(p, MAX_SHARE) for p in args.share],
            passwords,
            args.out,
            args.checkpoint,
        )
        print(f"Authenticated and recovered: {args.out}")
    except (ValueError, OSError, EOFError) as exc:
        print(f"x12-recover: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("x12-recover: interrupted", file=sys.stderr)
        return 130
    return 0
