"""CLI wiring for explicit, fingerprint-pinned file handoff."""

import argparse
from pathlib import Path

from x12.storage import read_bounded
from x12.vault import MAX_SHARE, VaultError, parse_json


def add_commands(commands: argparse._SubParsersAction) -> None:
    identity = commands.add_parser("identity", help="Create protected device keys")
    identity.add_argument("--out", type=Path, required=True)
    identity.add_argument("--password-file", type=Path)
    fingerprint = commands.add_parser("fingerprint", help="Display a device public-key fingerprint")
    fingerprint.add_argument("public", type=Path)
    for name in ("request", "approve", "receive"):
        parser = commands.add_parser(name, help=f"{name.title()} an explicit offline share handoff")
        parser.add_argument("--identity", type=Path, required=True)
        parser.add_argument("--peer-public", type=Path, required=True)
        parser.add_argument(
            "--peer-fingerprint",
            required=True,
            help="Full fingerprint independently verified with the other person",
        )
        parser.add_argument("--password-file", type=Path)
        parser.add_argument("--out", type=Path, required=True)
        if name in {"request", "receive"}:
            parser.add_argument("--state", type=Path, required=True)
        if name == "request":
            parser.add_argument("--vault", type=Path, required=True)
            parser.add_argument("--lifetime", type=int, default=600)
        else:
            parser.add_argument("--request", type=Path, required=True)
        if name == "approve":
            parser.add_argument("--share", type=Path, required=True)
            parser.add_argument("--share-password-file", type=Path)
            parser.add_argument(
                "--confirm",
                action="store_true",
                help="Explicitly authorize release of this share to the pinned requester",
            )
        if name == "receive":
            parser.add_argument("--capsule", type=Path, required=True)
            parser.add_argument("--new-password-file", type=Path)


def dispatch(args: argparse.Namespace) -> int:
    from x12.cli import _password
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

    if args.command == "fingerprint":
        print(fingerprint(parse_json(read_bounded(args.public, MAX_MESSAGE))))
        return 0
    if args.command == "identity":
        print(create_identity(args.out, _password(args, confirm=True)))
        return 0
    peer = load_public(args.peer_public, args.peer_fingerprint)
    if args.command == "approve" and not args.confirm:
        raise VaultError(
            "Release requires --confirm after checking the request and peer fingerprint"
        )
    identity = load_identity(args.identity, _password(args))
    if args.command == "request":
        make_request(identity, peer, args.vault, args.out, args.state, args.lifetime)
    elif args.command == "approve":
        password = _password(argparse.Namespace(password_file=args.share_password_file))
        approve(
            identity, peer, args.request, read_bounded(args.share, MAX_SHARE), password, args.out
        )
    elif args.command == "receive":
        password = _password(argparse.Namespace(password_file=args.new_password_file), confirm=True)
        receive(identity, peer, args.request, args.capsule, args.state, args.out, password)
    else:
        raise VaultError("Unknown transport command")
    print(f"Created: {args.out}")
    return 0
