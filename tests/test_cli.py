import json
import os
import subprocess
import sys
from argparse import Namespace

import pytest

from x12.cli import _password, main


@pytest.mark.parametrize(
    "suffix,expected", [(b"\n", b""), (b"\r\n", b""), (b"\r", b"\r"), (b"", b"")]
)
def test_password_file_newline_rules(tmp_path, suffix, expected):
    path = tmp_path / "password"
    path.write_bytes(b"long-test-password" + suffix)
    assert _password(Namespace(password_file=path)) == b"long-test-password" + expected


def test_cli_create_inspect_recover_and_no_clobber(tmp_path, capsys):
    source = tmp_path / "input.txt"
    source.write_bytes(b"cli synthetic fixture")
    password = tmp_path / "password"
    password.write_bytes(b"cli-fixture-password\n")
    bundle = tmp_path / "bundle"
    args = ["--password-file", str(password)]
    assert main(["create", str(source), "--out", str(bundle), *args]) == 0
    assert (bundle / "COMPLETE").exists()
    assert len(list(bundle.glob("*.x12share"))) == 5
    if os.name == "posix":
        assert bundle.stat().st_mode & 0o777 == 0o700
    capsys.readouterr()
    assert main(["inspect", str(bundle / "vault.x12")]) == 0
    metadata = json.loads(capsys.readouterr().out)
    assert metadata["authenticated"] is False
    assert metadata["header"]["threshold"] == 3
    recovery = ["recover", str(bundle / "vault.x12"), *args]
    for index in [1, 3, 5]:
        recovery.extend(["--share", str(bundle / f"share-{index:03d}.x12share")])
    output = tmp_path / "recovered"
    assert main([*recovery, "--out", str(output)]) == 0
    assert output.read_bytes() == source.read_bytes()
    assert main([*recovery, "--out", str(output)]) == 1
    assert output.read_bytes() == source.read_bytes()
    assert main(["create", str(source), "--out", str(bundle), *args]) == 1
    assert (bundle / "COMPLETE").exists()


def test_authentication_failure_never_writes_plaintext(tmp_path):
    source = tmp_path / "input"
    source.write_bytes(b"private synthetic text")
    password = tmp_path / "password"
    password.write_bytes(b"correct-fixture-password")
    bundle = tmp_path / "bundle"
    assert (
        main(
            [
                "create",
                str(source),
                "--out",
                str(bundle),
                "--threshold",
                "2",
                "--shares",
                "2",
                "--password-file",
                str(password),
            ]
        )
        == 0
    )
    encrypted = bundle / "vault.x12"
    raw = encrypted.read_bytes()
    encrypted.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
    output = tmp_path / "must-not-exist"
    assert (
        main(
            [
                "recover",
                str(encrypted),
                "--out",
                str(output),
                "--share",
                str(bundle / "share-001.x12share"),
                "--share",
                str(bundle / "share-002.x12share"),
                "--password-file",
                str(password),
            ]
        )
        == 1
    )
    assert not output.exists()
    assert not list(tmp_path.glob(".x12-*"))


def test_module_help_and_version():
    for args in [["--help"], ["--version"]]:
        result = subprocess.run(
            [sys.executable, "-m", "x12", *args], capture_output=True, text=True, check=False
        )
        assert result.returncode == 0
        assert result.stdout
        assert not result.stderr


def test_create_and_recover_in_separate_processes(tmp_path):
    source = tmp_path / "source"
    source.write_bytes(b"survives a real process restart")
    password = tmp_path / "password"
    password.write_bytes(b"separate-process-password")
    bundle = tmp_path / "bundle"
    output = tmp_path / "restored"
    commands = [
        [
            "create",
            str(source),
            "--out",
            str(bundle),
            "--threshold",
            "2",
            "--shares",
            "2",
            "--password-file",
            str(password),
        ],
        [
            "recover",
            str(bundle / "vault.x12"),
            "--out",
            str(output),
            "--share",
            str(bundle / "share-001.x12share"),
            "--share",
            str(bundle / "share-002.x12share"),
            "--password-file",
            str(password),
        ],
    ]
    for command in commands:
        process = subprocess.run(
            [sys.executable, "-m", "x12", *command],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        assert process.returncode == 0, process.stderr
    assert output.read_bytes() == source.read_bytes()
