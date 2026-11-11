import hashlib
import json
import random

import pytest

from x12 import __version__
from x12.lab import minimize, nonce_reuse, replay_report, run_lab
from x12.vault import VaultError


def test_minimize_restart_and_rollback_models():
    for actions in [
        ["snapshot", "encrypt", "encrypt", "restart", "snapshot", "encrypt"],
        ["snapshot", "encrypt", "encrypt", "restore", "encrypt"],
    ]:
        result = minimize(actions, nonce_reuse)
        assert nonce_reuse(result)
        assert all(not nonce_reuse(result[:i] + result[i + 1 :]) for i in range(len(result)))
    with pytest.raises(VaultError):
        minimize(["encrypt"], nonce_reuse)


def test_lab_and_replay(tmp_path):
    report_dir = tmp_path / "report"
    assert run_lab(report_dir, seed=42) == 0
    report = json.loads((report_dir / "report.json").read_text())
    assert all(case["passed"] for case in report["results"])
    assert report["synthetic_only"] is True
    assert report["counter_model_demo"]["vault_implementation"] is False
    assert "synthetic-lab-password-only" not in (report_dir / "report.json").read_text()
    assert replay_report(report_dir / "report.json", tmp_path / "replay") == 0
    replayed = json.loads((tmp_path / "replay/report.json").read_text())
    assert replayed["fixture_sha256"] == report["fixture_sha256"]
    assert replayed["results"] == report["results"]


@pytest.mark.parametrize("seed", [-1, True, 2**64, "12"])
def test_invalid_seeds_rejected(tmp_path, seed):
    with pytest.raises(VaultError):
        run_lab(tmp_path / "report", seed=seed)
    assert not (tmp_path / "report").exists()


def test_replay_is_data_not_commands(tmp_path):
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps(
            {
                "format": "x12-lab-report",
                "version": 1,
                "tool_version": __version__,
                "synthetic_only": True,
                "seed": "__import__('os').system('whoami')",
            }
        )
    )
    with pytest.raises(VaultError):
        replay_report(report, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_replay_rejects_mismatched_fixtures_and_versions(tmp_path):
    path = tmp_path / "report.json"
    report = {
        "format": "x12-lab-report",
        "version": 1,
        "tool_version": __version__,
        "synthetic_only": True,
        "seed": 12,
        "fixture_sha256": "0" * 64,
    }
    path.write_text(json.dumps(report))
    with pytest.raises(VaultError):
        replay_report(path, tmp_path / "out")
    report["fixture_sha256"] = hashlib.sha256(random.Random(12).randbytes(4096)).hexdigest()
    report["tool_version"] = "future-version"
    path.write_text(json.dumps(report))
    with pytest.raises(VaultError):
        replay_report(path, tmp_path / "out")
