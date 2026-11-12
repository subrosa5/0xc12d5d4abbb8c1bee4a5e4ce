import json

import pytest

from x12.traces import evaluate, reduce_trace, replay_trace
from x12.vault import VaultError


def test_reduce_real_streaming_recovery_error(tmp_path):
    source = tmp_path / "trace.json"
    source.write_text(
        json.dumps(
            {
                "format": "x12-trace",
                "version": 1,
                "seed": 12,
                "actions": ["snapshot", "recover", "flip-footer", "recover", "restore"],
            }
        )
    )
    output = tmp_path / "reduced"
    report = reduce_trace(source, output)
    assert report["minimal_actions"] == ["flip-footer", "recover"]
    assert report["failure"]["type"] == "VaultError"
    assert replay_trace(output / "trace.json") == report["failure"]
    assert evaluate(12, ["recover"]) is None


def test_trace_cannot_supply_commands_or_paths(tmp_path):
    source = tmp_path / "bad.json"
    source.write_text(
        json.dumps(
            {
                "format": "x12-trace",
                "version": 1,
                "seed": 12,
                "actions": ["__import__('os').system('whoami')"],
            }
        )
    )
    with pytest.raises(VaultError):
        replay_trace(source)


def test_nonfailing_trace_not_reported_as_bug(tmp_path):
    source = tmp_path / "trace.json"
    source.write_text(
        json.dumps({"format": "x12-trace", "version": 1, "seed": 12, "actions": ["recover"]})
    )
    with pytest.raises(VaultError, match="does not produce"):
        reduce_trace(source, tmp_path / "report")
