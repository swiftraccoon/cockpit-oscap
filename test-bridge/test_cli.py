"""Command dispatch, argument parsing and packaging guards."""
# mypy: disallow-untyped-defs=false, disallow-untyped-decorators=false, disallow-untyped-calls=false

from __future__ import annotations

import ast

import pytest
from conftest import BRIDGE_PATH

# The frontend passes the whole script as a single `python3 -c` argument; Linux
# limits a single argument to 128 KiB (MAX_ARG_STRLEN).  Keep a safety margin.
MAX_BRIDGE_BYTES = 120_000


def test_unknown_command(run_bridge):
    data = run_bridge("bogus-command", expect_rc=1)
    assert "bogus-command" in data["error"]


def test_usage_without_command(run_bridge):
    data = run_bridge(expect_rc=1)
    assert "usage" in data["error"]
    assert "detect-backend" in data["error"]


def test_every_handler_is_a_command(bridge):
    for name, handler in bridge.HANDLERS.items():
        assert callable(handler), name
        assert name == name.lower()


def test_bridge_stays_below_argv_limit():
    assert BRIDGE_PATH.stat().st_size < MAX_BRIDGE_BYTES


def test_bridge_is_python39_syntax():
    source = BRIDGE_PATH.read_text()
    ast.parse(source, feature_version=(3, 9))
    # Runtime-only 3.11 features that ast cannot catch:
    assert "StrEnum" not in source
    assert "datetime.UTC" not in source
    assert "from datetime import UTC" not in source


def test_positional_and_option_parsing(bridge):
    args = ["profile", "--datastream", "/ds.xml", "--no-tailoring", "--rules", "[]", "extra"]
    assert bridge._positional(args) == ["profile", "extra"]
    assert bridge._opt(args, "--datastream") == "/ds.xml"
    assert bridge._opt(args, "--missing") is None
    assert bridge._opt(["--datastream"], "--datastream") is None


def test_internal_errors_are_reported_as_json(bridge, capsys, monkeypatch):
    def boom(_args):
        raise RuntimeError("kaboom")

    monkeypatch.setitem(bridge.HANDLERS, "detect-backend", boom)
    with pytest.raises(SystemExit) as exc_info:
        bridge.main(["detect-backend"])
    assert exc_info.value.code == 1
    out = capsys.readouterr().out
    assert "internal error" in out
    assert "kaboom" in out


def test_bridge_errors_are_reported_as_json(bridge, capsys):
    with pytest.raises(SystemExit) as exc_info:
        bridge.main(["get-result", "../etc/passwd"])
    assert exc_info.value.code == 1
    assert "invalid result id" in capsys.readouterr().out
