"""Tests for the detect-backend command."""
from __future__ import annotations

import json
import pathlib
import subprocess

BRIDGE_PATH = pathlib.Path(__file__).resolve().parent.parent / "src" / "oscap-bridge.py"


def _run_detect_backend():
    """Run detect-backend and return (parsed_json, returncode)."""
    result = subprocess.run(
        ["python3", str(BRIDGE_PATH), "detect-backend"],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    data = json.loads(result.stdout)
    return data, result.returncode


def test_detect_backend_returns_oscap_info():
    """Verify oscap version and path fields exist in detect-backend response.

    On macOS without oscap, the bridge returns an error JSON with rc=1.
    That is acceptable — the dispatcher still works and returns valid JSON.
    """
    data, rc = _run_detect_backend()
    if "error" in data:
        # oscap not installed — acceptable on macOS dev machines
        assert rc == 1
        assert "oscap" in data["error"]
    else:
        assert rc == 0
        assert "oscap" in data
        oscap = data["oscap"]
        assert "version" in oscap
        assert "path" in oscap


def test_detect_backend_returns_content_info():
    """Verify content datastream_path field exists in detect-backend response."""
    data, rc = _run_detect_backend()
    if "error" in data:
        assert rc == 1
    else:
        assert rc == 0
        assert "content" in data
        content = data["content"]
        assert "datastream_path" in content
        assert "present" in content


def test_detect_backend_complyctl_null_when_missing():
    """Verify complyctl field exists in the response (may be null or populated)."""
    data, rc = _run_detect_backend()
    if "error" in data:
        assert rc == 1
    else:
        assert rc == 0
        assert "complyctl" in data
        # complyctl may be None/null if not installed, or a dict if installed


def test_unknown_command_returns_error(run_bridge):
    """Verify error response for unknown commands."""
    data = run_bridge("bogus-command", expect_rc=1)
    assert "error" in data
    assert "bogus-command" in data["error"]
