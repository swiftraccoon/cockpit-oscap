"""Shared fixtures for oscap-bridge tests."""
from __future__ import annotations

import json
import pathlib
import subprocess

import pytest

BRIDGE_PATH = pathlib.Path(__file__).resolve().parent.parent / "src" / "oscap-bridge.py"


@pytest.fixture
def bridge_path():
    """Return the absolute path to oscap-bridge.py."""
    return BRIDGE_PATH


@pytest.fixture
def run_bridge(bridge_path):
    """Return a helper that invokes oscap-bridge.py with args and parses JSON output."""

    def _run(*args, expect_rc=0):
        result = subprocess.run(
            ["python3", str(bridge_path), *args],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        assert result.returncode == expect_rc, (
            f"Expected rc={expect_rc}, got {result.returncode}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        return json.loads(result.stdout)

    return _run
