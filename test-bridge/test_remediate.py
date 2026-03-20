"""Tests for generate-fix and apply-fix commands."""
from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import sys
import textwrap

import pytest

BRIDGE_PATH = pathlib.Path(__file__).resolve().parent.parent / "src" / "oscap-bridge.py"

EXPECTED_RULE_COUNT = 3


@pytest.fixture
def bridge():
    """Import oscap-bridge.py as a module."""
    spec = importlib.util.spec_from_file_location("oscap_bridge", str(BRIDGE_PATH))
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["oscap_bridge"] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Fix script parser tests (synthetic input, no oscap needed)
# ---------------------------------------------------------------------------


SYNTHETIC_FIX_SCRIPT = textwrap.dedent("""\
#!/bin/bash
# OSCAP remediation script

###############################################################################
# BEGIN fix (xccdf_org.ssgproject.content_rule_package_audit_installed) for 'package_audit_installed'
###############################################################################
dnf install -y audit
# END fix (xccdf_org.ssgproject.content_rule_package_audit_installed) for 'package_audit_installed'
###############################################################################

###############################################################################
# BEGIN fix (xccdf_org.ssgproject.content_rule_service_auditd_enabled) for 'service_auditd_enabled'
###############################################################################
systemctl enable --now auditd
# END fix (xccdf_org.ssgproject.content_rule_service_auditd_enabled) for 'service_auditd_enabled'
###############################################################################

###############################################################################
# BEGIN fix (xccdf_org.ssgproject.content_rule_no_empty_passwords) for 'no_empty_passwords'
###############################################################################
sed -i 's/nullok//g' /etc/pam.d/system-auth
# END fix (xccdf_org.ssgproject.content_rule_no_empty_passwords) for 'no_empty_passwords'
###############################################################################
""")


class TestFixScriptParser:
    """Test _parse_fix_script with synthetic oscap-style output."""

    def test_parses_three_rules(self, bridge):
        rules = bridge._parse_fix_script(SYNTHETIC_FIX_SCRIPT)
        assert len(rules) == EXPECTED_RULE_COUNT

    def test_rule_ids_extracted(self, bridge):
        rules = bridge._parse_fix_script(SYNTHETIC_FIX_SCRIPT)
        ids = [r["id"] for r in rules]
        assert "xccdf_org.ssgproject.content_rule_package_audit_installed" in ids
        assert "xccdf_org.ssgproject.content_rule_service_auditd_enabled" in ids
        assert "xccdf_org.ssgproject.content_rule_no_empty_passwords" in ids

    def test_fix_snippets_contain_commands(self, bridge):
        rules = bridge._parse_fix_script(SYNTHETIC_FIX_SCRIPT)
        by_id = {r["id"]: r for r in rules}
        assert "dnf install" in by_id["xccdf_org.ssgproject.content_rule_package_audit_installed"]["fix_snippet"]
        assert "systemctl" in by_id["xccdf_org.ssgproject.content_rule_service_auditd_enabled"]["fix_snippet"]

    def test_risk_levels_assigned(self, bridge):
        rules = bridge._parse_fix_script(SYNTHETIC_FIX_SCRIPT)
        by_id = {r["id"]: r for r in rules}
        # systemctl -> medium
        assert by_id["xccdf_org.ssgproject.content_rule_service_auditd_enabled"]["risk_level"] == "medium"
        # pam.d -> high
        assert by_id["xccdf_org.ssgproject.content_rule_no_empty_passwords"]["risk_level"] == "high"
        # dnf install -> low
        assert by_id["xccdf_org.ssgproject.content_rule_package_audit_installed"]["risk_level"] == "low"

    def test_empty_script_returns_empty(self, bridge):
        rules = bridge._parse_fix_script("")
        assert rules == []

    def test_script_without_markers_returns_empty(self, bridge):
        rules = bridge._parse_fix_script("#!/bin/bash\necho hello\n")
        assert rules == []


# ---------------------------------------------------------------------------
# Integration tests: generate-fix via subprocess (error path on macOS)
# ---------------------------------------------------------------------------


class TestGenerateFixCommand:
    """Integration tests for generate-fix via subprocess."""

    def test_generate_fix_without_oscap_returns_error(self):
        """On macOS without oscap, generate-fix returns error JSON."""
        result = subprocess.run(
            ["python3", str(BRIDGE_PATH), "generate-fix",
             "xccdf_org.ssgproject.content_profile_ospp"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        data = json.loads(result.stdout)
        if "error" in data:
            # Expected on macOS — oscap not installed
            assert result.returncode == 1
            assert isinstance(data["error"], str)
        else:
            # On a real system with oscap, we'd get fix info
            assert "script" in data
            assert "rules" in data

    def test_generate_fix_returns_script_and_rules_fields(self):
        """Verify output has the expected FixInfo shape."""
        result = subprocess.run(
            ["python3", str(BRIDGE_PATH), "generate-fix",
             "xccdf_org.ssgproject.content_profile_ospp"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        data = json.loads(result.stdout)
        if "error" not in data:
            assert "script" in data
            assert "rules" in data
            assert isinstance(data["rules"], list)

    def test_generate_fix_rules_have_risk(self):
        """Each rule in the output has a risk_level field."""
        result = subprocess.run(
            ["python3", str(BRIDGE_PATH), "generate-fix",
             "xccdf_org.ssgproject.content_profile_ospp"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        data = json.loads(result.stdout)
        if "error" not in data:
            for rule in data["rules"]:
                assert "risk_level" in rule
                assert rule["risk_level"] in ("low", "medium", "high")


# ---------------------------------------------------------------------------
# Integration tests: apply-fix via subprocess (error path on macOS)
# ---------------------------------------------------------------------------


class TestApplyFixCommand:
    """Integration tests for apply-fix via subprocess."""

    def test_apply_fix_returns_result(self, tmp_path):
        """Verify output has success, output, errors fields."""
        script = tmp_path / "fix.sh"
        script.write_text("#!/bin/bash\necho 'hello from fix'\n")
        script.chmod(0o755)

        result = subprocess.run(
            ["python3", str(BRIDGE_PATH), "apply-fix", str(script)],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        data = json.loads(result.stdout)
        assert "success" in data
        assert "output" in data
        assert "errors" in data

    def test_apply_fix_success(self, tmp_path):
        """A script that exits 0 produces success=true."""
        script = tmp_path / "fix.sh"
        script.write_text("#!/bin/bash\necho 'applied'\n")
        script.chmod(0o755)

        result = subprocess.run(
            ["python3", str(BRIDGE_PATH), "apply-fix", str(script)],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        data = json.loads(result.stdout)
        assert data["success"] is True
        assert "applied" in data["output"]
        assert data["errors"] == ""

    def test_apply_fix_failure(self, tmp_path):
        """A script that exits non-zero produces success=false."""
        script = tmp_path / "fix.sh"
        script.write_text("#!/bin/bash\necho 'failure message' >&2\nexit 1\n")
        script.chmod(0o755)

        result = subprocess.run(
            ["python3", str(BRIDGE_PATH), "apply-fix", str(script)],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        data = json.loads(result.stdout)
        assert data["success"] is False
        assert "failure message" in data["errors"]

    def test_apply_fix_missing_script(self):
        """Applying a nonexistent script returns an error."""
        result = subprocess.run(
            ["python3", str(BRIDGE_PATH), "apply-fix", "/nonexistent/fix.sh"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        data = json.loads(result.stdout)
        assert "error" in data
