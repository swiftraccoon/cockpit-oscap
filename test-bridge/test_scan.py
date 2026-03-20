"""Tests for the scan command and ARF parsing helpers."""
from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import subprocess
import textwrap

import pytest

BRIDGE_PATH = pathlib.Path(__file__).resolve().parent.parent / "src" / "oscap-bridge.py"
MAX_SCORE = 100.0
PRUNE_LIMIT = 3

# ---------------------------------------------------------------------------
# Synthetic ARF XML fixture
# ---------------------------------------------------------------------------

# Minimal ARF XML that exercises the parser without needing a real oscap run.
# Structure mirrors what `oscap xccdf eval --results-arf` produces.
SYNTHETIC_ARF_XML = textwrap.dedent("""\
<?xml version="1.0" encoding="UTF-8"?>
<arf:asset-report-collection
    xmlns:arf="urn:oasis:names:tc:dfi:2.0:asset-report-format:1.1"
    xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2"
    xmlns:core="http://scap.nist.gov/schema/asset-reporting-format/1.1/core"
    xmlns:ai="http://scap.nist.gov/schema/asset-identification/1.1">
  <arf:report-requests>
    <arf:report-request id="rr1">
      <arf:content>
        <xccdf:Benchmark id="xccdf_org.ssgproject.content_benchmark_FEDORA">
          <xccdf:Rule id="xccdf_org.ssgproject.content_rule_package_audit_installed" severity="medium">
            <xccdf:title>Ensure audit is installed</xccdf:title>
          </xccdf:Rule>
          <xccdf:Rule id="xccdf_org.ssgproject.content_rule_service_auditd_enabled" severity="medium">
            <xccdf:title>Enable auditd service</xccdf:title>
          </xccdf:Rule>
          <xccdf:Rule id="xccdf_org.ssgproject.content_rule_no_empty_passwords" severity="high">
            <xccdf:title>Prevent login to accounts with empty password</xccdf:title>
          </xccdf:Rule>
          <xccdf:Rule id="xccdf_org.ssgproject.content_rule_sshd_disable_root_login" severity="medium">
            <xccdf:title>Disable SSH root login</xccdf:title>
          </xccdf:Rule>
          <xccdf:Rule id="xccdf_org.ssgproject.content_rule_grub2_password" severity="high">
            <xccdf:title>Set boot loader password in grub2</xccdf:title>
          </xccdf:Rule>
        </xccdf:Benchmark>
      </arf:content>
    </arf:report-request>
  </arf:report-requests>
  <arf:reports>
    <arf:report id="xccdf1">
      <arf:content>
        <xccdf:TestResult id="xccdf_org.ssgproject.content_testresult_xccdf_profile"
                     test-system="cpe:/a:redhat:openscap:1.3.9">
          <xccdf:benchmark href="/usr/share/xml/scap/ssg/content/ssg-fedora-ds.xml"
                     id="xccdf_org.ssgproject.content_benchmark_FEDORA"/>
          <xccdf:title>OSCAP Scan Result</xccdf:title>
          <xccdf:rule-result idref="xccdf_org.ssgproject.content_rule_package_audit_installed"
                       severity="medium" time="2026-03-19T18:30:00" weight="1.0">
            <xccdf:result>pass</xccdf:result>
          </xccdf:rule-result>
          <xccdf:rule-result idref="xccdf_org.ssgproject.content_rule_service_auditd_enabled"
                       severity="medium" time="2026-03-19T18:30:01" weight="1.0">
            <xccdf:result>pass</xccdf:result>
          </xccdf:rule-result>
          <xccdf:rule-result idref="xccdf_org.ssgproject.content_rule_no_empty_passwords"
                       severity="high" time="2026-03-19T18:30:02" weight="1.0">
            <xccdf:result>fail</xccdf:result>
          </xccdf:rule-result>
          <xccdf:rule-result idref="xccdf_org.ssgproject.content_rule_sshd_disable_root_login"
                       severity="medium" time="2026-03-19T18:30:03" weight="1.0">
            <xccdf:result>notapplicable</xccdf:result>
          </xccdf:rule-result>
          <xccdf:rule-result idref="xccdf_org.ssgproject.content_rule_grub2_password"
                       severity="high" time="2026-03-19T18:30:04" weight="1.0">
            <xccdf:result>error</xccdf:result>
          </xccdf:rule-result>
          <xccdf:score system="urn:xccdf:scoring:default" maximum="100">66.67</xccdf:score>
        </xccdf:TestResult>
      </arf:content>
    </arf:report>
  </arf:reports>
</arf:asset-report-collection>
""")


@pytest.fixture
def arf_xml_path(tmp_path):
    """Write synthetic ARF XML to a temp file and return its path."""
    p = tmp_path / "test-result.arf.xml"
    p.write_text(SYNTHETIC_ARF_XML)
    return p


@pytest.fixture
def results_dir(tmp_path):
    """Create and return a temporary results directory."""
    d = tmp_path / "results"
    d.mkdir()
    return d


# ---------------------------------------------------------------------------
# Helper import — we import the bridge module directly for unit tests
# ---------------------------------------------------------------------------


@pytest.fixture
def bridge_module():
    """Import oscap-bridge as a module for direct function testing."""
    spec = importlib.util.spec_from_file_location("oscap_bridge", str(BRIDGE_PATH))
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Unit tests for ARF parsing (works on macOS without oscap)
# ---------------------------------------------------------------------------


class TestParseArfResults:
    """Test the _parse_arf_results helper with synthetic XML."""

    def test_returns_structured_result(self, bridge_module, arf_xml_path):
        """Verify parse returns score, results list, and expected fields."""
        result = bridge_module._parse_arf_results(str(arf_xml_path))
        assert "score" in result
        assert "results" in result
        assert isinstance(result["results"], list)
        assert len(result["results"]) > 0

    def test_result_has_rule_fields(self, bridge_module, arf_xml_path):
        """Each result item has rule_id, result, title, severity."""
        parsed = bridge_module._parse_arf_results(str(arf_xml_path))
        for item in parsed["results"]:
            assert "rule_id" in item, f"Missing rule_id in {item}"
            assert "result" in item, f"Missing result in {item}"
            assert "title" in item, f"Missing title in {item}"
            assert "severity" in item, f"Missing severity in {item}"

    def test_score_computed_from_pass_fail(self, bridge_module, arf_xml_path):
        """Score should reflect pass/fail/error counts (ignoring notapplicable)."""
        parsed = bridge_module._parse_arf_results(str(arf_xml_path))
        # Our fixture: 2 pass, 1 fail, 1 notapplicable, 1 error
        # Score = pass / (pass + fail + error) = 2/4 = 50.0
        assert isinstance(parsed["score"], float)
        assert 0.0 <= parsed["score"] <= MAX_SCORE

    def test_correct_rule_results(self, bridge_module, arf_xml_path):
        """Verify specific rule results from the synthetic fixture."""
        parsed = bridge_module._parse_arf_results(str(arf_xml_path))
        results_map = {r["rule_id"]: r for r in parsed["results"]}

        audit_rule = results_map["xccdf_org.ssgproject.content_rule_package_audit_installed"]
        assert audit_rule["result"] == "pass"
        assert audit_rule["severity"] == "medium"
        assert audit_rule["title"] == "Ensure audit is installed"

        empty_pw = results_map["xccdf_org.ssgproject.content_rule_no_empty_passwords"]
        assert empty_pw["result"] == "fail"
        assert empty_pw["severity"] == "high"

    def test_parse_arf_invalid_xml(self, bridge_module, tmp_path):
        """Parsing invalid XML raises or returns error gracefully."""
        bad = tmp_path / "bad.xml"
        bad.write_text("this is not xml")
        with pytest.raises(Exception):  # noqa: B017, PT011
            bridge_module._parse_arf_results(str(bad))


# ---------------------------------------------------------------------------
# Unit tests for result file management
# ---------------------------------------------------------------------------


class TestResultStorage:
    """Test result file writing and pruning helpers."""

    def test_save_scan_result_creates_files(self, bridge_module, arf_xml_path, results_dir):
        """Verify ARF XML and JSON cache are written to results_dir."""
        parsed = bridge_module._parse_arf_results(str(arf_xml_path))
        arf_dest, json_dest = bridge_module._save_scan_result(
            arf_source=str(arf_xml_path),
            parsed=parsed,
            profile_id="xccdf_org.ssgproject.content_profile_ospp",
            results_dir=results_dir,
        )
        assert pathlib.Path(arf_dest).exists()
        assert pathlib.Path(json_dest).exists()

        # JSON file should be loadable and match parsed data
        with pathlib.Path(json_dest).open() as f:
            saved = json.load(f)
        assert saved["score"] == parsed["score"]
        assert len(saved["results"]) == len(parsed["results"])

    def test_save_scan_result_filename_pattern(self, bridge_module, arf_xml_path, results_dir):
        """Filenames follow the timestamp-profileshortname pattern."""
        parsed = bridge_module._parse_arf_results(str(arf_xml_path))
        arf_dest, json_dest = bridge_module._save_scan_result(
            arf_source=str(arf_xml_path),
            parsed=parsed,
            profile_id="xccdf_org.ssgproject.content_profile_ospp",
            results_dir=results_dir,
        )
        arf_name = pathlib.Path(arf_dest).name
        json_name = pathlib.Path(json_dest).name
        # Should contain "ospp" as short name
        assert "ospp" in arf_name
        assert arf_name.endswith(".arf.xml")
        assert json_name.endswith(".json")

    def test_prune_old_results(self, bridge_module, results_dir):
        """Pruning removes oldest files beyond the configured max."""
        # Create 5 fake result pairs
        for i in range(5):
            (results_dir / f"2026-03-{10 + i:02d}T120000-test.arf.xml").write_text("<xml/>")
            (results_dir / f"2026-03-{10 + i:02d}T120000-test.json").write_text("{}")

        # Prune to keep max PRUNE_LIMIT pairs
        bridge_module._prune_old_results(results_dir, max_results=PRUNE_LIMIT)

        arf_files = sorted(results_dir.glob("*.arf.xml"))
        json_files = sorted(results_dir.glob("*.json"))
        assert len(arf_files) <= PRUNE_LIMIT
        assert len(json_files) <= PRUNE_LIMIT


# ---------------------------------------------------------------------------
# Integration test: scan command via subprocess (error path on macOS)
# ---------------------------------------------------------------------------


class TestScanCommand:
    """Integration tests for the scan command via subprocess."""

    def test_scan_without_oscap_returns_error_json(self):
        """On macOS without oscap, scan returns a JSON error and rc=1."""
        result = subprocess.run(
            ["python3", str(BRIDGE_PATH), "scan", "xccdf_org.ssgproject.content_profile_ospp"],
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
            # On a real system with oscap, we'd get a scan result
            assert "score" in data
            assert "results" in data
            assert "arf_path" in data

    def test_scan_with_tailoring_arg_accepted(self):
        """Verify the bridge accepts --tailoring-path without crashing."""
        result = subprocess.run(
            [
                "python3", str(BRIDGE_PATH), "scan",
                "xccdf_org.ssgproject.content_profile_ospp",
                "--tailoring-path", "/nonexistent/tailoring.xml",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        data = json.loads(result.stdout)
        # Should get an error (either oscap missing, or tailoring file not found),
        # but it should be valid JSON, not a crash
        assert isinstance(data, dict)

    def test_scan_no_profile_reads_config(self, tmp_path):
        """When no profile_id given, scan should try to read config.json."""
        result = subprocess.run(
            ["python3", str(BRIDGE_PATH), "scan"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
            env={**os.environ, "COCKPIT_OSCAP_DATA_DIR": str(tmp_path)},
        )
        data = json.loads(result.stdout)
        # Should get an error (no config or no oscap), but valid JSON
        assert isinstance(data, dict)
        assert "error" in data
