"""Shared fixtures for the oscap-bridge test suite.

The bridge is a single script without a package, so tests import it with
``importlib`` after pointing its data directory, SCAP content directory and
os-release file at temporary locations.
"""
# mypy: disallow-untyped-defs=false, disallow-untyped-decorators=false, disallow-untyped-calls=false

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys
import textwrap
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import ModuleType

BRIDGE_PATH = pathlib.Path(__file__).resolve().parent.parent / "src" / "oscap-bridge.py"
SSG_CONTENT_DIR = pathlib.Path("/usr/share/xml/scap/ssg/content")

PROFILE_BASE = "xccdf_org.test.content_profile_base"
PROFILE_EXTENDED = "xccdf_org.test.content_profile_extended"
RULE_AUDIT = "xccdf_org.test.content_rule_audit_installed"
RULE_ROOT_LOGIN = "xccdf_org.test.content_rule_sshd_root_login"
RULE_TIMEOUT = "xccdf_org.test.content_rule_sshd_timeout"
RULE_NEVER = "xccdf_org.test.content_rule_never_selected"
VALUE_TIMEOUT = "xccdf_org.test.content_value_timeout"
VALUE_UNUSED = "xccdf_org.test.content_value_unused"

# A tiny but structurally faithful SCAP source datastream: profiles (one
# extending another, one abstract), nested groups, values with selectors,
# rules with check exports and a fix, followed by a (dummy) OVAL component.
SYNTHETIC_DATASTREAM = textwrap.dedent(f"""\
<?xml version="1.0" encoding="UTF-8"?>
<ds:data-stream-collection xmlns:ds="http://scap.nist.gov/schema/scap/source/1.2"
    xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2"
    xmlns:html="http://www.w3.org/1999/xhtml" id="scap_org.open-scap_collection_test">
  <ds:data-stream id="scap_org.open-scap_datastream_test"/>
  <ds:component id="scap_org.open-scap_comp_test-xccdf.xml">
    <xccdf:Benchmark id="xccdf_org.test.content_benchmark_TEST">
      <xccdf:title>Test Benchmark</xccdf:title>
      <xccdf:version>1.0</xccdf:version>
      <xccdf:Profile id="{PROFILE_BASE}">
        <xccdf:title>Base Profile</xccdf:title>
        <xccdf:description>
          <html:p>First paragraph.</html:p><html:p>Second   paragraph.</html:p>
        </xccdf:description>
        <xccdf:select idref="{RULE_AUDIT}" selected="true"/>
        <xccdf:select idref="xccdf_org.test.content_group_ssh" selected="true"/>
        <xccdf:refine-value idref="{VALUE_TIMEOUT}" selector="10_minutes"/>
      </xccdf:Profile>
      <xccdf:Profile id="{PROFILE_EXTENDED}" extends="{PROFILE_BASE}">
        <xccdf:title>Extended Profile</xccdf:title>
        <xccdf:select idref="{RULE_ROOT_LOGIN}" selected="false"/>
        <xccdf:set-value idref="{VALUE_TIMEOUT}">42</xccdf:set-value>
      </xccdf:Profile>
      <xccdf:Profile id="xccdf_org.test.content_profile_abstract" abstract="true">
        <xccdf:title>Hidden</xccdf:title>
      </xccdf:Profile>
      <xccdf:Value id="{VALUE_TIMEOUT}" type="number">
        <xccdf:title>Idle timeout</xccdf:title>
        <xccdf:description>Seconds before idle sessions end.</xccdf:description>
        <xccdf:value>300</xccdf:value>
        <xccdf:value selector="5_minutes">300</xccdf:value>
        <xccdf:value selector="10_minutes">600</xccdf:value>
      </xccdf:Value>
      <xccdf:Value id="{VALUE_UNUSED}" type="string">
        <xccdf:title>Unused</xccdf:title>
        <xccdf:value>x</xccdf:value>
      </xccdf:Value>
      <xccdf:Group id="xccdf_org.test.content_group_system">
        <xccdf:title>System Settings</xccdf:title>
        <xccdf:Group id="xccdf_org.test.content_group_audit">
          <xccdf:title>Auditing</xccdf:title>
          <xccdf:Rule id="{RULE_AUDIT}" severity="medium" selected="false">
            <xccdf:title>Ensure audit is installed</xccdf:title>
            <xccdf:description>Install the <html:code>audit</html:code> package.</xccdf:description>
            <xccdf:rationale>Auditing matters.</xccdf:rationale>
            <xccdf:warning category="general">Be careful.</xccdf:warning>
            <xccdf:ident system="https://ncp.nist.gov/cce">CCE-1</xccdf:ident>
            <xccdf:reference href="https://example.com/ref">R1</xccdf:reference>
            <xccdf:fix system="urn:xccdf:fix:script:sh">dnf install -y audit</xccdf:fix>
            <xccdf:check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">
              <xccdf:check-content-ref href="test-oval.xml" name="oval:test:def:1"/>
            </xccdf:check>
          </xccdf:Rule>
          <xccdf:Rule id="{RULE_NEVER}" severity="low" selected="false">
            <xccdf:title>Never selected</xccdf:title>
          </xccdf:Rule>
        </xccdf:Group>
      </xccdf:Group>
      <xccdf:Group id="xccdf_org.test.content_group_services">
        <xccdf:title>Services</xccdf:title>
        <xccdf:Group id="xccdf_org.test.content_group_ssh">
          <xccdf:title>SSH Server</xccdf:title>
          <xccdf:Rule id="{RULE_ROOT_LOGIN}" severity="high" selected="false">
            <xccdf:title>Disable SSH root login</xccdf:title>
            <xccdf:description>No root over SSH.</xccdf:description>
            <xccdf:fix system="urn:xccdf:fix:script:ansible">- name: no root login</xccdf:fix>
            <xccdf:check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">
              <xccdf:check-export export-name="oval:test:var:1" value-id="{VALUE_TIMEOUT}"/>
              <xccdf:check-content-ref href="test-oval.xml" name="oval:test:def:2"/>
            </xccdf:check>
          </xccdf:Rule>
          <xccdf:Rule id="{RULE_TIMEOUT}" severity="medium" selected="false">
            <xccdf:title>Set SSH idle timeout</xccdf:title>
            <xccdf:check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">
              <xccdf:check-export export-name="oval:test:var:2" value-id="{VALUE_TIMEOUT}"/>
              <xccdf:check-content-ref href="test-oval.xml" name="oval:test:def:3"/>
            </xccdf:check>
          </xccdf:Rule>
        </xccdf:Group>
      </xccdf:Group>
    </xccdf:Benchmark>
  </ds:component>
  <ds:component id="scap_org.open-scap_comp_test-oval.xml">
    <oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"/>
  </ds:component>
</ds:data-stream-collection>
""")

# An ARF document as produced by `oscap xccdf eval --results-arf`, trimmed to
# the parts the bridge reads: the embedded benchmark (with groups) and the
# TestResult with rule results, a message, a score and a notselected rule.
SYNTHETIC_ARF = textwrap.dedent(f"""\
<?xml version="1.0" encoding="UTF-8"?>
<arf:asset-report-collection
    xmlns:arf="urn:oasis:names:tc:dfi:2.0:asset-report-format:1.1"
    xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2">
  <arf:report-requests>
    <arf:report-request id="rr1">
      <arf:content>
        <xccdf:Benchmark id="xccdf_org.test.content_benchmark_TEST">
          <xccdf:Group id="g1"><xccdf:title>System Settings</xccdf:title>
            <xccdf:Group id="g2"><xccdf:title>Auditing</xccdf:title>
              <xccdf:Rule id="{RULE_AUDIT}" severity="medium">
                <xccdf:title>Ensure audit is installed</xccdf:title>
              </xccdf:Rule>
              <xccdf:Rule id="{RULE_NEVER}" severity="low"><xccdf:title>Never selected</xccdf:title></xccdf:Rule>
            </xccdf:Group>
          </xccdf:Group>
          <xccdf:Group id="g3"><xccdf:title>Services</xccdf:title>
            <xccdf:Group id="g4"><xccdf:title>SSH Server</xccdf:title>
              <xccdf:Rule id="{RULE_ROOT_LOGIN}" severity="high">
                <xccdf:title>Disable SSH root login</xccdf:title>
              </xccdf:Rule>
              <xccdf:Rule id="{RULE_TIMEOUT}" severity="medium">
                <xccdf:title>Set SSH idle timeout</xccdf:title>
              </xccdf:Rule>
            </xccdf:Group>
          </xccdf:Group>
        </xccdf:Benchmark>
      </arf:content>
    </arf:report-request>
  </arf:report-requests>
  <arf:reports>
    <arf:report id="xccdf1">
      <arf:content>
        <xccdf:TestResult id="xccdf_org.open-scap_testresult_{PROFILE_BASE}"
                          start-time="2026-03-19T18:30:00+00:00" end-time="2026-03-19T18:31:00+00:00"
                          version="1.0">
          <xccdf:benchmark href="#comp" id="xccdf_org.test.content_benchmark_TEST"/>
          <xccdf:title>OSCAP Scan Result</xccdf:title>
          <xccdf:profile idref="{PROFILE_BASE}"/>
          <xccdf:rule-result idref="{RULE_AUDIT}" severity="medium" time="2026-03-19T18:30:00">
            <xccdf:result>pass</xccdf:result>
          </xccdf:rule-result>
          <xccdf:rule-result idref="{RULE_ROOT_LOGIN}" severity="high" time="2026-03-19T18:30:01">
            <xccdf:result>fail</xccdf:result>
          </xccdf:rule-result>
          <xccdf:rule-result idref="{RULE_TIMEOUT}" severity="medium" time="2026-03-19T18:30:02">
            <xccdf:result>error</xccdf:result>
            <xccdf:message severity="error">probe failed</xccdf:message>
          </xccdf:rule-result>
          <xccdf:rule-result idref="{RULE_NEVER}" severity="low" time="2026-03-19T18:30:03">
            <xccdf:result>notselected</xccdf:result>
          </xccdf:rule-result>
          <xccdf:rule-result idref="xccdf_org.test.content_rule_unknown" severity="unknown"
                             time="2026-03-19T18:30:04">
            <xccdf:result>notapplicable</xccdf:result>
          </xccdf:rule-result>
          <xccdf:score system="urn:xccdf:scoring:default" maximum="100.000000">33.333333</xccdf:score>
        </xccdf:TestResult>
      </arf:content>
    </arf:report>
  </arf:reports>
</arf:asset-report-collection>
""")


def load_bridge(name: str = "oscap_bridge") -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, str(BRIDGE_PATH))
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def data_dir(tmp_path: pathlib.Path) -> pathlib.Path:
    d = tmp_path / "data"
    d.mkdir()
    return d


@pytest.fixture
def content_dir(tmp_path: pathlib.Path) -> pathlib.Path:
    d = tmp_path / "content"
    d.mkdir()
    (d / "ssg-test-ds.xml").write_text(SYNTHETIC_DATASTREAM)
    return d


@pytest.fixture
def os_release(tmp_path: pathlib.Path) -> pathlib.Path:
    p = tmp_path / "os-release"
    p.write_text('ID=test\nVERSION_ID="1"\nPRETTY_NAME="Test OS 1"\n')
    return p


@pytest.fixture
def bridge_env(monkeypatch: pytest.MonkeyPatch, data_dir: pathlib.Path, content_dir: pathlib.Path,
               os_release: pathlib.Path) -> dict[str, str]:
    env = {
        "COCKPIT_OSCAP_DATA_DIR": str(data_dir),
        "COCKPIT_OSCAP_CONTENT_DIR": str(content_dir),
        "COCKPIT_OSCAP_OS_RELEASE": str(os_release),
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return env


@pytest.fixture
def bridge(bridge_env: dict[str, str]) -> ModuleType:
    """The bridge module, isolated to temporary data/content directories."""
    assert bridge_env
    return load_bridge()


@pytest.fixture
def datastream(content_dir: pathlib.Path) -> str:
    return str(content_dir / "ssg-test-ds.xml")


@pytest.fixture
def arf_path(tmp_path: pathlib.Path) -> pathlib.Path:
    p = tmp_path / "result.arf.xml"
    p.write_text(SYNTHETIC_ARF)
    return p


@pytest.fixture
def run_bridge(bridge_env: dict[str, str]) -> Callable[..., Any]:
    """Invoke the bridge as a subprocess and return the parsed JSON of its last output line."""

    def _run(*args: str, expect_rc: int = 0, stdin: str | None = None) -> Any:
        result = subprocess.run(
            ["python3", str(BRIDGE_PATH), *args],
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
            input=stdin,
            env={**os.environ, **bridge_env},
        )
        assert result.returncode == expect_rc, (
            f"Expected rc={expect_rc}, got {result.returncode}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}")
        lines = [line for line in result.stdout.splitlines() if line.strip()]
        assert lines, f"no output\nstderr: {result.stderr}"
        return json.loads(lines[-1])

    return _run


def real_content() -> pathlib.Path | None:
    """Return a real SSG datastream if OpenSCAP and content are installed."""
    if shutil.which("oscap") is None or not SSG_CONTENT_DIR.is_dir():
        return None
    candidates = sorted(SSG_CONTENT_DIR.glob("ssg-*-ds.xml"))
    return candidates[-1] if candidates else None


requires_oscap = pytest.mark.skipif(real_content() is None,
                                    reason="oscap and scap-security-guide are not installed")
