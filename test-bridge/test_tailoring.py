"""Tests for create-tailoring and parse-tailoring commands."""
from __future__ import annotations

import importlib.util
import os
import pathlib
import sys
import textwrap
import xml.etree.ElementTree as ET

import pytest

BRIDGE_PATH = pathlib.Path(__file__).resolve().parent.parent / "src" / "oscap-bridge.py"

EXPECTED_SELECT_COUNT = 2


@pytest.fixture
def bridge(tmp_path: pathlib.Path):
    """Import oscap-bridge.py as a module with DATA_DIR pointed at tmp_path."""
    # Set env var BEFORE importing so the module picks it up
    os.environ["COCKPIT_OSCAP_DATA_DIR"] = str(tmp_path)
    spec = importlib.util.spec_from_file_location("oscap_bridge_tailoring", str(BRIDGE_PATH))
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["oscap_bridge_tailoring"] = mod
    spec.loader.exec_module(mod)
    yield mod
    # Cleanup
    os.environ.pop("COCKPIT_OSCAP_DATA_DIR", None)
    sys.modules.pop("oscap_bridge_tailoring", None)


# ---------------------------------------------------------------------------
# Synthetic tailoring XML for parse tests
# ---------------------------------------------------------------------------

SYNTHETIC_TAILORING_XML = textwrap.dedent("""\
<?xml version="1.0" encoding="UTF-8"?>
<xccdf:Tailoring xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2"
                 id="cockpit-oscap-tailoring">
  <xccdf:version time="2026-03-19T00:00:00">1</xccdf:version>
  <xccdf:Profile id="cockpit_oscap_custom_profile"
                 extends="xccdf_org.ssgproject.content_profile_ospp">
    <xccdf:title>Custom profile based on ospp</xccdf:title>
    <xccdf:select idref="xccdf_org.ssgproject.content_rule_package_audit_installed"
                  selected="true"/>
    <xccdf:select idref="xccdf_org.ssgproject.content_rule_no_empty_passwords"
                  selected="false"/>
    <xccdf:set-value idref="xccdf_org.ssgproject.content_value_var_password_minlen">12</xccdf:set-value>
  </xccdf:Profile>
</xccdf:Tailoring>
""")

# Base profile ID used across tests
_BASE_PROFILE = "xccdf_org.ssgproject.content_profile_ospp"

# Reusable modifications list for create tests
_FULL_MODIFICATIONS: list[dict[str, str]] = [
    {
        "rule_id": "xccdf_org.ssgproject.content_rule_package_audit_installed",
        "action": "enable",
    },
    {
        "rule_id": "xccdf_org.ssgproject.content_rule_no_empty_passwords",
        "action": "disable",
    },
    {
        "rule_id": "xccdf_org.ssgproject.content_value_var_password_minlen",
        "action": "set-value",
        "value": "12",
    },
]


# ---------------------------------------------------------------------------
# create-tailoring tests
# ---------------------------------------------------------------------------


class TestCreateTailoring:
    """Tests for the _build_tailoring_xml helper function."""

    def test_create_tailoring_generates_xml(self, bridge):
        """Create tailoring from base profile with modifications, verify valid XCCDF XML."""
        result = bridge._build_tailoring_xml(_BASE_PROFILE, _FULL_MODIFICATIONS)
        xml_str = result["tailoring_xml"]

        # Must be parseable XML
        root = ET.fromstring(xml_str)  # noqa: S314

        # Root element is xccdf:Tailoring
        ns = "http://checklists.nist.gov/xccdf/1.2"
        assert root.tag == f"{{{ns}}}Tailoring"

        # Must contain a Profile element
        profile = root.find(f"{{{ns}}}Profile")
        assert profile is not None
        assert profile.get("extends") == _BASE_PROFILE

        # Must contain select and set-value elements
        selects = profile.findall(f"{{{ns}}}select")
        assert len(selects) == EXPECTED_SELECT_COUNT

        set_values = profile.findall(f"{{{ns}}}set-value")
        assert len(set_values) == 1

    def test_create_tailoring_writes_file(self, bridge):
        """Verify tailoring file is written to TAILORING_DIR."""
        modifications = [
            {
                "rule_id": "xccdf_org.ssgproject.content_rule_package_audit_installed",
                "action": "enable",
            },
        ]

        result = bridge._build_tailoring_xml(_BASE_PROFILE, modifications)
        path = pathlib.Path(result["path"])

        assert path.exists()
        assert path.suffix == ".xml"
        assert "tailoring" in str(path.parent)
        # File content should match returned XML
        assert path.read_text() == result["tailoring_xml"]

    def test_create_tailoring_roundtrip(self, bridge):
        """Create then parse back, verify modifications match."""
        create_result = bridge._build_tailoring_xml(_BASE_PROFILE, _FULL_MODIFICATIONS)

        # Now parse it back
        parse_result = bridge._parse_tailoring_file(create_result["path"])

        assert parse_result["base_profile"] == _BASE_PROFILE
        assert len(parse_result["modifications"]) == len(_FULL_MODIFICATIONS)

        # Check each modification came back correctly
        mods_by_id = {m["rule_id"]: m for m in parse_result["modifications"]}

        audit_mod = mods_by_id["xccdf_org.ssgproject.content_rule_package_audit_installed"]
        assert audit_mod["action"] == "enable"

        pw_mod = mods_by_id["xccdf_org.ssgproject.content_rule_no_empty_passwords"]
        assert pw_mod["action"] == "disable"

        val_mod = mods_by_id["xccdf_org.ssgproject.content_value_var_password_minlen"]
        assert val_mod["action"] == "set-value"
        assert val_mod["value"] == "12"


# ---------------------------------------------------------------------------
# parse-tailoring tests
# ---------------------------------------------------------------------------


class TestParseTailoring:
    """Tests for the _parse_tailoring_file helper function."""

    def test_parse_tailoring_extracts_selects(self, bridge, tmp_path):
        """Parse tailoring XML with select elements."""
        tailoring_path = tmp_path / "test-tailoring.xml"
        tailoring_path.write_text(SYNTHETIC_TAILORING_XML)

        result = bridge._parse_tailoring_file(str(tailoring_path))

        assert result["base_profile"] == _BASE_PROFILE
        mods = result["modifications"]

        # Find the select-based modifications
        select_mods = [m for m in mods if m["action"] in ("enable", "disable")]
        assert len(select_mods) == EXPECTED_SELECT_COUNT

        mods_by_id = {m["rule_id"]: m for m in mods}
        assert mods_by_id["xccdf_org.ssgproject.content_rule_package_audit_installed"]["action"] == "enable"
        assert mods_by_id["xccdf_org.ssgproject.content_rule_no_empty_passwords"]["action"] == "disable"

    def test_parse_tailoring_extracts_set_values(self, bridge, tmp_path):
        """Parse tailoring with set-value elements."""
        tailoring_path = tmp_path / "test-tailoring.xml"
        tailoring_path.write_text(SYNTHETIC_TAILORING_XML)

        result = bridge._parse_tailoring_file(str(tailoring_path))

        mods = result["modifications"]
        set_value_mods = [m for m in mods if m["action"] == "set-value"]
        assert len(set_value_mods) == 1

        sv = set_value_mods[0]
        assert sv["rule_id"] == "xccdf_org.ssgproject.content_value_var_password_minlen"
        assert sv["value"] == "12"
