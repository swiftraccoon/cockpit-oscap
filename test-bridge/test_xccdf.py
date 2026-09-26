"""XCCDF datastream parsing: profiles, rules, groups and values."""
# mypy: disallow-untyped-defs=false, disallow-untyped-decorators=false, disallow-untyped-calls=false

from __future__ import annotations

import xml.etree.ElementTree as ET

import pytest
from conftest import (
    PROFILE_BASE,
    PROFILE_EXTENDED,
    RULE_AUDIT,
    RULE_NEVER,
    RULE_ROOT_LOGIN,
    RULE_TIMEOUT,
    VALUE_TIMEOUT,
    VALUE_UNUSED,
)

BASE_RULE_COUNT = 3
EXTENDED_RULE_COUNT = 2
TOTAL_RULES = 4


def test_load_benchmark_stops_at_benchmark(bridge, datastream):
    benchmark = bridge.load_benchmark(datastream)
    assert benchmark.get("id") == "xccdf_org.test.content_benchmark_TEST"


def test_load_benchmark_errors(bridge, tmp_path):
    bad = tmp_path / "bad.xml"
    bad.write_text("<not-closed>")
    with pytest.raises(bridge.BridgeError, match="failed to parse"):
        bridge.load_benchmark(str(bad))
    no_benchmark = tmp_path / "empty.xml"
    no_benchmark.write_text("<root/>")
    with pytest.raises(bridge.BridgeError, match="no XCCDF benchmark"):
        bridge.load_benchmark(str(no_benchmark))
    with pytest.raises(bridge.BridgeError, match="cannot read"):
        bridge.load_benchmark(str(tmp_path / "missing.xml"))


def test_list_profiles_hides_abstract_and_counts_rules(bridge, datastream):
    profiles = bridge.list_profiles(datastream, {})
    by_id = {p["id"]: p for p in profiles}
    assert set(by_id) == {PROFILE_BASE, PROFILE_EXTENDED}
    assert by_id[PROFILE_BASE]["rule_count"] == BASE_RULE_COUNT  # audit + whole ssh group
    assert by_id[PROFILE_EXTENDED]["rule_count"] == EXTENDED_RULE_COUNT  # root login unselected
    assert by_id[PROFILE_EXTENDED]["extends"] == PROFILE_BASE
    assert by_id[PROFILE_BASE]["description"] == "First paragraph.\n\nSecond paragraph."
    assert by_id[PROFILE_BASE]["tailoring_path"] is None


def test_list_profiles_reports_tailoring(bridge, datastream):
    mods = [{"idref": RULE_AUDIT, "action": "unselect"}]
    profile_id, xml = bridge.build_tailoring_xml(PROFILE_BASE, "Base Profile", mods, datastream)
    path = bridge.TAILORING_DIR / "base.xml"
    bridge._atomic_write(path, xml)
    profiles = bridge.list_profiles(datastream, {"tailorings": {PROFILE_BASE: str(path),
                                                              PROFILE_EXTENDED: "/missing.xml"}})
    by_id = {p["id"]: p for p in profiles}
    assert by_id[PROFILE_BASE]["tailoring_path"] == str(path)
    assert by_id[PROFILE_BASE]["tailored_profile_id"] == profile_id
    assert by_id[PROFILE_EXTENDED]["tailoring_path"] is None


def test_profile_rules_selection_groups_and_values(bridge, datastream):
    data = bridge.profile_rules(datastream, PROFILE_BASE)
    assert data["title"] == "Base Profile"
    rules = {r["id"]: r for r in data["rules"]}
    assert len(rules) == TOTAL_RULES
    assert rules[RULE_AUDIT]["selected"] is True
    assert rules[RULE_ROOT_LOGIN]["selected"] is True
    assert rules[RULE_TIMEOUT]["selected"] is True
    assert rules[RULE_NEVER]["selected"] is False
    assert rules[RULE_AUDIT]["group"] == "Auditing"
    assert rules[RULE_AUDIT]["group_path"] == ["System Settings", "Auditing"]
    assert rules[RULE_AUDIT]["has_fix"] is True
    assert rules[RULE_ROOT_LOGIN]["has_fix"] is False
    assert rules[RULE_AUDIT]["description"] == "Install the audit package."
    assert rules[RULE_AUDIT]["severity"] == "medium"

    values = {v["id"]: v for v in data["values"]}
    assert set(values) == {VALUE_TIMEOUT}
    assert VALUE_UNUSED not in values
    timeout = values[VALUE_TIMEOUT]
    assert timeout["selector"] == "10_minutes"
    assert timeout["value"] == "600"
    assert timeout["default"] == "300"
    assert timeout["set_value"] is None
    assert timeout["options"] == [{"selector": "5_minutes", "value": "300"},
                                  {"selector": "10_minutes", "value": "600"}]
    assert timeout["type"] == "number"


def test_profile_rules_extends_and_set_value(bridge, datastream):
    data = bridge.profile_rules(datastream, PROFILE_EXTENDED)
    rules = {r["id"]: r for r in data["rules"]}
    assert rules[RULE_ROOT_LOGIN]["selected"] is False
    assert rules[RULE_TIMEOUT]["selected"] is True
    timeout = {v["id"]: v for v in data["values"]}[VALUE_TIMEOUT]
    assert timeout["set_value"] == "42"
    assert timeout["value"] == "42"
    assert timeout["selector"] == "10_minutes"


def test_profile_rules_unknown_profile(bridge, datastream):
    with pytest.raises(bridge.BridgeError, match="profile not found"):
        bridge.profile_rules(datastream, "xccdf_org.test.content_profile_nope")


def test_rule_detail(bridge, datastream):
    detail = bridge.rule_detail(datastream, RULE_AUDIT)
    assert detail["title"] == "Ensure audit is installed"
    assert detail["rationale"] == "Auditing matters."
    assert detail["warnings"] == ["Be careful."]
    assert detail["idents"] == [{"system": "https://ncp.nist.gov/cce", "text": "CCE-1"}]
    assert detail["references"] == [{"href": "https://example.com/ref", "text": "R1"}]
    assert detail["group_path"] == ["System Settings", "Auditing"]
    assert detail["fix_systems"] == ["urn:xccdf:fix:script:sh"]
    with pytest.raises(bridge.BridgeError, match="rule not found"):
        bridge.rule_detail(datastream, "xccdf_org.test.content_rule_nope")


def test_rich_text_preserves_paragraphs(bridge):
    el = ET.fromstring(  # noqa: S314
        '<d xmlns:html="http://www.w3.org/1999/xhtml">Intro <html:code>x</html:code> text.'
        "<html:p>Para   one</html:p><html:pre>  keep\n  this</html:pre>"
        "<html:ul><html:li>item</html:li></html:ul></d>")
    assert bridge._rich_text(el) == "Intro x text.\n\nPara one\n\nkeep\nthis\n\nitem"
    assert bridge._rich_text(None) == ""
    assert bridge._text(el) == "Intro x text. Para one keep this item"


def test_cli_list_profiles_and_rules(run_bridge, datastream):
    profiles = run_bridge("list-profiles")
    assert [p["id"] for p in profiles] == [PROFILE_BASE, PROFILE_EXTENDED]
    profiles = run_bridge("list-profiles", "--datastream", datastream)
    assert len(profiles) == 2
    rules = run_bridge("profile-rules", PROFILE_BASE)
    assert rules["profile_id"] == PROFILE_BASE
    assert "error" in run_bridge("profile-rules", expect_rc=1)
    info = run_bridge("rule-info", RULE_TIMEOUT)
    assert info["title"] == "Set SSH idle timeout"
    assert "error" in run_bridge("rule-info", expect_rc=1)


def test_list_profiles_ignores_tailoring_for_other_content(bridge, datastream):
    mods = [{"idref": RULE_AUDIT, "action": "unselect"}]
    _profile_id, xml = bridge.build_tailoring_xml(PROFILE_BASE, "Base Profile", mods,
                                                  "/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml")
    path = bridge.TAILORING_DIR / "rhel9.xml"
    bridge._atomic_write(path, xml)
    broken = bridge.TAILORING_DIR / "broken.xml"
    bridge._atomic_write(broken, "<nope/>")
    profiles = bridge.list_profiles(datastream, {"tailorings": {PROFILE_BASE: str(path),
                                                              PROFILE_EXTENDED: str(broken)}})
    by_id = {p["id"]: p for p in profiles}
    assert by_id[PROFILE_BASE]["tailoring_path"] is None
    assert by_id[PROFILE_BASE]["tailored_profile_id"] is None
    assert by_id[PROFILE_EXTENDED]["tailoring_path"] is None
