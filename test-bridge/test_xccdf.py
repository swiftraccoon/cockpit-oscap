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
    assert by_id[PROFILE_BASE]["rule_count"] == BASE_RULE_COUNT  # audit + the ssh group's rules
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


def test_selection_is_resolved_as_the_scanner_does(bridge, datastream):
    """Checked against oscap on a bare benchmark: a group switched on does not reach a rule that is
    off by itself, a rule switched on inside a group that is off stays skipped, the last select for
    an item wins, and a profile's ancestors apply first."""
    index = bridge._BenchmarkIndex(bridge.load_benchmark(datastream))
    sel = index.selection(PROFILE_BASE)
    assert (sel[RULE_AUDIT], sel[RULE_ROOT_LOGIN], sel[RULE_TIMEOUT], sel[RULE_NEVER]) == (True, True, True, False)
    extended = index.selection(PROFILE_EXTENDED)
    assert (extended[RULE_ROOT_LOGIN], extended[RULE_TIMEOUT]) == (False, True)

    def select(idref: str, on: bool) -> ET.Element:  # noqa: FBT001
        return ET.Element(bridge.TAG_SELECT, {"idref": idref, "selected": str(on).lower()})

    # switching the never-selected rule's group on does not reach it; switching the rule on does
    group_on = index.selection(PROFILE_BASE, [select("xccdf_org.test.content_group_auditing", True)])
    assert group_on[RULE_NEVER] is False
    assert index.selection(PROFILE_BASE, [select(RULE_NEVER, True)])[RULE_NEVER] is True
    # a rule switched on inside a group that is off stays skipped; the last select wins
    ssh_off = index.selection(PROFILE_BASE,
                              [select("xccdf_org.test.content_group_ssh", False), select(RULE_TIMEOUT, True)])
    assert (ssh_off[RULE_ROOT_LOGIN], ssh_off[RULE_TIMEOUT]) == (False, False)
    flip = index.selection(PROFILE_BASE, [select(RULE_AUDIT, False), select(RULE_AUDIT, True)])
    assert flip[RULE_AUDIT] is True
    # an unknown profile falls back to the content's own attributes
    assert index.selection("xccdf_org.test.content_profile_nope") == {
        RULE_AUDIT: False, RULE_NEVER: False, RULE_ROOT_LOGIN: False, RULE_TIMEOUT: False}


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
    assert rules[RULE_ROOT_LOGIN]["has_fix"] is False  # only an Ansible fix: nothing the plugin can apply
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


def test_list_profiles_reports_unusable_tailoring(bridge, datastream):
    mods = [{"idref": RULE_AUDIT, "action": "unselect"}]
    _profile_id, xml = bridge.build_tailoring_xml("xccdf_org.test.content_profile_missing", "Gone", mods,
                                                  "/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml")
    path = bridge.TAILORING_DIR / "gone.xml"
    bridge._atomic_write(path, xml)
    broken = bridge.TAILORING_DIR / "broken.xml"
    bridge._atomic_write(broken, "<nope/>")
    profiles = bridge.list_profiles(datastream, {"tailorings": {PROFILE_BASE: str(path),
                                                              PROFILE_EXTENDED: str(broken)}})
    by_id = {p["id"]: p for p in profiles}
    # the file is still reported (so it can be removed), but it is not applied
    assert by_id[PROFILE_BASE]["tailoring_path"] == str(path)
    assert by_id[PROFILE_BASE]["tailored_profile_id"] is None
    assert "not part of ssg-test-ds.xml" in by_id[PROFILE_BASE]["tailoring_problem"]
    assert by_id[PROFILE_EXTENDED]["tailoring_path"] == str(broken)
    assert by_id[PROFILE_EXTENDED]["tailored_profile_id"] is None
    assert "cannot be read" in by_id[PROFILE_EXTENDED]["tailoring_problem"]

    # a tailoring from another SSG product with the same profile ids applies as usual
    profile_id, xml = bridge.build_tailoring_xml(PROFILE_BASE, "Base Profile", mods,
                                                 "/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml")
    bridge._atomic_write(path, xml)
    by_id = {p["id"]: p for p in bridge.list_profiles(datastream, {"tailorings": {PROFILE_BASE: str(path)}})}
    assert by_id[PROFILE_BASE]["tailored_profile_id"] == profile_id
    assert by_id[PROFILE_BASE]["tailoring_problem"] == ""


def test_rule_detail_fix_systems(bridge, datastream):
    audit = bridge.rule_detail(datastream, RULE_AUDIT)
    assert audit["has_fix"] is True
    assert audit["fix_systems"] == ["urn:xccdf:fix:script:sh"]
    root_login = bridge.rule_detail(datastream, RULE_ROOT_LOGIN)
    assert root_login["has_fix"] is False
    assert root_login["fix_systems"] == ["urn:xccdf:fix:script:ansible"]
    assert bridge.rule_detail(datastream, RULE_TIMEOUT)["fix_systems"] == []


def test_rule_info_falls_back_when_recorded_content_is_gone(run_bridge):
    info = run_bridge("rule-info", RULE_AUDIT, "--datastream", "/gone/ssg-old-ds.xml")
    assert info["id"] == RULE_AUDIT
    assert info["has_fix"] is True
    assert info["content_substituted"] is True
    assert run_bridge("rule-info", RULE_AUDIT)["content_substituted"] is False
    # other commands keep insisting on the content they were given
    assert "error" in run_bridge("profile-rules", PROFILE_BASE, "--datastream", "/gone/ssg-old-ds.xml", expect_rc=1)
