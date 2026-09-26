"""Tailoring creation, parsing, import and deletion."""
# mypy: disallow-untyped-defs=false, disallow-untyped-decorators=false, disallow-untyped-calls=false

from __future__ import annotations

import json
import xml.etree.ElementTree as ET

import pytest
from conftest import PROFILE_BASE, RULE_AUDIT, RULE_ROOT_LOGIN, VALUE_TIMEOUT

NS = "http://checklists.nist.gov/xccdf/1.2"
MODIFICATIONS = [
    {"idref": RULE_AUDIT, "action": "unselect"},
    {"idref": RULE_ROOT_LOGIN, "action": "select"},
    {"idref": VALUE_TIMEOUT, "action": "refine-value", "selector": "5_minutes"},
    {"idref": VALUE_TIMEOUT, "action": "set-value", "value": "12"},
]


def test_build_tailoring_xml_is_valid_xccdf(bridge, datastream):
    profile_id, xml = bridge.build_tailoring_xml(PROFILE_BASE, "Base Profile", MODIFICATIONS, datastream)
    assert profile_id == f"{PROFILE_BASE}_customized"
    root = ET.fromstring(xml)  # noqa: S314
    assert root.tag == f"{{{NS}}}Tailoring"
    assert root.get("id") == "xccdf_org.cockpit-project.oscap_tailoring_default"
    children = [c.tag.split("}")[1] for c in root]
    assert children == ["benchmark", "version", "Profile"]
    benchmark = root.find(f"{{{NS}}}benchmark")
    version = root.find(f"{{{NS}}}version")
    profile = root.find(f"{{{NS}}}Profile")
    assert benchmark is not None
    assert version is not None
    assert profile is not None
    assert benchmark.get("href") == datastream
    assert version.get("time")
    assert profile.get("extends") == PROFILE_BASE
    title = profile.find(f"{{{NS}}}title")
    refine = profile.find(f"{{{NS}}}refine-value")
    set_value = profile.find(f"{{{NS}}}set-value")
    assert title is not None
    assert refine is not None
    assert set_value is not None
    assert title.text == "Base Profile (customized)"
    selects = {s.get("idref"): s.get("selected") for s in profile.findall(f"{{{NS}}}select")}
    assert selects == {RULE_AUDIT: "false", RULE_ROOT_LOGIN: "true"}
    assert refine.get("selector") == "5_minutes"
    assert set_value.text == "12"


def test_remarks_travel_with_selects(bridge, datastream, run_bridge):
    mods = [
        {"idref": RULE_AUDIT, "action": "unselect", "remark": "  Audit is\n handled by the SIEM agent  "},
        {"idref": RULE_ROOT_LOGIN, "action": "select"},
        {"idref": VALUE_TIMEOUT, "action": "set-value", "value": "12", "remark": "not a select: dropped"},
    ]
    validated = bridge._validate_modifications(mods)
    _profile_id, xml = bridge.build_tailoring_xml(PROFILE_BASE, "Base", validated, datastream)
    root = ET.fromstring(xml)  # noqa: S314
    remarks = {s.get("idref"): [r.text for r in s.findall(f"{{{NS}}}remark")] for s in root.iter(f"{{{NS}}}select")}
    assert remarks == {RULE_AUDIT: ["Audit is handled by the SIEM agent"], RULE_ROOT_LOGIN: []}
    assert root.find(f".//{{{NS}}}set-value/{{{NS}}}remark") is None
    parsed = bridge.parse_tailoring_xml(xml)["modifications"]
    assert parsed[0] == {"idref": RULE_AUDIT, "action": "unselect", "remark": "Audit is handled by the SIEM agent"}
    assert "remark" not in parsed[1]
    assert "remark" not in parsed[2]
    # several remarks on one select (other tools) are kept together; validation rejects the unusable
    xml = xml.replace("</xccdf:remark>", "</xccdf:remark><xccdf:remark>ticket 42</xccdf:remark>")
    joined = bridge.parse_tailoring_xml(xml)["modifications"][0]["remark"]
    assert joined == "Audit is handled by the SIEM agent ticket 42"
    with pytest.raises(bridge.BridgeError, match="string"):
        bridge._validate_modifications([{"idref": RULE_AUDIT, "action": "unselect", "remark": 1}])
    with pytest.raises(bridge.BridgeError, match="at most"):
        bridge._validate_modifications([{"idref": RULE_AUDIT, "action": "unselect", "remark": "x" * 4001}])
    assert bridge._validate_modifications([{"idref": RULE_AUDIT, "action": "unselect", "remark": "  "}]) == [
        {"idref": RULE_AUDIT, "action": "unselect"}]
    info = run_bridge("create-tailoring", PROFILE_BASE, json.dumps(mods[:1]))
    assert info["modifications"][0]["remark"] == "Audit is handled by the SIEM agent"


def test_selected_accepts_every_xml_boolean(bridge, datastream):
    _profile_id, xml = bridge.build_tailoring_xml(PROFILE_BASE, "Base", bridge._validate_modifications([
        {"idref": RULE_AUDIT, "action": "unselect"}, {"idref": RULE_ROOT_LOGIN, "action": "select"}]), datastream)
    # another tool's file: xs:boolean allows 1 and 0 as well
    xml = xml.replace('selected="false"', 'selected="0"').replace('selected="true"', 'selected="1"')
    actions = {m["idref"]: m["action"] for m in bridge.parse_tailoring_xml(xml)["modifications"]}
    assert actions == {RULE_AUDIT: "unselect", RULE_ROOT_LOGIN: "select"}
    assert bridge._xml_true(None) is True
    assert bridge._xml_true(" true ") is True
    assert bridge._xml_true("FALSE") is False


def test_text_destined_for_xml_is_checked_before_anything_is_written(bridge, run_bridge):
    for bad in ("handled\x08elsewhere", "a\x00b", "\x1f", "lone \ud800 surrogate"):
        with pytest.raises(bridge.BridgeError, match="control characters"):
            bridge._validate_modifications([{"idref": RULE_AUDIT, "action": "unselect", "remark": bad}])
        with pytest.raises(bridge.BridgeError, match="control characters"):
            bridge._validate_modifications([{"idref": VALUE_TIMEOUT, "action": "set-value", "value": bad}])
    # tabs and newlines are fine in a remark (collapsed) and in a value (kept)
    mods = bridge._validate_modifications([
        {"idref": RULE_AUDIT, "action": "unselect", "remark": "line\none\ttwo"},
        {"idref": VALUE_TIMEOUT, "action": "set-value", "value": "1\n2"}])
    assert mods[0]["remark"] == "line one two"
    assert mods[1]["value"] == "1\n2"
    with pytest.raises(bridge.BridgeError, match="at most"):
        bridge._validate_modifications([{"idref": VALUE_TIMEOUT, "action": "set-value", "value": "x" * 4001}])
    # a rejected document leaves no file and no registration behind
    bad_json = json.dumps([{"idref": RULE_AUDIT, "action": "unselect", "remark": "a\x08b"}])
    assert "control characters" in run_bridge("create-tailoring", PROFILE_BASE, bad_json, expect_rc=1)["error"]
    assert not bridge.TAILORING_DIR.exists() or not list(bridge.TAILORING_DIR.iterdir())
    assert "tailorings" not in run_bridge("get-config")


def test_tailor_rule_edits_one_rule_of_the_customization(run_bridge, bridge):
    # no customization yet: one is created around the change
    info = run_bridge("tailor-rule", PROFILE_BASE, RULE_ROOT_LOGIN, "disable", "--remark", "  accepted\nrisk ")
    assert info["modifications"] == [{"idref": RULE_ROOT_LOGIN, "action": "unselect", "remark": "accepted risk"}]
    assert run_bridge("get-config")["tailorings"] == {PROFILE_BASE: info["path"]}
    # other customizations stay, the same rule is replaced rather than repeated
    run_bridge("create-tailoring", PROFILE_BASE, json.dumps(MODIFICATIONS))
    info = run_bridge("tailor-rule", PROFILE_BASE, RULE_ROOT_LOGIN, "disable", "--remark", "ticket 42")
    assert info["modifications"] == [  # selects first: the parsed order, not the insertion order
        {"idref": RULE_AUDIT, "action": "unselect"},
        {"idref": RULE_ROOT_LOGIN, "action": "unselect", "remark": "ticket 42"},
        {"idref": VALUE_TIMEOUT, "action": "refine-value", "selector": "5_minutes"},
        {"idref": VALUE_TIMEOUT, "action": "set-value", "value": "12"},
    ]
    info = run_bridge("tailor-rule", PROFILE_BASE, RULE_ROOT_LOGIN, "enable")
    assert info["modifications"][1] == {"idref": RULE_ROOT_LOGIN, "action": "select"}
    assert len(info["modifications"]) == len(MODIFICATIONS)
    # arguments are checked
    assert "error" in run_bridge("tailor-rule", PROFILE_BASE, RULE_ROOT_LOGIN, expect_rc=1)
    dropped = run_bridge("tailor-rule", PROFILE_BASE, RULE_ROOT_LOGIN, "drop", expect_rc=1)
    assert "enable or disable" in dropped["error"]
    missing = run_bridge("tailor-rule", PROFILE_BASE, "xccdf_org.test.content_rule_nope", "disable", expect_rc=1)
    assert "rule not found" in missing["error"]
    no_profile = run_bridge("tailor-rule", "xccdf_org.test.content_profile_nope", RULE_ROOT_LOGIN, "disable",
                            expect_rc=1)
    assert "profile not found" in no_profile["error"]
    assert "invalid rule id" in run_bridge("tailor-rule", PROFILE_BASE, "bad id", "disable", expect_rc=1)["error"]
    # a justification that looks like an option is still just text
    info = run_bridge("tailor-rule", PROFILE_BASE, RULE_ROOT_LOGIN, "disable", "--remark", "--datastream")
    assert info["modifications"][1] == {"idref": RULE_ROOT_LOGIN, "action": "unselect", "remark": "--datastream"}
    # a customization that cannot be applied is not silently replaced
    bridge.Path(info["path"]).write_text("<nope/>")
    broken = run_bridge("tailor-rule", PROFILE_BASE, RULE_ROOT_LOGIN, "disable", expect_rc=1)
    assert "cannot be changed" in broken["error"]


def test_tailor_rule_keeps_what_the_editor_does_not_model(run_bridge, bridge, datastream):
    # a file from another tool: its own ids, a severity override and a second profile
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<xccdf:Tailoring xmlns:xccdf="{NS}" id="xccdf_org.example_tailoring_site">
  <xccdf:benchmark href="{datastream}"/>
  <xccdf:version time="2020-01-01T00:00:00">3</xccdf:version>
  <xccdf:Profile id="xccdf_org.example_profile_site" extends="{PROFILE_BASE}">
    <xccdf:title>Site profile</xccdf:title>
    <xccdf:select idref="{RULE_ROOT_LOGIN}" selected="false"><xccdf:remark>old reason</xccdf:remark></xccdf:select>
    <xccdf:refine-rule idref="{RULE_AUDIT}" severity="high"/>
  </xccdf:Profile>
  <xccdf:Profile id="xccdf_org.example_profile_other" extends="{PROFILE_BASE}">
    <xccdf:title>Other</xccdf:title>
  </xccdf:Profile>
</xccdf:Tailoring>
"""
    run_bridge("import-tailoring", PROFILE_BASE, "-", stdin=xml)
    info = run_bridge("tailor-rule", PROFILE_BASE, RULE_ROOT_LOGIN, "disable", "--remark", "new reason")
    root = ET.fromstring(bridge.Path(info["path"]).read_text())  # noqa: S314
    assert root.get("id") == "xccdf_org.example_tailoring_site"
    profiles = root.findall(f"{{{NS}}}Profile")
    assert [p.get("id") for p in profiles] == ["xccdf_org.example_profile_site", "xccdf_org.example_profile_other"]
    assert profiles[0].find(f"{{{NS}}}refine-rule") is not None
    selects = profiles[0].findall(f"{{{NS}}}select")
    assert [(s.get("idref"), s.get("selected"), [r.text for r in s]) for s in selects] == [
        (RULE_ROOT_LOGIN, "false", ["new reason"])]
    version = root.find(f"{{{NS}}}version")
    assert version is not None
    assert version.text == "3"
    assert version.get("time") != "2020-01-01T00:00:00"
    assert info["profile_id"] == "xccdf_org.example_profile_site"
    assert info["modifications"] == [{"idref": RULE_ROOT_LOGIN, "action": "unselect", "remark": "new reason"}]
    info = run_bridge("tailor-rule", PROFILE_BASE, RULE_AUDIT, "disable")
    assert [m["idref"] for m in info["modifications"]] == [RULE_ROOT_LOGIN, RULE_AUDIT]


def test_tailor_rule_places_the_select_where_the_schema_allows(run_bridge, bridge, datastream):
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<xccdf:Tailoring xmlns:xccdf="{NS}" id="t">
  <xccdf:benchmark href="{datastream}"/>
  <xccdf:version time="2020-01-01T00:00:00">1</xccdf:version>
  <xccdf:Profile id="p" extends="{PROFILE_BASE}">
    <xccdf:title>With metadata</xccdf:title>
    <xccdf:set-value idref="{VALUE_TIMEOUT}">12</xccdf:set-value>
    <xccdf:metadata><note>kept last</note></xccdf:metadata>
  </xccdf:Profile>
</xccdf:Tailoring>
"""
    run_bridge("import-tailoring", PROFILE_BASE, "-", stdin=xml)
    info = run_bridge("tailor-rule", PROFILE_BASE, RULE_AUDIT, "disable")
    profile = ET.fromstring(bridge.Path(info["path"]).read_text()).find(f"{{{NS}}}Profile")  # noqa: S314
    assert profile is not None
    assert [c.tag.split("}")[1] for c in profile] == ["title", "set-value", "select", "metadata"]
    # with nothing to follow, the select goes before the metadata
    xml = xml.replace(f'<xccdf:set-value idref="{VALUE_TIMEOUT}">12</xccdf:set-value>', "")
    run_bridge("import-tailoring", PROFILE_BASE, "-", stdin=xml)
    info = run_bridge("tailor-rule", PROFILE_BASE, RULE_AUDIT, "disable")
    profile = ET.fromstring(bridge.Path(info["path"]).read_text()).find(f"{{{NS}}}Profile")  # noqa: S314
    assert profile is not None
    assert [c.tag.split("}")[1] for c in profile] == ["title", "select", "metadata"]
    # nothing to go before: the select comes last; a signature stays last
    plain = xml.replace("<xccdf:metadata><note>kept last</note></xccdf:metadata>", "")
    run_bridge("import-tailoring", PROFILE_BASE, "-", stdin=plain)
    info = run_bridge("tailor-rule", PROFILE_BASE, RULE_AUDIT, "disable")
    profile = ET.fromstring(bridge.Path(info["path"]).read_text()).find(f"{{{NS}}}Profile")  # noqa: S314
    assert profile is not None
    assert [c.tag.split("}")[1] for c in profile] == ["title", "select"]
    signed = xml.replace("<xccdf:metadata><note>kept last</note></xccdf:metadata>",
                         '<dsig:Signature xmlns:dsig="http://www.w3.org/2000/09/xmldsig#"/>')
    run_bridge("import-tailoring", PROFILE_BASE, "-", stdin=signed)
    info = run_bridge("tailor-rule", PROFILE_BASE, RULE_AUDIT, "disable")
    profile = ET.fromstring(bridge.Path(info["path"]).read_text()).find(f"{{{NS}}}Profile")  # noqa: S314
    assert profile is not None
    assert [c.tag.split("}")[1] for c in profile] == ["title", "select", "Signature"]


def test_parse_round_trip(bridge, datastream):
    _profile_id, xml = bridge.build_tailoring_xml(PROFILE_BASE, "Base Profile", MODIFICATIONS, datastream)
    info = bridge.parse_tailoring_xml(xml)
    assert info["base_profile_id"] == PROFILE_BASE
    assert info["profile_id"] == f"{PROFILE_BASE}_customized"
    assert info["benchmark_href"] == datastream
    assert info["title"] == "Base Profile (customized)"
    assert info["modifications"] == MODIFICATIONS


def test_parse_tailoring_errors(bridge):
    with pytest.raises(bridge.BridgeError, match="invalid tailoring XML"):
        bridge.parse_tailoring_xml("<broken")
    with pytest.raises(bridge.BridgeError, match="not an XCCDF"):
        bridge.parse_tailoring_xml("<root/>")
    with pytest.raises(bridge.BridgeError, match="Profile"):
        bridge.parse_tailoring_xml(f'<xccdf:Tailoring xmlns:xccdf="{NS}" id="x"/>')
    with pytest.raises(bridge.BridgeError, match="cannot read"):
        bridge.parse_tailoring_file("/nonexistent/tailoring.xml")


@pytest.mark.parametrize("bad", [
    "{}",
    '[{"idref": "x y", "action": "select"}]',
    f'[{{"idref": "{RULE_AUDIT}", "action": "enable"}}]',
    f'[{{"idref": "{VALUE_TIMEOUT}", "action": "refine-value"}}]',
    f'[{{"idref": "{VALUE_TIMEOUT}", "action": "set-value", "value": 3}}]',
    "[1]",
])
def test_create_tailoring_validation(run_bridge, bad):
    assert "error" in run_bridge("create-tailoring", PROFILE_BASE, bad, expect_rc=1)


def test_create_tailoring_cli_writes_file_and_config(run_bridge, bridge):
    info = run_bridge("create-tailoring", PROFILE_BASE, json.dumps(MODIFICATIONS))
    path = bridge.Path(info["path"])
    assert path == bridge.TAILORING_DIR / "base-tailoring.xml"
    assert path.read_text() == info["tailoring_xml"]
    assert info["profile_id"] == f"{PROFILE_BASE}_customized"
    assert info["modifications"] == MODIFICATIONS
    assert run_bridge("get-config")["tailorings"] == {PROFILE_BASE: str(path)}
    # legacy rule_id key is still accepted
    info = run_bridge("create-tailoring", PROFILE_BASE, json.dumps([{"rule_id": RULE_AUDIT, "action": "select"}]))
    assert info["modifications"] == [{"idref": RULE_AUDIT, "action": "select"}]
    assert "error" in run_bridge("create-tailoring", "xccdf_org.test.content_profile_nope", "[]", expect_rc=1)


def test_parse_tailoring_cli_from_stdin_and_file(run_bridge, bridge, datastream):
    _profile_id, xml = bridge.build_tailoring_xml(PROFILE_BASE, "Base Profile", MODIFICATIONS, datastream)
    info = run_bridge("parse-tailoring", "-", stdin=xml)
    assert info["modifications"] == MODIFICATIONS
    assert info["path"] == ""
    path = bridge.TAILORING_DIR / "x.xml"
    bridge._atomic_write(path, xml)
    assert run_bridge("parse-tailoring", str(path))["path"] == str(path)
    assert "error" in run_bridge("parse-tailoring", expect_rc=1)


def test_import_tailoring_warns_on_mismatch(run_bridge, bridge, datastream):
    _profile_id, xml = bridge.build_tailoring_xml(PROFILE_BASE, "Base Profile", MODIFICATIONS, datastream)
    other = "xccdf_org.test.content_profile_extended"
    info = run_bridge("import-tailoring", other, "-", stdin=xml)
    assert other in info["warning"]
    assert bridge.Path(info["path"]).read_text() == xml
    assert run_bridge("get-config")["tailorings"] == {other: info["path"]}
    info = run_bridge("import-tailoring", PROFILE_BASE, "-", stdin=xml)
    assert info["warning"] == ""
    assert "error" in run_bridge("import-tailoring", PROFILE_BASE, "-", stdin="<nope/>", expect_rc=1)


def test_delete_tailoring(run_bridge, bridge):
    info = run_bridge("create-tailoring", PROFILE_BASE, json.dumps(MODIFICATIONS))
    assert run_bridge("delete-tailoring", PROFILE_BASE) == {"deleted": True, "profile_id": PROFILE_BASE}
    assert not bridge.Path(info["path"]).exists()
    assert "tailorings" not in run_bridge("get-config")
    assert run_bridge("delete-tailoring", PROFILE_BASE) == {"deleted": False, "profile_id": PROFILE_BASE}
    assert "error" in run_bridge("delete-tailoring", expect_rc=1)


@pytest.mark.parametrize(("name", "stem"), [
    ("ssg-rhel9-ds.xml", "ssg-rhel9"),
    ("/usr/share/xml/scap/ssg/content/ssg-rhel9-ds-1.2.xml", "ssg-rhel9"),
    ("ssg-rhel9-xccdf.xml", "ssg-rhel9"),
    ("ssg-rhel9-xccdf-1.2.xml", "ssg-rhel9"),
    ("file:///content/ssg-debian12-ds.xml", "ssg-debian12"),
    ("custom-benchmark.xml", "custom-benchmark"),
])
def test_content_stem(bridge, name, stem):
    assert bridge._content_stem(name) == stem


def test_tailoring_applicability(bridge, datastream):
    benchmark = bridge.load_benchmark(datastream)
    _profile_id, xml = bridge.build_tailoring_xml(PROFILE_BASE, "Base Profile", MODIFICATIONS, datastream)
    info = bridge.parse_tailoring_xml(xml)
    assert bridge._tailoring_problem(info, benchmark, datastream) == ""
    assert bridge._href_mismatch(info, datastream) == ""
    assert bridge._href_mismatch(info, "/elsewhere/ssg-test-ds-1.2.xml") == ""
    note = bridge._href_mismatch(info, "/elsewhere/ssg-other-ds.xml")
    assert "ssg-test-ds.xml" in note
    assert "ssg-other-ds.xml" in note
    # hrefs that are not content file names (fragments, empty) are not judged
    info["benchmark_href"] = "#xccdf_org.test.content_benchmark_TEST"
    assert bridge._href_mismatch(info, "/elsewhere/ssg-other-ds.xml") == ""
    info["benchmark_href"] = ""
    assert bridge._href_mismatch(info, "/elsewhere/ssg-other-ds.xml") == ""
    # only a base profile oscap cannot find makes a tailoring unusable
    info["base_profile_id"] = "xccdf_org.test.content_profile_missing"
    assert "not part of ssg-test-ds.xml" in bridge._tailoring_problem(info, benchmark, datastream)
    info["base_profile_id"] = ""
    assert bridge._tailoring_problem(info, benchmark, datastream) == ""


def test_import_tailoring_notes_other_content(run_bridge, bridge):
    # a tailoring written on another SSG product (same rule ids) imports with a note
    _profile_id, xml = bridge.build_tailoring_xml(PROFILE_BASE, "Base Profile", MODIFICATIONS,
                                                  "/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml")
    info = run_bridge("import-tailoring", PROFILE_BASE, "-", stdin=xml)
    assert "ssg-rhel9-ds.xml" in info["warning"]
    assert "ssg-test-ds.xml" in info["warning"]
    assert run_bridge("get-config")["tailorings"] == {PROFILE_BASE: info["path"]}
    # another copy of the same datastream is not worth a note
    _profile_id, xml = bridge.build_tailoring_xml(PROFILE_BASE, "Base Profile", MODIFICATIONS,
                                                  "/backup/ssg-test-ds-1.2.xml")
    assert run_bridge("import-tailoring", PROFILE_BASE, "-", stdin=xml)["warning"] == ""
    # one customizing a profile this content does not have is refused
    _profile_id, xml = bridge.build_tailoring_xml("xccdf_org.test.content_profile_missing", "Gone", MODIFICATIONS,
                                                  "/backup/ssg-test-ds.xml")
    reply = run_bridge("import-tailoring", PROFILE_BASE, "-", stdin=xml, expect_rc=1)
    assert "not part of ssg-test-ds.xml" in reply["error"]
    assert "error" in run_bridge("import-tailoring", "xccdf_org.test.content_profile_nope", "-", stdin=xml,
                                 expect_rc=1)


def test_tailoring_document_uses_xccdf_tailoring_element(bridge, datastream):
    _profile_id, xml = bridge.build_tailoring_xml(PROFILE_BASE, "Base Profile", MODIFICATIONS, datastream)
    assert ET.fromstring(xml).tag == bridge.TAG_TAILORING  # noqa: S314
