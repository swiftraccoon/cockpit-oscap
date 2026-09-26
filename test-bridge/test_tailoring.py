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
