"""Backend and SCAP content detection."""
# mypy: disallow-untyped-defs=false, disallow-untyped-decorators=false, disallow-untyped-calls=false

from __future__ import annotations

import pytest

API_VERSION = 2


@pytest.mark.parametrize(("os_release", "expected"), [
    ({"ID": "fedora", "VERSION_ID": "42"}, ["fedora"]),
    ({"ID": "rhel", "VERSION_ID": "9.4"}, ["rhel9"]),
    ({"ID": "centos", "VERSION_ID": "9"}, ["cs9", "centos9", "rhel9"]),
    ({"ID": "almalinux", "VERSION_ID": "9.3", "ID_LIKE": "rhel centos fedora"},
     ["almalinux9", "rhel9", "cs9", "centos9", "fedora"]),
    ({"ID": "rocky", "VERSION_ID": "10.0"}, ["rl10", "rocky10", "rhel10"]),
    ({"ID": "ol", "VERSION_ID": "9.2"}, ["ol9"]),
    ({"ID": "debian", "VERSION_ID": "12"}, ["debian12"]),
    ({"ID": "ubuntu", "VERSION_ID": "24.04", "ID_LIKE": "debian"}, ["ubuntu2404"]),
    ({"ID": "opensuse-leap", "VERSION_ID": "15.6", "ID_LIKE": "suse opensuse"}, ["opensuse"]),
    ({"ID": "sles", "VERSION_ID": "15.5"}, ["sle15"]),
    ({"ID": "amzn", "VERSION_ID": "2023"}, ["al2023"]),
    ({"ID": "unknownos"}, []),
])
def test_candidate_products(bridge, os_release, expected):
    assert bridge._candidate_products(os_release) == expected


def test_detect_content_matches_os(bridge, content_dir, os_release):
    (content_dir / "ssg-fedora-ds.xml").write_text("<x/>")
    os_release.write_text("ID=fedora\nVERSION_ID=42\n")
    content = bridge.detect_content({})
    assert content["present"] is True
    assert content["source"] == "detected"
    assert content["datastream_path"].endswith("ssg-fedora-ds.xml")
    assert [d["product"] for d in content["available"]] == ["fedora", "test"]
    assert content["os"] == {"id": "fedora", "version_id": "42", "pretty_name": ""}


def test_detect_content_prefers_config_override(bridge, content_dir):
    (content_dir / "ssg-fedora-ds.xml").write_text("<x/>")
    content = bridge.detect_content({"datastream": str(content_dir / "ssg-fedora-ds.xml")})
    assert content["source"] == "config"
    assert content["datastream_path"].endswith("ssg-fedora-ds.xml")
    assert {d["name"] for d in content["available"]} == {p.name for p in content_dir.iterdir()}


def test_detect_content_ignores_missing_override(bridge):
    content = bridge.detect_content({"datastream": "/nonexistent/ssg-x-ds.xml"})
    assert content["source"] == "fallback"
    assert content["datastream_path"].endswith("ssg-test-ds.xml")


def test_detect_content_fallback_prefers_newest_product(bridge, content_dir):
    for name in ("ssg-debian10-ds.xml", "ssg-debian12-ds.xml", "ssg-debian9-ds.xml"):
        (content_dir / name).write_text("<x/>")
    (content_dir / "ssg-test-ds.xml").unlink()
    content = bridge.detect_content({})
    assert content["source"] == "fallback"
    assert content["datastream_path"].endswith("ssg-debian12-ds.xml")
    assert [d["product"] for d in content["available"]] == ["debian9", "debian10", "debian12"]


def test_detect_content_without_content(bridge, content_dir):
    (content_dir / "ssg-test-ds.xml").unlink()
    content = bridge.detect_content({})
    assert content == {"datastream_path": "", "present": False, "source": "none", "available": [],
                       "os": {"id": "test", "version_id": "1", "pretty_name": "Test OS 1"}}


def test_resolve_datastream_errors(bridge, content_dir):
    with pytest.raises(bridge.BridgeError, match="not found"):
        bridge.resolve_datastream("/nonexistent.xml")
    (content_dir / "ssg-test-ds.xml").unlink()
    with pytest.raises(bridge.BridgeError, match="scap-security-guide"):
        bridge.resolve_datastream(None, {})


def test_detect_backend_shape(run_bridge):
    data = run_bridge("detect-backend")
    assert data["api_version"] == API_VERSION
    assert set(data) == {"api_version", "oscap", "complyctl", "content", "privileged", "data_dir"}
    assert data["oscap"] is None or {"version", "path"} <= set(data["oscap"])
    assert data["content"]["present"] is True
    assert isinstance(data["privileged"], bool)


def test_detect_backend_without_oscap(bridge, monkeypatch, capsys):
    monkeypatch.setattr(bridge.shutil, "which", lambda _name: None)
    bridge.cmd_detect_backend([])
    out = capsys.readouterr().out
    assert '"oscap": null' in out
    assert '"complyctl": null' in out
