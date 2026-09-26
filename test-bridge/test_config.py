"""Configuration file handling."""
# mypy: disallow-untyped-defs=false, disallow-untyped-decorators=false, disallow-untyped-calls=false

from __future__ import annotations

import json

import pytest


def test_missing_config_is_empty(bridge):
    assert bridge.load_config() == {}


def test_invalid_config_is_ignored(bridge):
    bridge.CONFIG_PATH.write_text("not json")
    assert bridge.load_config() == {}


def test_legacy_tailoring_keys_are_migrated(bridge):
    bridge.CONFIG_PATH.write_text(json.dumps({
        "active_profile": "xccdf_org.test.content_profile_base",
        "tailoring_xccdf_org.test.content_profile_base": "/var/lib/cockpit-oscap/tailoring/base.xml",
        "junk": 12,
    }))
    config = bridge.load_config()
    assert config["active_profile"] == "xccdf_org.test.content_profile_base"
    assert config["tailorings"] == {
        "xccdf_org.test.content_profile_base": "/var/lib/cockpit-oscap/tailoring/base.xml"}
    assert "junk" not in config


def test_set_config_round_trip(run_bridge, bridge):
    data = run_bridge("set-config", json.dumps({"active_profile": "xccdf_org.test.content_profile_base",
                                                 "max_results": 12}))
    assert data == {"active_profile": "xccdf_org.test.content_profile_base", "max_results": 12}
    assert run_bridge("get-config") == data
    # null deletes a key
    data = run_bridge("set-config", json.dumps({"max_results": None}))
    assert data == {"active_profile": "xccdf_org.test.content_profile_base"}
    assert json.loads(bridge.CONFIG_PATH.read_text()) == data


@pytest.mark.parametrize("patch", [
    {"max_results": "many"},
    {"max_results": 0},
    {"max_results": True},
    {"active_profile": "bad id with spaces"},
    {"datastream": 5},
    {"tailorings": {}},
    {"unknown": 1},
])
def test_set_config_rejects_bad_values(run_bridge, patch):
    data = run_bridge("set-config", json.dumps(patch), expect_rc=1)
    assert "error" in data


def test_set_config_requires_object(run_bridge):
    assert "error" in run_bridge("set-config", "[]", expect_rc=1)
    assert "error" in run_bridge("set-config", "{bad", expect_rc=1)
    assert "error" in run_bridge("set-config", expect_rc=1)
