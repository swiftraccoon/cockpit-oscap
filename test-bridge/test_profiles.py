"""Tests for list-profiles and profile-rules commands."""
from __future__ import annotations


def test_list_profiles_returns_list(run_bridge):
    result = run_bridge("list-profiles")
    assert isinstance(result, list)
    if result:
        profile = result[0]
        assert "id" in profile
        assert "title" in profile
        assert "description" in profile


def test_profile_rules_returns_rules(run_bridge):
    # First get a profile ID
    profiles = run_bridge("list-profiles")
    if not profiles or "error" in profiles:
        return  # Skip if no oscap/content available
    profile_id = profiles[0]["id"]

    result = run_bridge("profile-rules", profile_id)
    assert isinstance(result, list)
    if result:
        rule = result[0]
        assert "id" in rule
        assert "title" in rule
        assert "severity" in rule
        assert "selected" in rule
