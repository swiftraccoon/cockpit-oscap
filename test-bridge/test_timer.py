"""Scheduled scan timer management."""
# mypy: disallow-untyped-defs=false, disallow-untyped-decorators=false, disallow-untyped-calls=false

from __future__ import annotations

import json

import pytest

TIMER_UNIT = "cockpit-oscap-scan.timer"
SERVICE_UNIT = "cockpit-oscap-scan.service"

TIMER_ACTIVE = (
    "LoadState=loaded\nActiveState=active\nUnitFileState=enabled\n"
    "NextElapseUSecRealtime=Thu 2026-03-26 00:00:00 UTC\nLastTriggerUSec=Thu 2026-03-19 00:00:00 UTC\n"
    "TimersCalendar={ OnCalendar=weekly ; next_elapse=Thu 2026-03-26 00:00:00 UTC }\n"
)
TIMER_INACTIVE = ("LoadState=loaded\nActiveState=inactive\nUnitFileState=disabled\n"
                  "NextElapseUSecRealtime=n/a\nLastTriggerUSec=\n")
TIMER_MISSING = ("LoadState=not-found\nActiveState=inactive\nUnitFileState=\n"
                 "NextElapseUSecRealtime=\nLastTriggerUSec=\n")
SERVICE_IDLE = "ActiveState=inactive\nResult=success\nExecMainExitTimestamp=Thu 2026-03-19 00:05:12 UTC\n"


def _fake_systemctl(responses):
    """Return a run_cmd stand-in answering `systemctl show <unit>` from a dict and recording other calls."""
    calls = []

    def run_cmd(argv, **_kwargs):
        calls.append(argv)
        if argv[:2] == ["systemctl", "show"]:
            return 0, responses.get(argv[2], ""), ""
        if argv[0] == "systemctl":
            return responses.get(" ".join(argv[1:]), (0, "", ""))
        return 0, "", ""

    return run_cmd, calls


def test_status_active(bridge, monkeypatch, capsys):
    run_cmd, _calls = _fake_systemctl({TIMER_UNIT: TIMER_ACTIVE, SERVICE_UNIT: SERVICE_IDLE})
    monkeypatch.setattr(bridge, "run_cmd", run_cmd)
    bridge.cmd_manage_timer(["status"])
    data = json.loads(capsys.readouterr().out)
    assert data["status"] == "active"
    assert data["enabled"] is True
    assert data["installed"] is True
    assert data["next_run"] == "2026-03-26T00:00:00+00:00"
    assert data["last_run"] == "2026-03-19T00:00:00+00:00"
    assert data["calendar"] == "weekly"
    assert data["service_state"] == "inactive"
    assert data["service_result"] == "success"
    assert data["last_scan_finished"] == "2026-03-19T00:05:12+00:00"


def test_status_inactive_and_missing(bridge, monkeypatch):
    run_cmd, _calls = _fake_systemctl({TIMER_UNIT: TIMER_INACTIVE, SERVICE_UNIT: SERVICE_IDLE})
    monkeypatch.setattr(bridge, "run_cmd", run_cmd)
    status = bridge.get_timer_status()
    assert status["status"] == "inactive"
    assert status["enabled"] is False
    assert status["next_run"] == ""

    run_cmd, _calls = _fake_systemctl({TIMER_UNIT: TIMER_MISSING, SERVICE_UNIT: ""})
    monkeypatch.setattr(bridge, "run_cmd", run_cmd)
    status = bridge.get_timer_status()
    assert status["status"] == "not-found"
    assert status["installed"] is False
    assert status["calendar"] == ""


def test_status_reads_calendar_override(bridge, monkeypatch, tmp_path):
    override_dir = tmp_path / "timer.d"
    override_dir.mkdir()
    (override_dir / "override.conf").write_text("[Timer]\nOnCalendar=\nOnCalendar=Mon *-*-* 02:30:00\n")
    monkeypatch.setattr(bridge, "TIMER_OVERRIDE_DIR", override_dir)
    run_cmd, _calls = _fake_systemctl({TIMER_UNIT: TIMER_ACTIVE, SERVICE_UNIT: SERVICE_IDLE})
    monkeypatch.setattr(bridge, "run_cmd", run_cmd)
    assert bridge.get_timer_status()["calendar"] == "Mon *-*-* 02:30:00"


@pytest.mark.parametrize(("value", "expected"), [
    ("Thu 2026-03-26 00:00:00 UTC", "2026-03-26T00:00:00+00:00"),
    ("2026-03-26 00:00:00 UTC", "2026-03-26T00:00:00+00:00"),
    ("n/a", ""),
    ("", ""),
    ("0", ""),
    ("garbage", "garbage"),
])
def test_parse_systemd_time(bridge, value, expected):
    assert bridge._parse_systemd_time(value) == expected


def test_parse_systemd_local_time_is_aware(bridge):
    iso = bridge._parse_systemd_time("Thu 2026-03-26 01:02:03 CET")
    assert iso.startswith("2026-03-26T01:02:03")
    assert iso[-6] in "+-"


@pytest.mark.parametrize(("config", "expected"), [
    ({"frequency": "daily", "time": "03:00"}, "*-*-* 03:00:00"),
    ({"frequency": "daily", "time": "3:5"}, "*-*-* 03:05:00"),
    ({"frequency": "daily"}, "*-*-* 03:00:00"),
    ({"frequency": "weekly", "day": "Mon", "time": "02:30"}, "Mon *-*-* 02:30:00"),
    ({"frequency": "weekly", "day": "friday", "time": "22:15"}, "Fri *-*-* 22:15:00"),
    ({"frequency": "weekly"}, "Mon *-*-* 03:00:00"),
    ({"frequency": "monthly", "day": "1", "time": "03:00"}, "*-*-01 03:00:00"),
    ({"frequency": "monthly", "day": 15, "time": "04:00"}, "*-*-15 04:00:00"),
    ({"frequency": "monthly"}, "*-*-01 03:00:00"),
])
def test_build_on_calendar(bridge, config, expected):
    assert bridge.build_on_calendar(config) == expected


@pytest.mark.parametrize("config", [
    {"frequency": "hourly"},
    {"frequency": "daily", "time": "25:00"},
    {"frequency": "daily", "time": "noon"},
    {"frequency": "weekly", "day": "Someday"},
    {"frequency": "monthly", "day": "31"},
    {"frequency": "monthly", "day": "first"},
    {"frequency": "custom"},
])
def test_build_on_calendar_rejects(bridge, config, monkeypatch):
    monkeypatch.setattr(bridge.shutil, "which", lambda _name: None)
    with pytest.raises(bridge.BridgeError):
        bridge.build_on_calendar(config)


def test_custom_calendar_uses_systemd_analyze(bridge, monkeypatch):
    def run_cmd(argv, **_kwargs):
        if argv[-1] == "*-*-1..7 04:00:00":
            return 0, ("  Original form: *-*-1..7 04:00:00\nNormalized form: *-*-01..07 04:00:00\n"
                       "    Next elapse: Thu 2026-10-01 04:00:00 UTC\n"), ""
        return 1, "", "Failed to parse calendar specification 'bogus': Invalid argument"

    monkeypatch.setattr(bridge.shutil, "which", lambda _name: "/usr/bin/systemd-analyze")
    monkeypatch.setattr(bridge, "run_cmd", run_cmd)
    assert bridge.build_on_calendar({"frequency": "custom", "calendar": "*-*-1..7 04:00:00"}) == "*-*-01..07 04:00:00"
    check = bridge.validate_calendar("*-*-1..7 04:00:00")
    assert check == {"valid": True, "normalized": "*-*-01..07 04:00:00", "next_elapse": "2026-10-01T04:00:00+00:00",
                     "error": ""}
    check = bridge.validate_calendar("bogus")
    assert check["valid"] is False
    assert "Invalid argument" in check["error"]
    with pytest.raises(bridge.BridgeError, match="Invalid argument"):
        bridge.build_on_calendar({"frequency": "custom", "calendar": "bogus"})
    assert bridge.validate_calendar("")["valid"] is False


def test_validate_calendar_without_systemd_analyze(bridge, monkeypatch):
    monkeypatch.setattr(bridge.shutil, "which", lambda _name: None)
    assert bridge.validate_calendar(" weekly ")["normalized"] == "weekly"


def test_configure_writes_override_and_profile(bridge, monkeypatch, tmp_path, capsys):
    override_dir = tmp_path / "timer.d"
    monkeypatch.setattr(bridge, "TIMER_OVERRIDE_DIR", override_dir)
    run_cmd, calls = _fake_systemctl({TIMER_UNIT: TIMER_ACTIVE, SERVICE_UNIT: SERVICE_IDLE})
    monkeypatch.setattr(bridge, "run_cmd", run_cmd)
    config = {"frequency": "weekly", "day": "Mon", "time": "02:30",
              "profile_id": "xccdf_org.test.content_profile_base"}
    bridge.cmd_manage_timer(["configure", json.dumps(config)])

    content = (override_dir / "override.conf").read_text()
    assert "[Timer]" in content
    assert "OnCalendar=\nOnCalendar=Mon *-*-* 02:30:00\n" in content
    assert bridge.load_config()["active_profile"] == "xccdf_org.test.content_profile_base"
    assert ["systemctl", "daemon-reload"] in calls
    assert ["systemctl", "restart", TIMER_UNIT] in calls  # active timer picks up the new schedule
    assert json.loads(capsys.readouterr().out)["status"] == "active"


def test_configure_errors(bridge, monkeypatch, tmp_path):
    monkeypatch.setattr(bridge, "TIMER_OVERRIDE_DIR", tmp_path / "timer.d")
    for args in (["configure"], ["configure", "not-json"], ["configure", "[]"],
                 ["configure", json.dumps({"frequency": "daily", "profile_id": "bad id"})]):
        with pytest.raises(bridge.BridgeError):
            bridge.cmd_manage_timer(args)


def test_enable_disable_run_now(bridge, monkeypatch, capsys):
    run_cmd, calls = _fake_systemctl({TIMER_UNIT: TIMER_ACTIVE, SERVICE_UNIT: SERVICE_IDLE})
    monkeypatch.setattr(bridge, "run_cmd", run_cmd)
    bridge.cmd_manage_timer(["enable"])
    bridge.cmd_manage_timer(["disable"])
    bridge.cmd_manage_timer(["run-now"])
    assert ["systemctl", "enable", "--now", TIMER_UNIT] in calls
    assert ["systemctl", "disable", "--now", TIMER_UNIT] in calls
    assert ["systemctl", "start", "--no-block", SERVICE_UNIT] in calls
    assert len(capsys.readouterr().out.splitlines()) == 3


def test_enable_failure(bridge, monkeypatch):
    run_cmd, _calls = _fake_systemctl({"enable --now cockpit-oscap-scan.timer": (1, "", "Failed to enable unit")})
    monkeypatch.setattr(bridge, "run_cmd", run_cmd)
    with pytest.raises(bridge.BridgeError, match="Failed to enable unit"):
        bridge.cmd_manage_timer(["enable"])


def test_invalid_actions(run_bridge):
    assert "error" in run_bridge("manage-timer", expect_rc=1)
    assert "error" in run_bridge("manage-timer", "restart", expect_rc=1)
    assert "error" in run_bridge("validate-calendar", expect_rc=1)


def test_validate_calendar_separates_spec_from_options(bridge, monkeypatch):
    calls = []

    def fake_run(argv, **_kwargs):
        calls.append(list(argv))
        return 0, ("  Original form: --weekly\nNormalized form: Mon *-*-* 00:00:00\n"
                   "    Next elapse: Mon 2026-09-28 00:00:00 UTC\n"), ""

    monkeypatch.setattr(bridge, "run_cmd", fake_run)
    monkeypatch.setattr(bridge.shutil, "which", lambda _name: "/usr/bin/systemd-analyze")
    check = bridge.validate_calendar("--weekly")
    assert calls == [["/usr/bin/systemd-analyze", "calendar", "--", "--weekly"]]
    assert check["valid"] is True
    assert check["normalized"] == "Mon *-*-* 00:00:00"
