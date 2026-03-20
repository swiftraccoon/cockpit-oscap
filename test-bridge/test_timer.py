"""Tests for the manage-timer command."""
from __future__ import annotations

import importlib.util
import json
import pathlib
from unittest.mock import patch

import pytest

BRIDGE_PATH = pathlib.Path(__file__).resolve().parent.parent / "src" / "oscap-bridge.py"

TIMER_UNIT = "cockpit-oscap-scan.timer"


@pytest.fixture
def bridge_module():
    """Import oscap-bridge as a module for direct function testing."""
    spec = importlib.util.spec_from_file_location("oscap_bridge", str(BRIDGE_PATH))
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Unit tests: status action
# ---------------------------------------------------------------------------


class TestManageTimerStatus:
    """Test manage-timer status action."""

    def test_status_active_timer(self, bridge_module, capsys):
        """status returns active state, next_run, and frequency."""
        mock_output = (
            "ActiveState=active\n"
            "NextElapseUSecRealtime=Thu 2026-03-26 00:00:00 UTC\n"
            "Description=Scheduled OpenSCAP Compliance Scan\n"
        )
        with patch.object(bridge_module, "run_cmd", return_value=(0, mock_output, "")):
            bridge_module.cmd_manage_timer(["status"])

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "active"
        assert data["next_run"] == "Thu 2026-03-26 00:00:00 UTC"
        assert "frequency" in data

    def test_status_inactive_timer(self, bridge_module, capsys):
        """status returns inactive when timer is stopped."""
        mock_output = (
            "ActiveState=inactive\n"
            "NextElapseUSecRealtime=n/a\n"
            "Description=Scheduled OpenSCAP Compliance Scan\n"
        )
        with patch.object(bridge_module, "run_cmd", return_value=(0, mock_output, "")):
            bridge_module.cmd_manage_timer(["status"])

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "inactive"
        assert data["next_run"] == ""

    def test_status_not_found(self, bridge_module, capsys):
        """status returns not-found when unit does not exist."""
        mock_output = "ActiveState=inactive\nNextElapseUSecRealtime=\nDescription=\n"
        with patch.object(
            bridge_module, "run_cmd",
            return_value=(4, mock_output, "Unit cockpit-oscap-scan.timer not found."),
        ):
            bridge_module.cmd_manage_timer(["status"])

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "not-found"


# ---------------------------------------------------------------------------
# Unit tests: enable action
# ---------------------------------------------------------------------------


class TestManageTimerEnable:
    """Test manage-timer enable action."""

    def test_enable_succeeds(self, bridge_module, capsys):
        """enable calls systemctl enable --now and returns status."""
        status_output = (
            "ActiveState=active\n"
            "NextElapseUSecRealtime=Thu 2026-03-26 00:00:00 UTC\n"
            "Description=Scheduled OpenSCAP Compliance Scan\n"
        )
        with patch.object(
            bridge_module, "run_cmd",
            side_effect=[
                (0, "", ""),           # enable --now
                (0, status_output, ""),  # status query
            ],
        ):
            bridge_module.cmd_manage_timer(["enable"])

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "active"

    def test_enable_failure(self, bridge_module, capsys):
        """enable returns error on systemctl failure."""
        with (
            patch.object(bridge_module, "run_cmd", return_value=(1, "", "Failed to enable unit")),
            pytest.raises(SystemExit),
        ):
            bridge_module.cmd_manage_timer(["enable"])

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "error" in data


# ---------------------------------------------------------------------------
# Unit tests: disable action
# ---------------------------------------------------------------------------


class TestManageTimerDisable:
    """Test manage-timer disable action."""

    def test_disable_succeeds(self, bridge_module, capsys):
        """disable calls systemctl disable --now and returns status."""
        status_output = (
            "ActiveState=inactive\n"
            "NextElapseUSecRealtime=n/a\n"
            "Description=Scheduled OpenSCAP Compliance Scan\n"
        )
        with patch.object(
            bridge_module, "run_cmd",
            side_effect=[
                (0, "", ""),           # disable --now
                (0, status_output, ""),  # status query
            ],
        ):
            bridge_module.cmd_manage_timer(["disable"])

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "inactive"


# ---------------------------------------------------------------------------
# Unit tests: configure action
# ---------------------------------------------------------------------------


class TestManageTimerConfigure:
    """Test manage-timer configure action."""

    def test_configure_weekly(self, bridge_module, capsys, tmp_path):
        """configure writes drop-in override and reloads daemon."""
        override_dir = tmp_path / "cockpit-oscap-scan.timer.d"
        config_json = json.dumps({"frequency": "weekly"})

        status_output = (
            "ActiveState=active\n"
            "NextElapseUSecRealtime=Thu 2026-03-26 00:00:00 UTC\n"
            "Description=Scheduled OpenSCAP Compliance Scan\n"
        )
        with (
            patch.object(bridge_module, "_TIMER_OVERRIDE_DIR", override_dir),
            patch.object(bridge_module, "run_cmd", side_effect=[
                (0, "", ""),           # daemon-reload
                (0, status_output, ""),  # status query
            ]),
        ):
            bridge_module.cmd_manage_timer(["configure", config_json])

        # Verify the override file was written
        override_file = override_dir / "override.conf"
        assert override_file.exists()
        content = override_file.read_text()
        assert "[Timer]" in content
        assert "OnCalendar=weekly" in content

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "active"

    def test_configure_daily_at_time(self, bridge_module, tmp_path):
        """configure with day and time produces correct OnCalendar value."""
        override_dir = tmp_path / "cockpit-oscap-scan.timer.d"
        config_json = json.dumps({"frequency": "daily", "time": "03:00"})

        status_output = (
            "ActiveState=active\n"
            "NextElapseUSecRealtime=Fri 2026-03-20 03:00:00 UTC\n"
            "Description=Scheduled OpenSCAP Compliance Scan\n"
        )
        with (
            patch.object(bridge_module, "_TIMER_OVERRIDE_DIR", override_dir),
            patch.object(bridge_module, "run_cmd", side_effect=[
                (0, "", ""),
                (0, status_output, ""),
            ]),
        ):
            bridge_module.cmd_manage_timer(["configure", config_json])

        override_file = override_dir / "override.conf"
        content = override_file.read_text()
        assert "OnCalendar=*-*-* 03:00:00" in content

    def test_configure_weekly_with_day_and_time(self, bridge_module, tmp_path):
        """configure with frequency=weekly, day, and time."""
        override_dir = tmp_path / "cockpit-oscap-scan.timer.d"
        config_json = json.dumps({"frequency": "weekly", "day": "Mon", "time": "02:30"})

        status_output = (
            "ActiveState=active\n"
            "NextElapseUSecRealtime=Mon 2026-03-23 02:30:00 UTC\n"
            "Description=Scheduled OpenSCAP Compliance Scan\n"
        )
        with (
            patch.object(bridge_module, "_TIMER_OVERRIDE_DIR", override_dir),
            patch.object(bridge_module, "run_cmd", side_effect=[
                (0, "", ""),
                (0, status_output, ""),
            ]),
        ):
            bridge_module.cmd_manage_timer(["configure", config_json])

        override_file = override_dir / "override.conf"
        content = override_file.read_text()
        assert "OnCalendar=Mon *-*-* 02:30:00" in content

    def test_configure_updates_active_profile(self, bridge_module, tmp_path):
        """configure with profile_id updates config.json active_profile."""
        override_dir = tmp_path / "cockpit-oscap-scan.timer.d"
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        config_path = data_dir / "config.json"

        config_json = json.dumps({
            "frequency": "weekly",
            "profile_id": "xccdf_org.ssgproject.content_profile_ospp",
        })

        status_output = (
            "ActiveState=active\n"
            "NextElapseUSecRealtime=Thu 2026-03-26 00:00:00 UTC\n"
            "Description=Scheduled OpenSCAP Compliance Scan\n"
        )
        with (
            patch.object(bridge_module, "_TIMER_OVERRIDE_DIR", override_dir),
            patch.object(bridge_module, "CONFIG_PATH", config_path),
            patch.object(bridge_module, "run_cmd", side_effect=[
                (0, "", ""),
                (0, status_output, ""),
            ]),
        ):
            bridge_module.cmd_manage_timer(["configure", config_json])

        # Verify config.json was updated
        assert config_path.exists()
        saved = json.loads(config_path.read_text())
        assert saved["active_profile"] == "xccdf_org.ssgproject.content_profile_ospp"

    def test_configure_missing_json(self, bridge_module, capsys):
        """configure without config_json arg returns an error."""
        with pytest.raises(SystemExit):
            bridge_module.cmd_manage_timer(["configure"])

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "error" in data

    def test_configure_invalid_json(self, bridge_module, capsys):
        """configure with invalid JSON returns an error."""
        with pytest.raises(SystemExit):
            bridge_module.cmd_manage_timer(["configure", "not-json"])

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "error" in data


# ---------------------------------------------------------------------------
# Unit tests: unknown action / missing action
# ---------------------------------------------------------------------------


class TestManageTimerEdgeCases:
    """Test manage-timer edge cases."""

    def test_missing_action(self, bridge_module, capsys):
        """manage-timer with no action returns an error."""
        with pytest.raises(SystemExit):
            bridge_module.cmd_manage_timer([])

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "error" in data

    def test_unknown_action(self, bridge_module, capsys):
        """manage-timer with unknown action returns an error."""
        with pytest.raises(SystemExit):
            bridge_module.cmd_manage_timer(["restart"])

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "error" in data
