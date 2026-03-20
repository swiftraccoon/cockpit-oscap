"""Tests for risk classification heuristic."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

BRIDGE_PATH = Path(__file__).resolve().parent.parent / "src" / "oscap-bridge.py"


@pytest.fixture
def bridge():
    """Import oscap-bridge.py as a module."""
    spec = importlib.util.spec_from_file_location("oscap_bridge", str(BRIDGE_PATH))
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["oscap_bridge"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_sudoers_is_high_risk(bridge):
    assert bridge.classify_risk("sed -i '/NOPASSWD/d' /etc/sudoers.d/*") == "high"


def test_pam_is_high_risk(bridge):
    assert bridge.classify_risk("echo 'auth required pam_wheel.so' >> /etc/pam.d/su") == "high"


def test_firewall_cmd_is_high_risk(bridge):
    assert bridge.classify_risk("firewall-cmd --set-default-zone=drop") == "high"


def test_selinux_is_high_risk(bridge):
    assert bridge.classify_risk("semanage fcontext -a -t sshd_exec_t /usr/sbin/sshd") == "high"


def test_authselect_is_high_risk(bridge):
    assert bridge.classify_risk("authselect select sssd with-mkhomedir") == "high"


def test_sshd_config_is_high_risk(bridge):
    assert bridge.classify_risk("sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config") == "high"


def test_firewalld_dir_is_high_risk(bridge):
    assert bridge.classify_risk("cp zones.xml /etc/firewalld/zones/public.xml") == "high"


def test_selinux_config_is_high_risk(bridge):
    assert bridge.classify_risk("sed -i 's/SELINUX=disabled/SELINUX=enforcing/' /etc/selinux/config") == "high"


def test_systemctl_is_medium_risk(bridge):
    assert bridge.classify_risk("systemctl enable --now auditd") == "medium"


def test_audit_config_is_medium_risk(bridge):
    assert bridge.classify_risk("echo '-w /etc/passwd' >> /etc/audit/rules.d/passwd.rules") == "medium"


def test_rsyslog_is_medium_risk(bridge):
    assert bridge.classify_risk("echo '*.* @@remote:514' >> /etc/rsyslog.conf") == "medium"


def test_cron_is_medium_risk(bridge):
    assert bridge.classify_risk("chmod 0600 /etc/cron.d/daily-scan") == "medium"


def test_sysctl_is_low_risk(bridge):
    assert bridge.classify_risk("sysctl -w kernel.yama.ptrace_scope=2") == "low"


def test_chmod_is_low_risk(bridge):
    assert bridge.classify_risk("chmod 0600 /etc/ssh/sshd_config") == "low"


def test_echo_only_is_low_risk(bridge):
    assert bridge.classify_risk("echo 'install usb-storage /bin/true' >> /etc/modprobe.d/usb.conf") == "low"


def test_empty_script_is_low_risk(bridge):
    assert bridge.classify_risk("") == "low"
