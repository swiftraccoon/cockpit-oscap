"""Fix script parsing, risk classification and remediation."""
# mypy: disallow-untyped-defs=false, disallow-untyped-decorators=false, disallow-untyped-calls=false

from __future__ import annotations

import json
import textwrap

import pytest
from conftest import PROFILE_BASE, RULE_AUDIT, RULE_ROOT_LOGIN, RULE_TIMEOUT

EXPECTED_RULE_COUNT = 3

# Format produced by `oscap xccdf generate fix --result-id ...` (OpenSCAP 1.3.x)
RESULT_FIX_SCRIPT = textwrap.dedent(f"""\
#!/usr/bin/env bash
###############################################################################
# Bash Remediation Script generated from evaluation of Base Profile
###############################################################################

###############################################################################
# BEGIN fix (1 / 3) for '{RULE_AUDIT}'
###############################################################################
(>&2 echo "Remediating rule 1/3: '{RULE_AUDIT}'")
dnf install -y audit

# END fix for '{RULE_AUDIT}'

###############################################################################
# BEGIN fix (2 / 3) for '{RULE_ROOT_LOGIN}'
###############################################################################
(>&2 echo "Remediating rule 2/3: '{RULE_ROOT_LOGIN}'")
sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl restart sshd

# END fix for '{RULE_ROOT_LOGIN}'

###############################################################################
# BEGIN fix (3 / 3) for '{RULE_TIMEOUT}'
###############################################################################
(>&2 echo "Remediating rule 3/3: '{RULE_TIMEOUT}'")
(>&2 echo "FIX FOR THIS RULE '{RULE_TIMEOUT}' IS MISSING!")

# END fix for '{RULE_TIMEOUT}'
""")

# Older format: rule id inside the parentheses
LEGACY_FIX_SCRIPT = textwrap.dedent(f"""\
###############################################################################
# BEGIN fix ({RULE_AUDIT}) for 'audit_installed'
###############################################################################
dnf install -y audit
# END fix ({RULE_AUDIT}) for 'audit_installed'
###############################################################################
""")


def test_parse_result_fix_script(bridge):
    rules = bridge.parse_fix_script(RESULT_FIX_SCRIPT)
    assert [r["id"] for r in rules] == [RULE_AUDIT, RULE_ROOT_LOGIN, RULE_TIMEOUT]
    by_id = {r["id"]: r for r in rules}
    assert by_id[RULE_AUDIT]["fix_snippet"].endswith("dnf install -y audit")
    assert by_id[RULE_AUDIT]["risk_level"] == "low"
    assert by_id[RULE_AUDIT]["has_fix"] is True
    assert by_id[RULE_ROOT_LOGIN]["risk_level"] == "high"
    assert "SSH" in by_id[RULE_ROOT_LOGIN]["risk_reason"]
    assert by_id[RULE_TIMEOUT]["has_fix"] is False


def test_parse_legacy_fix_script(bridge):
    rules = bridge.parse_fix_script(LEGACY_FIX_SCRIPT)
    assert [r["id"] for r in rules] == [RULE_AUDIT]
    assert rules[0]["fix_snippet"] == "dnf install -y audit"


def test_parse_fix_script_without_markers(bridge):
    assert bridge.parse_fix_script("") == []
    assert bridge.parse_fix_script("#!/bin/bash\necho hello\n") == []


@pytest.mark.parametrize(("snippet", "level"), [
    ("sed -i '/NOPASSWD/d' /etc/sudoers.d/*", "high"),
    ("echo 'auth required pam_wheel.so' >> /etc/pam.d/su", "high"),
    ("authselect select sssd with-mkhomedir", "high"),
    ("firewall-cmd --set-default-zone=drop", "high"),
    ("cp zones.xml /etc/firewalld/zones/public.xml", "high"),
    ("semanage fcontext -a -t sshd_exec_t /usr/sbin/sshd", "high"),
    ("sed -i 's/SELINUX=disabled/SELINUX=enforcing/' /etc/selinux/config", "high"),
    ("sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config", "high"),
    ("chmod 0600 /etc/ssh/sshd_config", "high"),
    ("grub2-mkconfig -o /boot/grub2/grub.cfg", "high"),
    ("systemctl enable --now auditd", "medium"),
    ("echo '-w /etc/passwd' >> /etc/audit/rules.d/passwd.rules", "medium"),
    ("echo '*.* @@remote:514' >> /etc/rsyslog.conf", "medium"),
    ("chmod 0600 /etc/cron.d/daily-scan", "medium"),
    ("dnf remove -y telnet-server", "medium"),
    ("sysctl -w kernel.yama.ptrace_scope=2", "low"),
    ("echo 'install usb-storage /bin/true' >> /etc/modprobe.d/usb.conf", "low"),
    ("dnf install -y audit", "low"),
    ("", "low"),
])
def test_classify_risk(bridge, snippet, level):
    got_level, reason = bridge.classify_risk(snippet)
    assert got_level == level
    assert bool(reason) == (level != "low")


def _seed_result(bridge, result_id="2026-04-08T025531-base"):
    bridge.RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    arf = bridge.RESULTS_DIR / f"{result_id}.arf.xml"
    arf.write_text("<x/>")
    (bridge.RESULTS_DIR / f"{result_id}.json").write_text(json.dumps({
        "score": 0.0, "profile_id": PROFILE_BASE, "timestamp": "2026-04-08T02:55:31+00:00",
        "test_result_id": "xccdf_org.open-scap_testresult_x",
        "results": [{"rule_id": RULE_AUDIT, "result": "fail", "title": "Audit", "severity": "medium"},
                    {"rule_id": RULE_ROOT_LOGIN, "result": "fail", "title": "Root", "severity": "high"},
                    {"rule_id": RULE_TIMEOUT, "result": "fail", "title": "Timeout", "severity": "medium"}],
    }))
    return result_id


def test_generate_fix_uses_result_id(bridge, monkeypatch):
    result_id = _seed_result(bridge)
    calls = []

    def fake_run(argv, **_kwargs):
        calls.append(argv)
        return 0, RESULT_FIX_SCRIPT, ""

    monkeypatch.setattr(bridge, "run_cmd", fake_run)
    monkeypatch.setattr(bridge.shutil, "which", lambda _name: "/usr/bin/oscap")
    fix = bridge.generate_fix(bridge._load_result(result_id))
    assert calls[0][1:7] == ["xccdf", "generate", "fix", "--fix-type", "bash", "--result-id"]
    assert calls[0][7] == "xccdf_org.open-scap_testresult_x"
    assert {r["id"]: r["title"] for r in fix["rules"]} == {RULE_AUDIT: "Audit", RULE_ROOT_LOGIN: "Root",
                                                          RULE_TIMEOUT: "Timeout"}


def test_generate_fix_passes_embedded_tailoring(bridge, monkeypatch, arf_path):
    result_id = _seed_result(bridge)
    arf = bridge.RESULTS_DIR / f"{result_id}.arf.xml"
    arf.write_text(
        '<arf:asset-report-collection xmlns:arf="urn:oasis:names:tc:dfi:2.0:asset-report-format:1.1" '
        'xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2"><arf:report-requests><arf:report-request id="r">'
        f'<arf:content><xccdf:Tailoring id="t">'
        f'<xccdf:Profile id="{PROFILE_BASE}_customized" extends="{PROFILE_BASE}">'
        f'<xccdf:select idref="{RULE_AUDIT}" selected="false"/></xccdf:Profile></xccdf:Tailoring>'
        "</arf:content></arf:report-request></arf:report-requests></arf:asset-report-collection>")
    calls = []

    def fake_run(argv, **_kwargs):
        calls.append(list(argv))
        tailoring = bridge.Path(argv[argv.index("--tailoring-file") + 1])
        assert tailoring.is_file()
        assert f"{PROFILE_BASE}_customized" in tailoring.read_text()
        return 0, RESULT_FIX_SCRIPT, ""

    monkeypatch.setattr(bridge, "run_cmd", fake_run)
    monkeypatch.setattr(bridge.shutil, "which", lambda _name: "/usr/bin/oscap")
    fix = bridge.generate_fix(bridge._load_result(result_id))
    assert len(fix["rules"]) == EXPECTED_RULE_COUNT
    assert "--tailoring-file" in calls[0]
    # the temporary tailoring file is cleaned up again
    assert not bridge.Path(calls[0][calls[0].index("--tailoring-file") + 1]).exists()
    extracted = bridge.extract_arf_tailoring(str(arf))
    assert extracted is not None
    bridge.Path(extracted).unlink()
    # an ARF from a scan without tailoring has nothing to extract
    assert bridge.extract_arf_tailoring(str(arf_path)) is None


def test_generate_fix_without_arf(bridge):
    result_id = _seed_result(bridge)
    (bridge.RESULTS_DIR / f"{result_id}.arf.xml").unlink()
    with pytest.raises(bridge.BridgeError, match="no longer available"):
        bridge.generate_fix(bridge._load_result(result_id))


def test_remediate_runs_each_rule_separately(bridge, monkeypatch, capsys):
    result_id = _seed_result(bridge)
    snippets = {
        RULE_AUDIT: "echo applied-audit",
        RULE_ROOT_LOGIN: "echo failing >&2; exit 3",
        RULE_TIMEOUT: "(>&2 echo \"FIX FOR THIS RULE IS MISSING!\")",
    }

    def fake_generate_fix(_result):
        rules = [bridge.FixRuleInfo(id=rid, title="", fix_snippet=snippet, risk_level="low", risk_reason="",
                                    has_fix="MISSING" not in snippet) for rid, snippet in snippets.items()]
        return bridge.FixInfo(result_id=result_id, script="", rules=rules)

    monkeypatch.setattr(bridge, "generate_fix", fake_generate_fix)
    bridge.cmd_remediate([result_id, "--rules", json.dumps([RULE_AUDIT, RULE_ROOT_LOGIN])])
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [line["type"] for line in lines] == ["progress", "progress", "done"]
    outcome = lines[-1]["result"]
    assert outcome["success"] is False
    assert outcome["rules"][0] == {"rule_id": RULE_AUDIT, "success": True, "exit_status": 0,
                                   "output": "applied-audit\n", "errors": ""}
    assert outcome["rules"][1]["exit_status"] == 3
    assert outcome["rules"][1]["errors"] == "failing\n"
    script = bridge.Path(outcome["script_path"])
    assert script.is_file()
    assert "echo applied-audit" in script.read_text()
    assert oct(script.stat().st_mode & 0o777) == "0o700"

    # the audit record next to the script, and the history built from it
    record = json.loads(script.with_suffix(".json").read_text())
    assert record["success"] is False
    assert record["timestamp"].endswith("+00:00")
    assert [r["rule_id"] for r in record["rules"]] == [RULE_AUDIT, RULE_ROOT_LOGIN]
    runs = bridge.list_remediations(result_id)
    assert len(runs) == 1
    assert runs[0]["result_id"] == result_id
    assert runs[0]["script_path"] == str(script)
    assert (runs[0]["success"], runs[0]["applied"], runs[0]["failed"]) == (False, 1, 1)
    assert bridge.list_remediations("2026-01-01T000000-other") == []
    # a script from before the audit record existed still shows up, with an unknown outcome
    legacy = bridge.REMEDIATION_DIR / "2026-01-01T000000-2026-04-08T025531-base.sh"
    legacy.write_text("#!/usr/bin/env bash\n# --- a ---\necho a\n# --- b ---\necho b\n")
    runs = bridge.list_remediations(result_id)
    assert [r["id"] for r in runs] == [script.stem, legacy.stem]  # newest first
    assert (runs[1]["success"], runs[1]["applied"], runs[1]["failed"]) == (None, 2, 0)
    assert runs[1]["timestamp"] == "2026-01-01T00:00:00+00:00"

    with pytest.raises(bridge.BridgeError, match="no remediation is available"):
        bridge.remediate(bridge._load_result(result_id), [RULE_TIMEOUT])
    with pytest.raises(bridge.BridgeError, match="no remediation is available"):
        bridge.remediate(bridge._load_result(result_id), ["xccdf_org.test.content_rule_nope"])


def test_remediate_argument_validation(run_bridge, bridge):
    result_id = _seed_result(bridge)
    assert "error" in run_bridge("remediate", expect_rc=1)
    assert "no rules" in run_bridge("remediate", result_id, expect_rc=1)["error"]
    assert "error" in run_bridge("remediate", result_id, "--rules", "{}", expect_rc=1)
    assert "error" in run_bridge("remediate", result_id, "--rules", '["bad id"]', expect_rc=1)


def test_generate_fix_ansible_playbook(bridge, monkeypatch):
    result_id = _seed_result(bridge)
    calls = []

    def fake_run(argv, **_kwargs):
        calls.append(list(argv))
        return 0, "---\n- hosts: all\n  tasks: []\n", ""

    monkeypatch.setattr(bridge, "run_cmd", fake_run)
    monkeypatch.setattr(bridge.shutil, "which", lambda _name: "/usr/bin/oscap")
    fix = bridge.generate_fix(bridge._load_result(result_id), "ansible")
    assert calls[0][4:6] == ["--fix-type", "ansible"]
    assert fix["fix_type"] == "ansible"
    assert fix["script"].startswith("---\n- hosts: all")
    assert fix["rules"] == []  # playbooks are not split into per-rule blocks
    with pytest.raises(bridge.BridgeError, match="unsupported fix type"):
        bridge.generate_fix(bridge._load_result(result_id), "puppet")
    with pytest.raises(bridge.BridgeError, match="unsupported fix type"):
        bridge.cmd_generate_fix([result_id, "--type", "puppet"])


def test_list_remediations_cli(run_bridge):
    assert run_bridge("list-remediations") == []
    assert "error" in run_bridge("list-remediations", "../etc", expect_rc=1)
