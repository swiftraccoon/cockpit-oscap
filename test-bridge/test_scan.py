"""ARF parsing, result storage and the scan command."""
# mypy: disallow-untyped-defs=false, disallow-untyped-decorators=false, disallow-untyped-calls=false

from __future__ import annotations

import json
import os
import signal
import subprocess
import time
from typing import Any

import pytest
from conftest import (
    BRIDGE_PATH,
    PROFILE_BASE,
    RULE_AUDIT,
    RULE_ROOT_LOGIN,
    RULE_TIMEOUT,
    SYNTHETIC_ARF,
    real_content,
    requires_oscap,
)

SCORED_RULES = 3
EXPECTED_SCORE = 33.33
KEEP = 2
MAX_SCORE = 100.0


def test_parse_arf(bridge, arf_path):
    parsed = bridge.parse_arf(str(arf_path))
    assert parsed["test_result_id"] == f"xccdf_org.open-scap_testresult_{PROFILE_BASE}"
    assert parsed["profile_id"] == PROFILE_BASE
    assert parsed["benchmark_id"] == "xccdf_org.test.content_benchmark_TEST"
    assert parsed["start_time"] == "2026-03-19T18:30:00+00:00"
    assert parsed["xccdf_score"] == EXPECTED_SCORE
    # pass / (pass + fail + error): 1 / 3, notapplicable excluded, notselected dropped
    assert parsed["score"] == EXPECTED_SCORE
    results = {r["rule_id"]: r for r in parsed["results"]}
    assert "xccdf_org.test.content_rule_never_selected" not in results
    assert len(results) == SCORED_RULES + 1
    assert results[RULE_AUDIT] == {"rule_id": RULE_AUDIT, "result": "pass", "title": "Ensure audit is installed",
                                   "severity": "medium", "group": "Auditing", "message": ""}
    assert results[RULE_TIMEOUT]["message"] == "probe failed"
    assert results[RULE_TIMEOUT]["group"] == "SSH Server"
    assert results["xccdf_org.test.content_rule_unknown"]["title"] == ""


def test_parse_arf_errors(bridge, tmp_path):
    bad = tmp_path / "bad.xml"
    bad.write_text("this is not xml")
    with pytest.raises(bridge.BridgeError, match="failed to parse"):
        bridge.parse_arf(str(bad))
    empty = tmp_path / "empty.xml"
    empty.write_text("<root/>")
    with pytest.raises(bridge.BridgeError, match="TestResult"):
        bridge.parse_arf(str(empty))


def _write_result(bridge: Any, result_id: str, **overrides: Any) -> dict[str, Any]:
    bridge.RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    data = {
        "score": 50.0,
        "results": [{"rule_id": RULE_AUDIT, "result": "pass", "title": "A", "severity": "medium"},
                    {"rule_id": RULE_ROOT_LOGIN, "result": "fail", "title": "B", "severity": "high"}],
        "timestamp": "2026-04-08T025531",
        "profile_id": PROFILE_BASE,
        "status": "complete",
        **overrides,
    }
    (bridge.RESULTS_DIR / f"{result_id}.json").write_text(json.dumps(data))
    return data


def test_load_legacy_result_normalizes(bridge):
    _write_result(bridge, "2026-04-08T025531-base")
    result = bridge._load_result("2026-04-08T025531-base")
    assert result["timestamp"] == "2026-04-08T02:55:31+00:00"
    assert result["counts"]["pass"] == 1
    assert result["counts"]["fail"] == 1
    assert result["counts"]["notapplicable"] == 0
    assert result["results"][0]["group"] == ""
    assert result["tailored"] is False
    assert result["base_profile_id"] == PROFILE_BASE
    assert result["arf_path"] == ""
    assert result["xccdf_score"] is None


def test_result_id_validation(bridge):
    for bad in ("../x", "a/b", "", "x" * 300, ".hidden"):
        with pytest.raises(bridge.BridgeError, match="invalid result id"):
            bridge._load_result(bad)
    with pytest.raises(bridge.BridgeError, match="not found"):
        bridge._load_result("2026-01-01T000000-nope")


def test_list_results_sorted_newest_first(bridge):
    _write_result(bridge, "2026-04-08T025531-base")
    _write_result(bridge, "2026-04-09T120000-base", timestamp="2026-04-09T12:00:00+00:00", tailored=True)
    (bridge.RESULTS_DIR / "garbage.json").write_text("{")
    (bridge.RESULTS_DIR / "notes.json").write_text('{"x": 1}')
    summaries = bridge.list_results()
    assert [s["id"] for s in summaries] == ["2026-04-09T120000-base", "2026-04-08T025531-base", "notes"]
    assert summaries[0]["tailored"] is True
    assert summaries[0]["total"] == 2
    assert summaries[0]["has_arf"] is False


def test_prune_results_keeps_newest(bridge):
    for day in range(1, 6):
        _write_result(bridge, f"2026-04-0{day}T000000-base")
        (bridge.RESULTS_DIR / f"2026-04-0{day}T000000-base.arf.xml").write_text("<x/>")
    bridge.REMEDIATION_DIR.mkdir()
    for day in range(1, 6):
        (bridge.REMEDIATION_DIR / f"2026-04-0{day}T000000-fix.sh").write_text("true")
    bridge.prune_results(KEEP)
    remaining = sorted(p.name for p in bridge.RESULTS_DIR.iterdir())
    assert remaining == ["2026-04-04T000000-base.arf.xml", "2026-04-04T000000-base.json",
                         "2026-04-05T000000-base.arf.xml", "2026-04-05T000000-base.json"]
    assert len(list(bridge.REMEDIATION_DIR.iterdir())) == KEEP


def test_cli_results_commands(run_bridge, bridge):
    _write_result(bridge, "2026-04-08T025531-base")
    assert run_bridge("list-results")[0]["id"] == "2026-04-08T025531-base"
    assert run_bridge("get-result", "2026-04-08T025531-base")["profile_id"] == PROFILE_BASE
    assert run_bridge("delete-result", "2026-04-08T025531-base") == {"deleted": True, "id": "2026-04-08T025531-base"}
    assert "error" in run_bridge("delete-result", "2026-04-08T025531-base", expect_rc=1)
    assert "error" in run_bridge("get-result", expect_rc=1)
    assert "error" in run_bridge("generate-report", "2026-04-08T025531-base", expect_rc=1)


def test_scan_requires_profile(bridge):
    with pytest.raises(bridge.BridgeError, match="no profile"):
        bridge._resolve_scan_request([])


def test_scan_resolves_request_and_tailoring(bridge, datastream):
    request = bridge._resolve_scan_request([PROFILE_BASE])
    assert request["profile_id"] == PROFILE_BASE
    assert request["profile_title"] == "Base Profile"
    assert request["total_rules"] == 3
    assert request["tailoring_path"] is None
    assert request["datastream"] == datastream

    mods = [{"idref": RULE_AUDIT, "action": "unselect"}]
    profile_id, xml = bridge.build_tailoring_xml(PROFILE_BASE, "Base Profile", mods, datastream)
    path = bridge.TAILORING_DIR / "base.xml"
    bridge._atomic_write(path, xml)
    bridge.save_config({"tailorings": {PROFILE_BASE: str(path)}, "active_profile": PROFILE_BASE})

    request = bridge._resolve_scan_request([])
    assert request["profile_id"] == profile_id
    assert request["tailoring_path"] == str(path)
    assert request["total_rules"] == 2
    assert request["profile_title"] == "Base Profile (customized)"
    assert bridge._resolve_scan_request(["--no-tailoring"])["profile_id"] == PROFILE_BASE
    with pytest.raises(bridge.BridgeError, match="profile not found"):
        bridge._resolve_scan_request(["xccdf_org.test.content_profile_nope"])
    with pytest.raises(bridge.BridgeError, match="invalid profile id"):
        bridge._resolve_scan_request(["bad id"])


def test_scan_without_oscap_reports_error(bridge, monkeypatch):
    monkeypatch.setattr(bridge.shutil, "which", lambda _name: None)
    with pytest.raises(bridge.BridgeError, match="openscap-scanner"):
        bridge.run_scan([PROFILE_BASE])


def test_scan_lock_is_exclusive(bridge):
    fd = bridge._scan_lock()
    try:
        with pytest.raises(bridge.BridgeError, match="already running"):
            bridge._scan_lock()
    finally:
        os.close(fd)
    os.close(bridge._scan_lock())


def test_fix_script_and_progress_parsing_with_fake_oscap(bridge, tmp_path, datastream, monkeypatch, capsys):
    """Drive run_scan with a stand-in `oscap` that emits --progress lines and copies a canned ARF."""
    fake = tmp_path / "oscap"
    canned = tmp_path / "canned.arf.xml"
    canned.write_text(SYNTHETIC_ARF)
    fake.write_text(f"""#!/bin/sh
# find --results-arf argument
while [ $# -gt 0 ]; do
  if [ "$1" = "--results-arf" ]; then out="$2"; fi
  shift
done
echo "{RULE_AUDIT}:pass"
echo "{RULE_ROOT_LOGIN}:fail"
echo "{RULE_TIMEOUT}:error"
echo "noise line without a rule id"
cp {canned} "$out"
exit 2
""")
    fake.chmod(0o755)
    monkeypatch.setattr(bridge.shutil, "which", lambda name: str(fake) if name == "oscap" else None)

    bridge.cmd_scan([PROFILE_BASE, "--datastream", datastream])
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    progress = [line for line in lines if line["type"] == "progress"]
    assert [p["current"] for p in progress] == [1, 2, 3]
    assert progress[-1]["progress"] == int(MAX_SCORE)
    assert progress[-1]["total"] == 3
    assert progress[0]["rule_id"] == RULE_AUDIT
    done = lines[-1]
    assert done["type"] == "done"
    result = done["result"]
    assert result["status"] == "complete"
    assert result["score"] == EXPECTED_SCORE
    assert result["counts"]["fail"] == 1
    assert result["profile_title"] == "Base Profile"
    assert result["id"].endswith("-base")
    saved = json.loads((bridge.RESULTS_DIR / f"{result['id']}.json").read_text())
    assert saved["test_result_id"] == result["test_result_id"]
    state = json.loads(bridge.SCAN_STATE_PATH.read_text())
    assert state["running"] is False
    assert state["status"] == "complete"
    assert state["result_id"] == result["id"]
    assert bridge.list_results()[0]["id"] == result["id"]


def test_scan_failure_with_fake_oscap(bridge, tmp_path, datastream, monkeypatch):
    fake = tmp_path / "oscap"
    fake.write_text("#!/bin/sh\necho 'OpenSCAP Error: boom' >&2\nexit 1\n")
    fake.chmod(0o755)
    monkeypatch.setattr(bridge.shutil, "which", lambda name: str(fake) if name == "oscap" else None)
    with pytest.raises(bridge.BridgeError, match="boom"):
        bridge.run_scan([PROFILE_BASE, "--datastream", datastream])
    state = json.loads(bridge.SCAN_STATE_PATH.read_text())
    assert state["status"] == "failed"
    assert not list(bridge.RESULTS_DIR.glob("*.arf.xml"))


def test_scan_cancellation_with_fake_oscap(bridge_env, tmp_path, datastream, bridge):
    fake = tmp_path / "oscap"
    fake.write_text(f"#!/bin/sh\necho '{RULE_AUDIT}:pass'\nsleep 30\n")
    fake.chmod(0o755)
    env = {**os.environ, **bridge_env, "PATH": f"{tmp_path}:{os.environ['PATH']}"}
    proc = subprocess.Popen(["python3", str(BRIDGE_PATH), "scan", PROFILE_BASE, "--datastream", datastream],
                            stdout=subprocess.PIPE, text=True, env=env)
    assert proc.stdout is not None
    first = json.loads(proc.stdout.readline())
    assert first["type"] == "progress"
    proc.send_signal(signal.SIGTERM)
    out = proc.stdout.read()
    assert proc.wait(timeout=20) == 1
    assert "cancelled" in out
    for _ in range(50):
        state = json.loads(bridge.SCAN_STATE_PATH.read_text())
        if not state["running"]:
            break
        time.sleep(0.1)
    assert state["status"] == "cancelled"


@requires_oscap
def test_real_scan_round_trip(bridge, monkeypatch):
    """End-to-end with the installed OpenSCAP and SCAP Security Guide content."""
    ds = str(real_content())
    profiles = bridge.list_profiles(ds, {})
    assert profiles
    profile = profiles[-1]["id"]
    result = bridge.run_scan([profile, "--datastream", ds, "--no-tailoring"])
    assert result["status"] == "complete"
    assert result["test_result_id"].startswith("xccdf_org.open-scap_testresult_")
    assert result["counts"]["pass"] + result["counts"]["fail"] + result["counts"]["notapplicable"] > 0
    assert 0.0 <= result["score"] <= MAX_SCORE
    assert all(r["title"] for r in result["results"])
    assert bridge.list_results()[0]["id"] == result["id"]

    fix = bridge.generate_fix(result)
    assert fix["result_id"] == result["id"]
    failed = {r["rule_id"] for r in result["results"] if r["result"] == "fail"}
    assert {r["id"] for r in fix["rules"]} == failed
    assert all(r["risk_level"] in ("low", "medium", "high") for r in fix["rules"])

    monkeypatch.setattr(bridge, "output_json", lambda data: setattr(bridge, "_last", data))
    bridge.cmd_generate_report([result["id"]])
    assert bridge._last["html"].lstrip().lower().startswith("<!doctype html")


def test_reconcile_stale_scan_state(bridge):
    bridge._write_scan_state({"running": True, "pid": 1, "profile_id": PROFILE_BASE, "source": "interactive"})
    bridge.reconcile_scan_state()  # no lock file yet: nothing to reconcile
    assert json.loads(bridge.SCAN_STATE_PATH.read_text())["running"] is True

    os.close(bridge._scan_lock())  # creates the lock file and releases it
    bridge.reconcile_scan_state()
    state = json.loads(bridge.SCAN_STATE_PATH.read_text())
    assert state["running"] is False
    assert state["status"] == "failed"
    assert state["profile_id"] == PROFILE_BASE

    bridge._write_scan_state({"running": True, "pid": os.getpid(), "profile_id": PROFILE_BASE, "source": "x"})
    fd = bridge._scan_lock()
    try:
        bridge.reconcile_scan_state()  # lock held: the scan is genuinely running
        assert json.loads(bridge.SCAN_STATE_PATH.read_text())["running"] is True
    finally:
        os.close(fd)
