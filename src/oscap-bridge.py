#!/usr/bin/env python3
"""Cockpit oscap bridge — typed dispatcher for OpenSCAP operations."""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import syslog
import traceback
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, TypedDict


# ---------------------------------------------------------------------------
# Logging — writes to syslog so errors are visible in `journalctl`
# ---------------------------------------------------------------------------

class _SyslogHandler(logging.Handler):
    """Minimal syslog handler that maps Python log levels to syslog priorities."""

    _PRIORITY_MAP: dict[int, int] = {
        logging.DEBUG: syslog.LOG_DEBUG,
        logging.INFO: syslog.LOG_INFO,
        logging.WARNING: syslog.LOG_WARNING,
        logging.ERROR: syslog.LOG_ERR,
        logging.CRITICAL: syslog.LOG_CRIT,
    }

    def emit(self, record: logging.LogRecord) -> None:
        priority = self._PRIORITY_MAP.get(record.levelno, syslog.LOG_INFO)
        msg = self.format(record)
        syslog.syslog(priority, msg)


def _setup_logging() -> logging.Logger:
    """Configure logging to syslog with cockpit-oscap prefix."""
    syslog.openlog("cockpit-oscap", syslog.LOG_PID, syslog.LOG_DAEMON)
    logger = logging.getLogger("cockpit-oscap")
    logger.setLevel(logging.DEBUG)
    handler = _SyslogHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    return logger


log = _setup_logging()

if TYPE_CHECKING:
    from collections.abc import Callable

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MIN_ARGC: int = 2  # script name + command
DEFAULT_DATASTREAM: str = "/usr/share/xml/scap/ssg/content/ssg-fedora-ds.xml"
DATA_DIR: Path = Path(os.environ.get("COCKPIT_OSCAP_DATA_DIR", "/var/lib/cockpit-oscap"))
RESULTS_DIR: Path = DATA_DIR / "results"
TAILORING_DIR: Path = DATA_DIR / "tailoring"
CONFIG_PATH: Path = DATA_DIR / "config.json"

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Command(StrEnum):
    """Supported bridge commands."""

    DETECT_BACKEND = "detect-backend"
    LIST_PROFILES = "list-profiles"
    PROFILE_RULES = "profile-rules"
    SCAN = "scan"
    GENERATE_FIX = "generate-fix"
    APPLY_FIX = "apply-fix"
    MANAGE_TIMER = "manage-timer"
    CREATE_TAILORING = "create-tailoring"
    PARSE_TAILORING = "parse-tailoring"


class RiskLevel(StrEnum):
    """Risk classification for remediation scripts."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RuleResult(StrEnum):
    """Possible results for a single SCAP rule."""

    PASS = "pass"  # noqa: S105
    FAIL = "fail"
    ERROR = "error"
    NOTAPPLICABLE = "notapplicable"
    NOTCHECKED = "notchecked"
    NOTSELECTED = "notselected"
    INFORMATIONAL = "informational"
    FIXED = "fixed"


# ---------------------------------------------------------------------------
# TypedDicts
# ---------------------------------------------------------------------------


class OscapInfo(TypedDict):
    """Information about the oscap binary."""

    version: str
    path: str


class ComplyctlInfo(TypedDict):
    """Information about the complyctl binary."""

    version: str
    path: str


class ContentInfo(TypedDict):
    """Information about installed SCAP content."""

    datastream_path: str
    present: bool


class BackendInfo(TypedDict):
    """Response shape for detect-backend command."""

    oscap: OscapInfo
    complyctl: ComplyctlInfo | None
    content: ContentInfo


class ErrorResponse(TypedDict):
    """Response shape for error conditions."""

    error: str


class ProfileInfo(TypedDict):
    """Profile metadata from an XCCDF datastream."""

    id: str
    title: str
    description: str
    rule_count: int


class RuleInfo(TypedDict):
    """Rule metadata from an XCCDF datastream."""

    id: str
    title: str
    severity: str
    description: str
    selected: bool


class RuleResultItem(TypedDict):
    """A single rule's evaluation result from an ARF report."""

    rule_id: str
    result: str
    title: str
    severity: str


class ScanResult(TypedDict):
    """Response shape for the scan command."""

    score: float
    results: list[RuleResultItem]
    arf_path: str
    json_path: str
    timestamp: str
    profile_id: str
    status: str


class ParsedArfResult(TypedDict):
    """Internal parsed ARF result (score + rule results)."""

    score: float
    results: list[RuleResultItem]


class FixRuleInfo(TypedDict):
    """Per-rule fix snippet with risk classification."""

    id: str
    fix_snippet: str
    risk_level: str


class FixInfo(TypedDict):
    """Response shape for the generate-fix command."""

    script: str
    rules: list[FixRuleInfo]


class ApplyResult(TypedDict):
    """Response shape for the apply-fix command."""

    success: bool
    output: str
    errors: str


class ScanStatus(StrEnum):
    """Scan completion status."""

    COMPLETE = "complete"
    INTERRUPTED = "interrupted"


class TailoringModification(TypedDict, total=False):
    """A single rule modification inside a tailoring profile.

    Fields:
        rule_id: XCCDF rule or value idref.
        action: One of "enable", "disable", "set-value".
        value: Required when action is "set-value".
    """

    rule_id: str
    action: str
    value: str


class TailoringResult(TypedDict):
    """Response shape for the create-tailoring command."""

    tailoring_xml: str
    path: str


class ParsedTailoring(TypedDict):
    """Response shape for the parse-tailoring command."""

    base_profile: str
    modifications: list[TailoringModification]


class TimerStatus(TypedDict):
    """Response shape for manage-timer status/enable/disable/configure."""

    status: str
    next_run: str
    frequency: str


class TimerConfig(TypedDict, total=False):
    """Configuration payload for manage-timer configure action.

    Fields:
        frequency: One of "daily", "weekly", "monthly" or a systemd calendar spec.
        day: Optional day-of-week (e.g. "Mon") for weekly frequency.
        time: Optional time string (e.g. "03:00") for daily/weekly.
        profile_id: Optional XCCDF profile ID to set as active_profile.
    """

    frequency: str
    day: str
    time: str
    profile_id: str


# ---------------------------------------------------------------------------
# XCCDF XML namespace constants
# ---------------------------------------------------------------------------

NS_DS: str = "http://scap.nist.gov/schema/scap/source/1.2"
NS_XCCDF: str = "http://checklists.nist.gov/xccdf/1.2"
NS_ARF: str = "urn:oasis:names:tc:dfi:2.0:asset-report-format:1.1"

# Convenience map for ElementTree findall/find
_NS: dict[str, str] = {"ds": NS_DS, "xccdf": NS_XCCDF, "arf": NS_ARF}

# Default maximum number of scan results to keep on disk
DEFAULT_MAX_RESULTS: int = 30

# oscap exit code 2 means "some rules failed" — this is normal, not an error
_OSCAP_EXIT_RULES_FAILED: int = 2

# Type alias for JSON output
_JsonOutput = (
    BackendInfo | ErrorResponse | ScanResult | FixInfo | ApplyResult
    | TailoringResult | ParsedTailoring | TimerStatus
    | list[ProfileInfo] | list[RuleInfo]
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def output_json(data: _JsonOutput) -> None:
    """Write a JSON response to stdout."""
    json.dump(data, sys.stdout)
    sys.stdout.write("\n")
    sys.stdout.flush()


def output_error(message: str) -> None:
    """Write an error JSON response to stdout and exit with code 1."""
    log.error("output_error: %s", message)
    output_json(ErrorResponse(error=message))
    sys.exit(1)


# ---------------------------------------------------------------------------
# Risk classification
# ---------------------------------------------------------------------------

# Compiled patterns for remediation risk heuristic (checked in order).
_HIGH_RISK_RE: re.Pattern[str] = re.compile(
    r"/etc/sudoers"
    r"|/etc/pam\.d/"
    r"|/etc/firewalld/"
    r"|/etc/selinux/"
    r"|(?:^|\s)firewall-cmd\b"
    r"|(?:^|\s)semanage\b"
    r"|(?:^|\s)authselect\b"
    r"|(?:sed|echo|cat|tee|cp)\b.*\bsshd_config\b",
    re.MULTILINE,
)

_MEDIUM_RISK_RE: re.Pattern[str] = re.compile(
    r"(?:^|\s)systemctl\b"
    r"|/etc/audit/"
    r"|/etc/rsyslog"
    r"|/etc/cron",
    re.MULTILINE,
)

# Pattern to extract per-rule fix blocks from oscap-generated bash scripts.
# oscap emits: # BEGIN fix (<rule_id>) for '<short_name>'
_FIX_BLOCK_RE: re.Pattern[str] = re.compile(
    r"^#+ BEGIN fix \(([^)]+)\).*?$"
    r"(.*?)"
    r"^#+ END fix \(\1\)",
    re.MULTILINE | re.DOTALL,
)


def classify_risk(fix_script: str) -> str:
    """Classify the risk level of a remediation script snippet.

    Returns a RiskLevel string value: "high", "medium", or "low".
    """
    if _HIGH_RISK_RE.search(fix_script):
        return RiskLevel.HIGH
    if _MEDIUM_RISK_RE.search(fix_script):
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _parse_fix_script(script: str) -> list[FixRuleInfo]:
    """Parse an oscap-generated bash fix script into per-rule snippets.

    oscap generates blocks delimited by:
        # BEGIN fix (<rule_id>) for '<short_name>'
        ...commands...
        # END fix (<rule_id>) for '<short_name>'

    Each block is classified by risk level.
    """
    rules: list[FixRuleInfo] = []
    for match in _FIX_BLOCK_RE.finditer(script):
        rule_id = match.group(1)
        snippet = match.group(2).strip()
        risk = classify_risk(snippet)
        rules.append(FixRuleInfo(id=rule_id, fix_snippet=snippet, risk_level=risk))
    return rules


def run_cmd(argv: list[str]) -> tuple[int, str, str]:
    """Run a subprocess and return (returncode, stdout, stderr)."""
    result = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    return result.returncode, result.stdout, result.stderr


def get_oscap_version() -> OscapInfo:
    """Detect the installed oscap binary version and path."""
    oscap_path = shutil.which("oscap")
    if oscap_path is None:
        output_error("oscap binary not found in PATH")
        msg = "unreachable"
        raise SystemExit(msg)  # unreachable; satisfies mypy

    rc, stdout, _stderr = run_cmd([oscap_path, "--version"])
    if rc != 0:
        output_error(f"oscap --version failed with exit code {rc}")
        msg = "unreachable"
        raise SystemExit(msg)

    # First line is typically: "OpenSCAP command line tool (oscap) X.Y.Z"
    version = "unknown"
    for line in stdout.splitlines():
        if "oscap" in line.lower():
            parts = line.strip().split()
            if parts:
                version = parts[-1]
            break

    return OscapInfo(version=version, path=oscap_path)


def get_complyctl_info() -> ComplyctlInfo | None:
    """Detect the installed complyctl binary, if any."""
    complyctl_path = shutil.which("complyctl")
    if complyctl_path is None:
        return None

    rc, stdout, _stderr = run_cmd([complyctl_path, "version"])
    if rc != 0:
        return ComplyctlInfo(version="unknown", path=complyctl_path)

    version = stdout.strip().splitlines()[0] if stdout.strip() else "unknown"
    return ComplyctlInfo(version=version, path=complyctl_path)


def get_content_info() -> ContentInfo:
    """Detect whether the default SCAP content datastream is installed."""
    ds_path = Path(DEFAULT_DATASTREAM)
    return ContentInfo(
        datastream_path=str(ds_path),
        present=ds_path.is_file(),
    )


# ---------------------------------------------------------------------------
# ARF result parsing
# ---------------------------------------------------------------------------


def _parse_arf_results(arf_path: str) -> ParsedArfResult:
    """Parse an ARF XML file and return structured scan results.

    Returns a ParsedArfResult with 'score' (float) and 'results' (list of RuleResultItem).
    The score is computed as: pass_count / (pass_count + fail_count + error_count) * 100.
    Rules with notapplicable/notchecked/notselected/informational results are excluded
    from the score denominator.
    """
    tree = ET.parse(arf_path)  # noqa: S314
    root = tree.getroot()

    # Find TestResult element — may be inside arf:reports/arf:report/arf:content
    # or directly (depending on output format)
    test_result: ET.Element | None = None
    for elem in root.iter(f"{{{NS_XCCDF}}}TestResult"):
        test_result = elem
        break

    if test_result is None:
        return ParsedArfResult(score=0.0, results=[])

    # Build rule_id → title map from the XCCDF Benchmark's Rule elements.
    # ARF rule-result elements don't contain titles inline — they must be
    # cross-referenced with the Benchmark's Rule definitions.
    rule_titles: dict[str, str] = {}
    for rule_el in root.iter(f"{{{NS_XCCDF}}}Rule"):
        rid = rule_el.get("id", "")
        title_el = rule_el.find(f"{{{NS_XCCDF}}}title")
        if rid and title_el is not None and title_el.text:
            rule_titles[rid] = title_el.text.strip()

    results: list[RuleResultItem] = []
    pass_count = 0
    fail_count = 0
    error_count = 0

    for rr in test_result.findall(f"{{{NS_XCCDF}}}rule-result"):
        rule_id = rr.get("idref", "")
        severity = rr.get("severity", "unknown")

        result_el = rr.find(f"{{{NS_XCCDF}}}result")
        result_text = result_el.text.strip() if result_el is not None and result_el.text else "unknown"

        title = rule_titles.get(rule_id, "")

        results.append(RuleResultItem(
            rule_id=rule_id,
            result=result_text,
            title=title,
            severity=severity,
        ))

        # Tally for score computation
        if result_text == RuleResult.PASS:
            pass_count += 1
        elif result_text == RuleResult.FAIL:
            fail_count += 1
        elif result_text == RuleResult.ERROR:
            error_count += 1
        # notapplicable, notchecked, notselected, informational, fixed — excluded from score

    denominator = pass_count + fail_count + error_count
    score = (pass_count / denominator * 100.0) if denominator > 0 else 0.0

    return ParsedArfResult(score=score, results=results)


def _profile_short_name(profile_id: str) -> str:
    """Extract a short name from a full XCCDF profile ID.

    E.g., "xccdf_org.ssgproject.content_profile_ospp" -> "ospp"
    """
    # Take everything after the last underscore in _profile_ suffix
    match = re.search(r"_profile_(.+)$", profile_id)
    if match:
        return match.group(1)
    # Fallback: last segment after any underscore
    parts = profile_id.rsplit("_", maxsplit=1)
    return parts[-1] if parts else profile_id


def _save_scan_result(
    *,
    arf_source: str,
    parsed: ParsedArfResult,
    profile_id: str,
    results_dir: Path,
) -> tuple[str, str]:
    """Save ARF XML and parsed JSON to the results directory.

    Returns (arf_dest_path, json_dest_path) as strings.
    Filenames follow: YYYY-MM-DDTHHMMSS-profileshortname.{arf.xml,json}
    """
    results_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(tz=UTC).strftime("%Y-%m-%dT%H%M%S")
    short_name = _profile_short_name(profile_id)
    base = f"{timestamp}-{short_name}"

    arf_dest = results_dir / f"{base}.arf.xml"
    json_dest = results_dir / f"{base}.json"

    # Copy ARF XML
    shutil.copy2(arf_source, str(arf_dest))

    # Write parsed JSON
    with json_dest.open("w") as f:
        json.dump(parsed, f, indent=2)
        f.write("\n")

    return str(arf_dest), str(json_dest)


def _prune_old_results(results_dir: Path, *, max_results: int = DEFAULT_MAX_RESULTS) -> None:
    """Remove oldest scan result pairs beyond max_results.

    Files are sorted by name (which starts with a timestamp), so alphabetical
    order equals chronological order.
    """
    arf_files = sorted(results_dir.glob("*.arf.xml"))
    json_files = sorted(results_dir.glob("*.json"))

    # Prune ARF files beyond max
    while len(arf_files) > max_results:
        oldest = arf_files.pop(0)
        oldest.unlink(missing_ok=True)

    # Prune JSON files beyond max
    while len(json_files) > max_results:
        oldest = json_files.pop(0)
        oldest.unlink(missing_ok=True)


def _emit_progress(current: int, total: int, message: str) -> None:
    """Write a progress JSON line to stderr for the frontend to consume."""
    progress = int(current / total * 100) if total > 0 else 0
    progress_obj = {"progress": progress, "message": message}
    sys.stderr.write(json.dumps(progress_obj) + "\n")
    sys.stderr.flush()


# ---------------------------------------------------------------------------
# XCCDF parsing
# ---------------------------------------------------------------------------


def _find_xccdf_benchmark(tree: ET.ElementTree[ET.Element]) -> ET.Element | None:
    """Locate the XCCDF Benchmark element inside a datastream XML."""
    # Try datastream-wrapped structure first:
    # <ds:data-stream-collection>/<ds:data-stream>/<ds:component>/<xccdf:Benchmark>
    for component in tree.iter(f"{{{NS_DS}}}component"):
        benchmark = component.find(f"{{{NS_XCCDF}}}Benchmark")
        if benchmark is not None:
            return benchmark

    # Fallback: bare XCCDF document (Benchmark at root)
    root = tree.getroot()
    if root.tag == f"{{{NS_XCCDF}}}Benchmark":
        return root

    return None


def _parse_profiles(benchmark: ET.Element) -> list[ProfileInfo]:
    """Extract all Profile elements from an XCCDF Benchmark."""
    profiles: list[ProfileInfo] = []
    for prof_el in benchmark.findall("xccdf:Profile", _NS):
        prof_id = prof_el.get("id", "")
        title_el = prof_el.find("xccdf:title", _NS)
        desc_el = prof_el.find("xccdf:description", _NS)

        # Count selected rules (select elements with selected="true")
        selects = prof_el.findall("xccdf:select", _NS)
        rule_count = sum(1 for s in selects if s.get("selected") == "true")

        profiles.append(ProfileInfo(
            id=prof_id,
            title=title_el.text.strip() if title_el is not None and title_el.text else "",
            description=desc_el.text.strip() if desc_el is not None and desc_el.text else "",
            rule_count=rule_count,
        ))
    return profiles


def _parse_rules_for_profile(
    benchmark: ET.Element,
    profile_id: str,
) -> list[RuleInfo]:
    """Extract rules selected by a specific profile from an XCCDF Benchmark."""
    # Find the matching profile
    profile_el: ET.Element | None = None
    for prof in benchmark.findall("xccdf:Profile", _NS):
        if prof.get("id") == profile_id:
            profile_el = prof
            break

    if profile_el is None:
        return []

    # Build a map of profile select overrides: rule_idref -> selected bool
    profile_selects: dict[str, bool] = {}
    for sel in profile_el.findall("xccdf:select", _NS):
        idref = sel.get("idref", "")
        selected = sel.get("selected", "true") == "true"
        if idref:
            profile_selects[idref] = selected

    # Build a map of all Rule elements in the benchmark
    rules: list[RuleInfo] = []
    for rule_el in benchmark.iter(f"{{{NS_XCCDF}}}Rule"):
        rule_id = rule_el.get("id", "")
        if not rule_id:
            continue

        # Determine selection: profile override takes precedence over rule default
        if rule_id in profile_selects:
            selected = profile_selects[rule_id]
        else:
            # Rule's own selected attribute (defaults to true per XCCDF spec)
            selected = rule_el.get("selected", "true") == "true"

        title_el = rule_el.find("xccdf:title", _NS)
        desc_el = rule_el.find("xccdf:description", _NS)
        severity = rule_el.get("severity", "unknown")

        rules.append(RuleInfo(
            id=rule_id,
            title=title_el.text.strip() if title_el is not None and title_el.text else "",
            severity=severity,
            description=desc_el.text.strip() if desc_el is not None and desc_el.text else "",
            selected=selected,
        ))

    return rules


# ---------------------------------------------------------------------------
# Timer management helpers
# ---------------------------------------------------------------------------

_TIMER_UNIT: str = "cockpit-oscap-scan.timer"
_TIMER_OVERRIDE_DIR: Path = Path(f"/etc/systemd/system/{_TIMER_UNIT}.d")


def _parse_systemctl_show(output: str) -> dict[str, str]:
    """Parse ``systemctl show --property=...`` output into a dict."""
    props: dict[str, str] = {}
    for line in output.splitlines():
        eq = line.find("=")
        if eq > 0:
            props[line[:eq]] = line[eq + 1:]
    return props


def _get_timer_status() -> TimerStatus:
    """Query systemd for the timer unit's current state."""
    rc, stdout, stderr = run_cmd([
        "systemctl", "show", _TIMER_UNIT,
        "--property=ActiveState,NextElapseUSecRealtime,Description",
    ])

    if rc != 0 and "not found" in stderr.lower():
        return TimerStatus(status="not-found", next_run="", frequency="")

    props = _parse_systemctl_show(stdout)
    active = props.get("ActiveState", "unknown")

    # Treat "inactive" + missing description as not-found (unit not installed)
    description = props.get("Description", "")
    if active == "inactive" and not description:
        return TimerStatus(status="not-found", next_run="", frequency="")

    next_raw = props.get("NextElapseUSecRealtime", "")
    next_run = "" if next_raw in ("n/a", "") else next_raw

    # Try to read frequency from the override, falling back to "weekly" default
    frequency = "weekly"
    override_conf = _TIMER_OVERRIDE_DIR / "override.conf"
    if override_conf.is_file():
        for line in override_conf.read_text().splitlines():
            if line.startswith("OnCalendar="):
                frequency = line.split("=", maxsplit=1)[1]
                break

    return TimerStatus(status=active, next_run=next_run, frequency=frequency)


def _build_on_calendar(config: TimerConfig) -> str:
    """Convert a TimerConfig into a systemd OnCalendar value.

    Examples:
        {"frequency": "daily"} -> "daily"
        {"frequency": "daily", "time": "03:00"} -> "*-*-* 03:00:00"
        {"frequency": "weekly", "day": "Mon", "time": "02:30"} -> "Mon *-*-* 02:30:00"
        {"frequency": "monthly"} -> "monthly"
    """
    freq = config.get("frequency", "weekly")
    day = config.get("day", "")
    time_str = config.get("time", "")

    if time_str:
        # Normalize time to HH:MM:SS
        normalized_time = time_str if time_str.count(":") >= 2 else f"{time_str}:00"  # noqa: PLR2004
        if day:
            return f"{day} *-*-* {normalized_time}"
        if freq == "daily":
            return f"*-*-* {normalized_time}"
        # weekly/monthly with time but no day — use the time with freq prefix
        return f"*-*-* {normalized_time}"

    return freq


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------


def cmd_detect_backend(_args: list[str]) -> None:
    """Handle the detect-backend command."""
    oscap = get_oscap_version()
    complyctl = get_complyctl_info()
    content = get_content_info()
    result = BackendInfo(oscap=oscap, complyctl=complyctl, content=content)
    output_json(result)


def cmd_list_profiles(args: list[str]) -> None:
    """Handle the list-profiles command.

    Optional arg: datastream path (defaults to DEFAULT_DATASTREAM).
    Returns a JSON array of ProfileInfo objects.
    """
    ds_path = Path(args[0]) if args else Path(DEFAULT_DATASTREAM)
    if not ds_path.is_file():
        output_json([])
        return

    try:
        tree = ET.parse(str(ds_path))  # noqa: S314
    except ET.ParseError as exc:
        output_error(f"failed to parse datastream XML: {exc}")
        return

    benchmark = _find_xccdf_benchmark(tree)
    if benchmark is None:
        output_json([])
        return

    profiles = _parse_profiles(benchmark)
    output_json(profiles)


def cmd_profile_rules(args: list[str]) -> None:
    """Handle the profile-rules command.

    Required arg: profile_id.
    Optional arg: datastream path (defaults to DEFAULT_DATASTREAM).
    Returns a JSON array of RuleInfo objects.
    """
    if not args:
        output_error("profile-rules requires a profile_id argument")
        return

    profile_id = args[0]
    ds_path = Path(args[1]) if len(args) > 1 else Path(DEFAULT_DATASTREAM)

    if not ds_path.is_file():
        output_json([])
        return

    try:
        tree = ET.parse(str(ds_path))  # noqa: S314
    except ET.ParseError as exc:
        output_error(f"failed to parse datastream XML: {exc}")
        return

    benchmark = _find_xccdf_benchmark(tree)
    if benchmark is None:
        output_json([])
        return

    rules = _parse_rules_for_profile(benchmark, profile_id)
    output_json(rules)


class _ScanArgs(TypedDict):
    """Parsed arguments for the scan command."""

    profile_id: str | None
    tailoring_path: str | None
    datastream: str


def _parse_scan_args(args: list[str]) -> _ScanArgs:
    """Parse scan command arguments into a structured dict."""
    profile_id: str | None = None
    tailoring_path: str | None = None
    datastream: str = DEFAULT_DATASTREAM

    i = 0
    while i < len(args):
        if args[i] == "--tailoring-path" and i + 1 < len(args):
            tailoring_path = args[i + 1]
            i += 2
        elif args[i] == "--datastream" and i + 1 < len(args):
            datastream = args[i + 1]
            i += 2
        elif not args[i].startswith("--") and profile_id is None:
            profile_id = args[i]
            i += 1
        else:
            i += 1

    return _ScanArgs(profile_id=profile_id, tailoring_path=tailoring_path, datastream=datastream)


def _resolve_profile_from_config() -> str | None:
    """Read active_profile from config.json, returning None on any failure."""
    if not CONFIG_PATH.is_file():
        return None
    try:
        with CONFIG_PATH.open() as f:
            config: dict[str, object] = json.load(f)
        value = config.get("active_profile")
        return str(value) if isinstance(value, str) else None
    except (json.JSONDecodeError, OSError):
        return None


def _run_oscap_scan(cmd: list[str]) -> tuple[int, list[str], bool]:
    """Run oscap via Popen, streaming progress to stderr.

    Returns (exit_code, stderr_lines, was_interrupted).
    """
    rule_pattern = re.compile(r"Evaluating rule", re.IGNORECASE)
    total_rules = 0
    current_rule = 0
    interrupted = False

    original_sigterm = signal.getsignal(signal.SIGTERM)

    def _on_sigterm(_signum: int, _frame: object) -> None:
        nonlocal interrupted
        interrupted = True

    signal.signal(signal.SIGTERM, _on_sigterm)

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        stderr_lines: list[str] = []
        if proc.stderr is not None:
            for line in proc.stderr:
                stderr_lines.append(line)
                if rule_pattern.search(line):
                    current_rule += 1
                    count_match = re.search(r"(\d+)/(\d+)", line)
                    if count_match:
                        current_rule = int(count_match.group(1))
                        total_rules = int(count_match.group(2))
                    effective_total = total_rules if total_rules > 0 else current_rule
                    msg = (
                        f"Evaluating rule {current_rule}/{total_rules}" if total_rules > 0
                        else f"Evaluating rule {current_rule}"
                    )
                    _emit_progress(current_rule, effective_total, msg)

        rc = proc.wait()
    finally:
        signal.signal(signal.SIGTERM, original_sigterm)

    return rc, stderr_lines, interrupted


def _validate_scan_paths(
    datastream: str,
    tailoring_path: str | None,
) -> str | None:
    """Validate oscap binary and file paths.  Returns an error message, or None if OK."""
    oscap_path = shutil.which("oscap")
    if oscap_path is None:
        return "oscap binary not found in PATH"
    if not Path(datastream).is_file():
        return f"datastream not found: {datastream}"
    if tailoring_path is not None and not Path(tailoring_path).is_file():
        return f"tailoring file not found: {tailoring_path}"
    return None


def _build_oscap_cmd(
    oscap_path: str,
    arf_path: str,
    profile_id: str,
    datastream: str,
    tailoring_path: str | None,
) -> list[str]:
    """Build the oscap xccdf command-line argument list."""
    cmd: list[str] = [
        oscap_path, "xccdf", "eval",
        "--results-arf", arf_path,
        "--profile", profile_id,
    ]
    if tailoring_path is not None:
        cmd.extend(["--tailoring-file", tailoring_path])
    cmd.append(datastream)
    return cmd


def cmd_scan(args: list[str]) -> None:
    """Handle the scan command.

    oscap xccdf exit codes: 0 = all pass, 1 = error, 2 = some rules failed (normal).
    """
    scan_args = _parse_scan_args(args)
    profile_id = scan_args["profile_id"] or _resolve_profile_from_config()

    if profile_id is None:
        output_error("scan requires a profile_id argument or active_profile in config.json")
        return

    validation_err = _validate_scan_paths(scan_args["datastream"], scan_args["tailoring_path"])
    if validation_err is not None:
        output_error(validation_err)
        return

    oscap_path = shutil.which("oscap")
    if oscap_path is None:  # unreachable after validation, satisfies mypy
        output_error("oscap binary not found in PATH")
        return

    # Prepare output paths
    results_dir = RESULTS_DIR
    results_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(tz=UTC).strftime("%Y-%m-%dT%H%M%S")
    short_name = _profile_short_name(profile_id)
    arf_path = str(results_dir / f"{timestamp}-{short_name}.arf.xml")

    cmd = _build_oscap_cmd(oscap_path, arf_path, profile_id, scan_args["datastream"], scan_args["tailoring_path"])
    rc, stderr_lines, interrupted = _run_oscap_scan(cmd)

    # Exit code 1 = real error; 0 = all pass; 2 = some rules failed (normal)
    if rc == 1:
        output_error(f"oscap xccdf failed (exit code 1): {''.join(stderr_lines)[:500]}")
        return

    if not Path(arf_path).is_file():
        output_error("oscap did not produce an ARF results file")
        return

    try:
        parsed = _parse_arf_results(arf_path)
    except ET.ParseError as exc:
        output_error(f"failed to parse ARF results XML: {exc}")
        return

    # Save JSON alongside ARF
    json_path = arf_path.replace(".arf.xml", ".json")
    with Path(json_path).open("w") as f:
        json.dump(parsed, f, indent=2)
        f.write("\n")

    _prune_old_results(results_dir)

    status = ScanStatus.INTERRUPTED if interrupted else ScanStatus.COMPLETE
    output_json(ScanResult(
        score=parsed["score"],
        results=parsed["results"],
        arf_path=arf_path,
        json_path=json_path,
        timestamp=timestamp,
        profile_id=profile_id,
        status=status,
    ))


def cmd_generate_fix(args: list[str]) -> None:
    """Handle the generate-fix command.

    Required arg: profile_id.
    Optional arg: datastream path (defaults to DEFAULT_DATASTREAM).

    Runs ``oscap xccdf generate fix`` to produce a bash remediation script,
    then splits it into per-rule snippets and classifies each by risk level.
    """
    if not args:
        output_error("generate-fix requires a profile_id argument")
        return

    profile_id = args[0]
    ds_path = args[1] if len(args) > 1 else DEFAULT_DATASTREAM

    oscap_path = shutil.which("oscap")
    if oscap_path is None:
        output_error("oscap binary not found in PATH")
        return

    if not Path(ds_path).is_file():
        output_error(f"datastream not found: {ds_path}")
        return

    cmd = [
        oscap_path, "xccdf", "generate", "fix",
        "--fix-type", "bash",
        "--profile", profile_id,
        ds_path,
    ]

    rc, stdout, stderr = run_cmd(cmd)
    if rc != 0:
        output_error(f"oscap generate fix failed (exit {rc}): {stderr[:500]}")
        return

    rules = _parse_fix_script(stdout)
    output_json(FixInfo(script=stdout, rules=rules))


# Timeout for apply-fix subprocess (5 minutes)
_APPLY_FIX_TIMEOUT: int = 300


def cmd_apply_fix(args: list[str]) -> None:
    """Handle the apply-fix command.

    Required arg: path to a bash fix script.
    Executes the script and returns success/output/errors.
    """
    if not args:
        output_error("apply-fix requires a script path argument")
        return

    script_path = Path(args[0])
    if not script_path.is_file():
        output_error(f"fix script not found: {script_path}")
        return

    try:
        result = subprocess.run(
            ["bash", str(script_path)],
            capture_output=True,
            text=True,
            check=False,
            timeout=_APPLY_FIX_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        output_json(ApplyResult(
            success=False,
            output="",
            errors=f"fix script timed out after {_APPLY_FIX_TIMEOUT}s",
        ))
        return

    output_json(ApplyResult(
        success=result.returncode == 0,
        output=result.stdout,
        errors=result.stderr,
    ))


def _build_tailoring_xml(
    base_profile_id: str,
    modifications: list[dict[str, str]],
) -> TailoringResult:
    """Generate XCCDF 1.2 tailoring XML and write it to TAILORING_DIR.

    Returns a TailoringResult with the XML string and file path.
    """
    short_name = _profile_short_name(base_profile_id)
    timestamp = datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%S")

    # Build XCCDF 1.2 Tailoring XML via ElementTree
    tailoring = ET.Element(f"{{{NS_XCCDF}}}Tailoring")
    tailoring.set("id", "cockpit-oscap-tailoring")

    version = ET.SubElement(tailoring, f"{{{NS_XCCDF}}}version")
    version.set("time", timestamp)
    version.text = "1"

    profile = ET.SubElement(tailoring, f"{{{NS_XCCDF}}}Profile")
    profile.set("id", "cockpit_oscap_custom_profile")
    profile.set("extends", base_profile_id)

    title = ET.SubElement(profile, f"{{{NS_XCCDF}}}title")
    title.text = f"Custom profile based on {short_name}"

    for mod in modifications:
        action = mod.get("action", "")
        rule_id = mod.get("rule_id", "")
        if action == "enable":
            sel = ET.SubElement(profile, f"{{{NS_XCCDF}}}select")
            sel.set("idref", rule_id)
            sel.set("selected", "true")
        elif action == "disable":
            sel = ET.SubElement(profile, f"{{{NS_XCCDF}}}select")
            sel.set("idref", rule_id)
            sel.set("selected", "false")
        elif action == "set-value":
            sv = ET.SubElement(profile, f"{{{NS_XCCDF}}}set-value")
            sv.set("idref", rule_id)
            sv.text = mod.get("value", "")

    # Serialize to string with XML declaration
    ET.indent(tailoring)
    xml_bytes = ET.tostring(tailoring, encoding="unicode", xml_declaration=False)
    xml_str = f'<?xml version="1.0" encoding="UTF-8"?>\n{xml_bytes}\n'

    # Write to TAILORING_DIR
    tailoring_dir = TAILORING_DIR
    tailoring_dir.mkdir(parents=True, exist_ok=True)
    out_path = tailoring_dir / f"{short_name}-custom.xml"
    out_path.write_text(xml_str)

    return TailoringResult(tailoring_xml=xml_str, path=str(out_path))


def _parse_tailoring_file(tailoring_path: str) -> ParsedTailoring:
    """Parse an XCCDF tailoring XML file and extract modifications.

    Returns a ParsedTailoring with base_profile and modifications list.
    """
    tree = ET.parse(tailoring_path)  # noqa: S314
    root = tree.getroot()

    # Find the Profile element
    profile = root.find(f"{{{NS_XCCDF}}}Profile")
    if profile is None:
        output_error("tailoring XML does not contain a Profile element")
        msg = "unreachable"
        raise SystemExit(msg)

    base_profile = profile.get("extends", "")
    modifications: list[TailoringModification] = []

    # Extract select elements -> enable/disable
    for sel in profile.findall(f"{{{NS_XCCDF}}}select"):
        idref = sel.get("idref", "")
        selected = sel.get("selected", "true")
        action = "enable" if selected == "true" else "disable"
        modifications.append(TailoringModification(rule_id=idref, action=action))

    # Extract set-value elements
    for sv in profile.findall(f"{{{NS_XCCDF}}}set-value"):
        idref = sv.get("idref", "")
        value = sv.text.strip() if sv.text else ""
        modifications.append(TailoringModification(
            rule_id=idref, action="set-value", value=value,
        ))

    return ParsedTailoring(base_profile=base_profile, modifications=modifications)


def cmd_create_tailoring(args: list[str]) -> None:
    """Handle the create-tailoring command.

    Required args:
        args[0]: base_profile_id — full XCCDF profile ID to extend.
        args[1]: modifications_json — JSON array of TailoringModification dicts.

    Generates XCCDF 1.2 tailoring XML, writes it to TAILORING_DIR, and outputs
    a TailoringResult JSON with the XML string and file path.
    """
    if len(args) < 2:  # noqa: PLR2004
        output_error("create-tailoring requires base_profile_id and modifications_json arguments")
        return

    base_profile_id = args[0]
    try:
        modifications: list[dict[str, str]] = json.loads(args[1])
    except json.JSONDecodeError as exc:
        output_error(f"invalid modifications JSON: {exc}")
        return

    result = _build_tailoring_xml(base_profile_id, modifications)
    output_json(result)


def cmd_parse_tailoring(args: list[str]) -> None:
    """Handle the parse-tailoring command.

    Required arg: tailoring_path — path to an XCCDF tailoring XML file.

    Parses the tailoring file and extracts the base profile and all rule
    modifications (select elements -> enable/disable, set-value elements).
    """
    if not args:
        output_error("parse-tailoring requires a tailoring_path argument")
        return

    tailoring_path = args[0]
    if not Path(tailoring_path).is_file():
        output_error(f"tailoring file not found: {tailoring_path}")
        return

    try:
        result = _parse_tailoring_file(tailoring_path)
    except ET.ParseError as exc:
        output_error(f"failed to parse tailoring XML: {exc}")
        return

    output_json(result)


def _timer_enable() -> None:
    """Enable and start the timer unit, then output status."""
    rc, _stdout, stderr = run_cmd(["systemctl", "enable", "--now", _TIMER_UNIT])
    if rc != 0:
        output_error(f"systemctl enable failed: {stderr[:500]}")
        return
    output_json(_get_timer_status())


def _timer_disable() -> None:
    """Disable and stop the timer unit, then output status."""
    rc, _stdout, stderr = run_cmd(["systemctl", "disable", "--now", _TIMER_UNIT])
    if rc != 0:
        output_error(f"systemctl disable failed: {stderr[:500]}")
        return
    output_json(_get_timer_status())


def _timer_configure(args: list[str]) -> None:
    """Write a drop-in override for OnCalendar and optionally update active_profile."""
    if len(args) < 2:  # noqa: PLR2004
        output_error("manage-timer configure requires a JSON config argument")
        return

    try:
        config: TimerConfig = json.loads(args[1])
    except json.JSONDecodeError as exc:
        output_error(f"invalid timer config JSON: {exc}")
        return

    on_calendar = _build_on_calendar(config)

    # Write drop-in override
    override_dir = _TIMER_OVERRIDE_DIR
    override_dir.mkdir(parents=True, exist_ok=True)
    override_conf = override_dir / "override.conf"
    override_conf.write_text(f"[Timer]\nOnCalendar=\nOnCalendar={on_calendar}\n")

    # Reload systemd to pick up the override
    rc, _stdout, stderr = run_cmd(["systemctl", "daemon-reload"])
    if rc != 0:
        output_error(f"systemctl daemon-reload failed: {stderr[:500]}")
        return

    # Update config.json active_profile if profile_id was provided
    profile_id = config.get("profile_id")
    if profile_id:
        _update_active_profile(profile_id)

    output_json(_get_timer_status())


def cmd_manage_timer(args: list[str]) -> None:
    """Handle the manage-timer command.

    Actions:
        status    — Return timer state, next scheduled run, and frequency.
        enable    — Enable and start the timer unit.
        disable   — Disable and stop the timer unit.
        configure — Write a drop-in override for OnCalendar and optionally
                    update config.json active_profile.  Requires a JSON
                    config object as the second argument.
    """
    _valid_actions = ("status", "enable", "disable", "configure")

    if not args:
        output_error(f"manage-timer requires an action: {', '.join(_valid_actions)}")
        return  # unreachable after output_error

    action = args[0]
    if action not in _valid_actions:
        output_error(f"unknown manage-timer action: {action} (expected one of {', '.join(_valid_actions)})")
        return

    if action == "status":
        output_json(_get_timer_status())
    elif action == "enable":
        _timer_enable()
    elif action == "disable":
        _timer_disable()
    else:
        _timer_configure(args)


def _update_active_profile(profile_id: str) -> None:
    """Write or update the active_profile field in config.json."""
    existing: dict[str, object] = {}
    if CONFIG_PATH.is_file():
        try:
            with CONFIG_PATH.open() as f:
                existing = json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    existing["active_profile"] = profile_id
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with CONFIG_PATH.open("w") as f:
        json.dump(existing, f, indent=2)
        f.write("\n")


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

HANDLERS: dict[str, Callable[[list[str]], None]] = {
    Command.DETECT_BACKEND: cmd_detect_backend,
    Command.LIST_PROFILES: cmd_list_profiles,
    Command.PROFILE_RULES: cmd_profile_rules,
    Command.SCAN: cmd_scan,
    Command.GENERATE_FIX: cmd_generate_fix,
    Command.APPLY_FIX: cmd_apply_fix,
    Command.MANAGE_TIMER: cmd_manage_timer,
    Command.CREATE_TAILORING: cmd_create_tailoring,
    Command.PARSE_TAILORING: cmd_parse_tailoring,
}


def main() -> None:
    """Parse argv and dispatch to the appropriate handler."""
    if len(sys.argv) < MIN_ARGC:
        output_error("usage: oscap-bridge.py <command> [args...]")
        return  # unreachable after output_error, but keeps mypy happy

    command = sys.argv[1]
    log.info("command=%s args=%s", command, sys.argv[2:])

    handler = HANDLERS.get(command)
    if handler is None:
        log.error("unknown command: %s", command)
        output_error(f"unknown command: {command}")
        return

    try:
        handler(sys.argv[2:])
        log.info("command=%s completed successfully", command)
    except SystemExit:
        raise  # let output_error's sys.exit propagate
    except subprocess.CalledProcessError as exc:
        log.error("command=%s subprocess failed: %s stderr=%s", command, exc.cmd, exc.stderr)
        output_error(f"subprocess failed: {exc.cmd}")
    except Exception:
        log.error("command=%s unhandled exception:\n%s", command, traceback.format_exc())
        output_error(f"internal error: {traceback.format_exc()}")


if __name__ == "__main__":
    main()
