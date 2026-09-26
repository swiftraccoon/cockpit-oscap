#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Cockpit OpenSCAP bridge.

A single, dependency-free script that the cockpit-oscap frontend spawns
(via ``python3 -c``) with a command name and arguments.  Every command
prints exactly one JSON document to stdout; long running commands
(``scan`` and ``remediate``) additionally stream newline-delimited JSON
progress objects before the final ``{"type": "done", ...}`` line.

Errors are reported as ``{"error": "..."}`` with exit status 1.

The script must stay compatible with Python 3.9 (RHEL 9 / CentOS Stream 9).
"""
from __future__ import annotations

import base64
import csv
import fcntl
import io
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import syslog
import tempfile
import time
import traceback
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, TypedDict

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

# ---------------------------------------------------------------------------
# Logging — goes to syslog so that problems are visible in `journalctl`
# ---------------------------------------------------------------------------


class _SyslogHandler(logging.Handler):
    """Minimal syslog handler mapping Python log levels to syslog priorities."""

    _PRIORITY_MAP: ClassVar[dict[int, int]] = {
        logging.DEBUG: syslog.LOG_DEBUG,
        logging.INFO: syslog.LOG_INFO,
        logging.WARNING: syslog.LOG_WARNING,
        logging.ERROR: syslog.LOG_ERR,
        logging.CRITICAL: syslog.LOG_CRIT,
    }

    def emit(self, record: logging.LogRecord) -> None:
        syslog.syslog(self._PRIORITY_MAP.get(record.levelno, syslog.LOG_INFO), self.format(record))


def _setup_logging() -> logging.Logger:
    syslog.openlog("cockpit-oscap", syslog.LOG_PID, syslog.LOG_DAEMON)
    logger = logging.getLogger("cockpit-oscap")
    logger.setLevel(logging.DEBUG)
    handler = _SyslogHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    return logger


log = _setup_logging()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

API_VERSION = 2

DATA_DIR = Path(os.environ.get("COCKPIT_OSCAP_DATA_DIR", "/var/lib/cockpit-oscap"))
RESULTS_DIR = DATA_DIR / "results"
TAILORING_DIR = DATA_DIR / "tailoring"
REMEDIATION_DIR = DATA_DIR / "remediation"
CONFIG_PATH = DATA_DIR / "config.json"
SCAN_STATE_PATH = DATA_DIR / "scan-state.json"
SCAN_LOCK_PATH = DATA_DIR / "scan.lock"

SSG_CONTENT_DIR = Path(os.environ.get("COCKPIT_OSCAP_CONTENT_DIR", "/usr/share/xml/scap/ssg/content"))
OS_RELEASE_PATH = Path(os.environ.get("COCKPIT_OSCAP_OS_RELEASE", "/etc/os-release"))

TIMER_UNIT = "cockpit-oscap-scan.timer"
SERVICE_UNIT = "cockpit-oscap-scan.service"
TIMER_OVERRIDE_DIR = Path(f"/etc/systemd/system/{TIMER_UNIT}.d")

DEFAULT_MAX_RESULTS = 30
MIN_MAX_RESULTS = 1
MAX_MAX_RESULTS = 500
DEFAULT_TIMER_FREQUENCY = "weekly"

CMD_TIMEOUT = 60
FIX_TIMEOUT = 300
REPORT_TIMEOUT = 300
REMEDIATE_RULE_TIMEOUT = 600

# oscap xccdf eval exit codes: 0 = all pass, 1 = error, 2 = at least one rule failed (normal)
OSCAP_EXIT_ERROR = 1
ERROR_TAIL = 800
STATE_WRITE_INTERVAL = 0.25
FIX_SYSTEM_BASH = "urn:xccdf:fix:script:sh"  # the fix system `oscap generate fix --fix-type bash` applies

RESULT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,200}$")
XCCDF_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,300}$")
WEEKDAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
MAX_DAY_OF_MONTH = 28
HOURS_PER_DAY = 24
MINUTES_PER_HOUR = 60
GROUP_CATEGORY_DEPTH = 2
REQUIRED_PAIR = 2
REQUIRED_TRIPLE = 3

# XCCDF / datastream / ARF namespaces
NS_DS = "http://scap.nist.gov/schema/scap/source/1.2"
NS_XCCDF = "http://checklists.nist.gov/xccdf/1.2"
NS_ARF = "urn:oasis:names:tc:dfi:2.0:asset-report-format:1.1"
NS_HTML = "http://www.w3.org/1999/xhtml"


def _x(tag: str) -> str:
    """Return a namespaced XCCDF tag."""
    return f"{{{NS_XCCDF}}}{tag}"


TAG_BENCHMARK = _x("Benchmark")
TAG_GROUP = _x("Group")
TAG_RULE = _x("Rule")
TAG_VALUE = _x("Value")
TAG_PROFILE = _x("Profile")
TAG_TITLE = _x("title")
TAG_DESCRIPTION = _x("description")
TAG_RATIONALE = _x("rationale")
TAG_WARNING = _x("warning")
TAG_SELECT = _x("select")
TAG_SET_VALUE = _x("set-value")
TAG_REMARK = _x("remark")
MAX_REMARK_LENGTH = 4000
MAX_VALUE_LENGTH = 4000
TAG_REFINE_VALUE = _x("refine-value")
TAG_TEST_RESULT = _x("TestResult")
TAG_TAILORING = _x("Tailoring")
TAG_RULE_RESULT = _x("rule-result")
TAG_RESULT = _x("result")
TAG_MESSAGE = _x("message")

RESULT_PASS = "pass"  # noqa: S105
RESULT_FAIL = "fail"
RESULT_ERROR = "error"
RESULT_NOTSELECTED = "notselected"
RESULT_FIXED = "fixed"
SCORED_RESULTS = (RESULT_PASS, RESULT_FAIL, RESULT_ERROR)
RESULT_KINDS = ("pass", "fail", "error", "notapplicable", "notchecked", "informational", "fixed", "unknown")

ACTION_SELECT = "select"
ACTION_UNSELECT = "unselect"
ACTION_SET_VALUE = "set-value"
ACTION_REFINE_VALUE = "refine-value"
TAILORING_ACTIONS = (ACTION_SELECT, ACTION_UNSELECT, ACTION_SET_VALUE, ACTION_REFINE_VALUE)
TAILORING_ID = "xccdf_org.cockpit-project.oscap_tailoring_default"
TAILORED_SUFFIX = "_customized"

RISK_LOW = "low"
RISK_MEDIUM = "medium"
RISK_HIGH = "high"

# ---------------------------------------------------------------------------
# Typed shapes shared with src/types.ts — keep both in sync
# ---------------------------------------------------------------------------

JsonDict = dict[str, object]


class ToolInfo(TypedDict):
    version: str
    path: str


class DatastreamInfo(TypedDict):
    path: str
    name: str
    product: str


class OsInfo(TypedDict):
    id: str
    version_id: str
    pretty_name: str


class ContentInfo(TypedDict):
    datastream_path: str
    present: bool
    source: str
    available: list[DatastreamInfo]
    os: OsInfo


class BackendInfo(TypedDict):
    api_version: int
    oscap: ToolInfo | None
    complyctl: ToolInfo | None
    content: ContentInfo
    privileged: bool
    data_dir: str


class ProfileInfo(TypedDict):
    id: str
    title: str
    description: str
    rule_count: int
    extends: str | None
    tailoring_path: str | None
    tailored_profile_id: str | None
    tailoring_problem: str


class RuleInfo(TypedDict):
    id: str
    title: str
    severity: str
    description: str
    selected: bool
    group: str
    group_path: list[str]
    has_fix: bool


class ValueOption(TypedDict):
    selector: str
    value: str


class ValueInfo(TypedDict):
    id: str
    title: str
    description: str
    type: str
    default: str
    value: str
    selector: str
    set_value: str | None
    options: list[ValueOption]


class ProfileRules(TypedDict):
    profile_id: str
    title: str
    rules: list[RuleInfo]
    values: list[ValueInfo]


class Reference(TypedDict):
    href: str
    text: str


class Ident(TypedDict):
    system: str
    text: str


class RuleDetail(TypedDict):
    id: str
    title: str
    severity: str
    description: str
    rationale: str
    warnings: list[str]
    references: list[Reference]
    idents: list[Ident]
    group_path: list[str]
    has_fix: bool
    fix_systems: list[str]
    #: the rule was described from the configured content because the requested one is gone
    content_substituted: bool


class RuleResultItem(TypedDict):
    rule_id: str
    result: str
    title: str
    severity: str
    group: str
    message: str


class RuleHistoryPoint(TypedDict):
    """One scan of a profile and how a rule fared in it."""

    id: str
    timestamp: str
    score: float
    result: str  # "notselected" when the scan skipped the rule


class RuleExclusion(TypedDict):
    """A rule the customization disabled for this scan, with the justification recorded with it."""

    rule_id: str
    title: str
    remark: str


class ScanResult(TypedDict):
    id: str
    timestamp: str
    start_time: str
    end_time: str
    profile_id: str
    profile_title: str
    base_profile_id: str
    benchmark_id: str
    benchmark_version: str
    datastream: str
    tailoring_path: str | None
    tailored: bool
    test_result_id: str
    status: str
    score: float
    xccdf_score: float | None
    counts: dict[str, int]
    results: list[RuleResultItem]
    exclusions: list[RuleExclusion]
    # not stored: the rules the profile's customization disables today (get-result fills it in)
    currently_excluded: list[str]
    arf_path: str
    json_path: str


class ResultSummary(TypedDict):
    id: str
    timestamp: str
    profile_id: str
    base_profile_id: str
    datastream: str
    #: wall-clock seconds the evaluation took, 0 when unknown
    duration_seconds: int
    profile_title: str
    score: float
    counts: dict[str, int]
    total: int
    status: str
    tailored: bool
    has_arf: bool


class FixRuleInfo(TypedDict):
    id: str
    title: str
    fix_snippet: str
    risk_level: str
    risk_reason: str
    has_fix: bool


class FixInfo(TypedDict):
    result_id: str
    fix_type: str
    script: str
    rules: list[FixRuleInfo]


class RuleRemediation(TypedDict):
    rule_id: str
    success: bool
    exit_status: int
    output: str
    errors: str


class RemediateResult(TypedDict):
    result_id: str
    success: bool
    script_path: str
    rules: list[RuleRemediation]


class TailoringModification(TypedDict, total=False):
    idref: str
    action: str
    value: str
    selector: str
    remark: str  # why a rule was enabled or disabled (an XCCDF <remark> on the <select>)


class TailoringInfo(TypedDict):
    path: str
    profile_id: str
    base_profile_id: str
    title: str
    benchmark_href: str
    modifications: list[TailoringModification]
    tailoring_xml: str
    warning: str


class TimerStatus(TypedDict):
    status: str
    enabled: bool
    installed: bool
    next_run: str
    last_run: str
    calendar: str
    service_state: str
    service_result: str
    last_scan_finished: str


class CalendarCheck(TypedDict):
    valid: bool
    normalized: str
    next_elapse: str
    error: str


class Config(TypedDict, total=False):
    active_profile: str
    datastream: str
    max_results: int
    tailorings: dict[str, str]


class BridgeError(Exception):
    """A user-facing error; reported as ``{"error": message}`` with exit status 1."""


# ---------------------------------------------------------------------------
# Output and subprocess helpers
# ---------------------------------------------------------------------------


def output_json(data: object) -> None:
    """Write one JSON document (plus newline) to stdout."""
    sys.stdout.write(json.dumps(data))
    sys.stdout.write("\n")
    sys.stdout.flush()


def output_error(message: str) -> None:
    """Write an error JSON document to stdout and exit with status 1."""
    log.error("error: %s", message)
    output_json({"error": message})
    sys.exit(1)


def _silence_stdout() -> None:
    """Point stdout at /dev/null once the reader has gone away, so interpreter shutdown does not fail again."""
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        os.close(devnull)
    except OSError:
        pass


def run_cmd(argv: list[str], *, timeout: int = CMD_TIMEOUT) -> tuple[int, str, str]:
    """Run a command and return (exit status, stdout, stderr)."""
    try:
        result = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=timeout)
    except FileNotFoundError as exc:
        raise BridgeError(f"{argv[0]}: command not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise BridgeError(f"{argv[0]} timed out after {timeout} seconds") from exc
    return result.returncode, result.stdout, result.stderr


def _now_utc() -> datetime:
    return datetime.now(tz=timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


def _ensure_dir(path: Path) -> None:
    try:
        path.mkdir(parents=True, exist_ok=True)
    except PermissionError as exc:
        raise BridgeError(f"administrative access is required to write to {path}") from exc


def _atomic_write(path: Path, content: str, mode: int = 0o644) -> None:
    """Write a file atomically (temporary file + rename); the mode is set before the file appears."""
    _ensure_dir(path.parent)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
        Path(tmp_name).chmod(mode)
        Path(tmp_name).replace(path)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise


def _read_json_file(path: Path, *, raise_permission: bool = False) -> JsonDict | None:
    """Read a JSON object from a file; return None when missing or invalid.

    With ``raise_permission`` a file the caller may not read raises ``PermissionError``
    instead of being treated as absent, so callers can tell "no data" from "not allowed".
    """
    try:
        with path.open() as f:
            data = json.load(f)
    except PermissionError:
        if raise_permission:
            raise
        return None
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _parse_json_arg(text: str, what: str) -> object:
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise BridgeError(f"invalid {what} JSON: {exc}") from exc


_VALUE_OPTIONS = frozenset((
    "--datastream", "--tailoring-path", "--rules", "--source", "--type", "--rescan-of", "--remark", "--limit"))


def _opt(args: list[str], name: str) -> str | None:
    """Return the value following ``--name`` in args, or None; another option's value never counts."""
    if name not in _VALUE_OPTIONS:
        raise ValueError(f"{name} is not an option with a value")
    skip = False
    for i, arg in enumerate(args):
        if skip:
            skip = False
        elif arg in _VALUE_OPTIONS:
            if arg == name:
                return args[i + 1] if i + 1 < len(args) else None
            skip = True
    return None


def _positional(args: list[str]) -> list[str]:
    """Return the positional (non ``--option value``) arguments."""
    result: list[str] = []
    skip = False
    for arg in args:
        if skip:
            skip = False
        elif arg.startswith("--"):
            skip = arg in _VALUE_OPTIONS
        else:
            result.append(arg)
    return result


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def load_config() -> Config:
    """Read config.json, migrating legacy keys, tolerating a missing/invalid file."""
    raw = _read_json_file(CONFIG_PATH) or {}
    config: Config = {}

    active = raw.get("active_profile")
    if isinstance(active, str) and active:
        config["active_profile"] = active
    datastream = raw.get("datastream")
    if isinstance(datastream, str) and datastream:
        config["datastream"] = datastream
    max_results = raw.get("max_results")
    if isinstance(max_results, int) and MIN_MAX_RESULTS <= max_results <= MAX_MAX_RESULTS:
        config["max_results"] = max_results

    tailorings: dict[str, str] = {}
    raw_tailorings = raw.get("tailorings")
    if isinstance(raw_tailorings, dict):
        tailorings.update({k: v for k, v in raw_tailorings.items() if isinstance(k, str) and isinstance(v, str)})
    # legacy layout: "tailoring_<profile id>": "<path>"
    for key, value in raw.items():
        if key.startswith("tailoring_") and isinstance(value, str):
            tailorings.setdefault(key[len("tailoring_"):], value)
    if tailorings:
        config["tailorings"] = tailorings
    return config


def save_config(config: Config) -> None:
    _atomic_write(CONFIG_PATH, json.dumps(config, indent=2, sort_keys=True) + "\n")


def _config_patch(config: Config, patch: JsonDict) -> Config:
    """Apply a JSON patch (null deletes a key) to the user-editable config keys."""
    for key, value in patch.items():
        if key in ("active_profile", "datastream"):
            if value is None or value == "":
                config.pop(key, None)  # type: ignore[misc]
            elif isinstance(value, str):
                if key == "active_profile" and not XCCDF_ID_RE.match(value):
                    raise BridgeError(f"invalid profile id: {value}")
                config[key] = value  # type: ignore[literal-required]
            else:
                raise BridgeError(f"{key} must be a string")
        elif key == "max_results":
            if value is None:
                config.pop("max_results", None)
            elif isinstance(value, int) and not isinstance(value, bool) and \
                    MIN_MAX_RESULTS <= value <= MAX_MAX_RESULTS:
                config["max_results"] = value
            else:
                raise BridgeError(f"max_results must be an integer between {MIN_MAX_RESULTS} and {MAX_MAX_RESULTS}")
        else:
            raise BridgeError(f"unknown configuration key: {key}")
    return config


def cmd_get_config(_args: list[str]) -> None:
    output_json(load_config())


def cmd_set_config(args: list[str]) -> None:
    if not args:
        raise BridgeError("set-config requires a JSON object argument")
    patch = _parse_json_arg(args[0], "configuration")
    if not isinstance(patch, dict):
        raise BridgeError("configuration patch must be a JSON object")
    config = _config_patch(load_config(), patch)
    save_config(config)
    output_json(config)


# ---------------------------------------------------------------------------
# Backend / content detection
# ---------------------------------------------------------------------------


def _read_os_release() -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        text = OS_RELEASE_PATH.read_text()
    except OSError:
        return values
    for line in text.splitlines():
        if "=" not in line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def _candidate_products(os_release: dict[str, str]) -> list[str]:
    """Return SSG product names that match this OS, most specific first."""
    os_id = os_release.get("ID", "").lower()
    version = os_release.get("VERSION_ID", "")
    major = version.split(".")[0]
    compact = version.replace(".", "")
    candidates: list[str] = []

    def add(*names: str) -> None:
        for name in names:
            if name and name not in candidates:
                candidates.append(name)

    products = {
        "fedora": ["fedora"],
        "rhel": [f"rhel{major}"],
        "centos": [f"cs{major}", f"centos{major}", f"rhel{major}"],
        "almalinux": [f"almalinux{major}", f"rhel{major}"],
        "rocky": [f"rl{major}", f"rocky{major}", f"rhel{major}"],
        "ol": [f"ol{major}"],
        "debian": [f"debian{major}"],
        "ubuntu": [f"ubuntu{compact}"],
        "suse": ["opensuse"],
        "sles": [f"sle{major}"],
        "sled": [f"sle{major}"],
        "sle_hpc": [f"sle{major}"],
        "amzn": ["al2023" if major == "2023" else f"amzn{major}"],
    }
    for ident in [os_id, *os_release.get("ID_LIKE", "").lower().split()]:
        if ident != os_id and ident in ("debian", "ubuntu"):
            continue  # derivatives do not share Debian/Ubuntu version numbers
        key = "suse" if ident.startswith("opensuse") else ident
        add(*products.get(key, []))
    return candidates


def _natural_key(text: str) -> list[object]:
    return [int(part) if part.isdigit() else part for part in re.split(r"(\d+)", text)]


def _available_datastreams() -> list[DatastreamInfo]:
    found: list[DatastreamInfo] = []
    if not SSG_CONTENT_DIR.is_dir():
        return found
    for path in sorted(SSG_CONTENT_DIR.glob("ssg-*-ds.xml"), key=lambda p: _natural_key(p.name)):
        product = path.name[len("ssg-"):-len("-ds.xml")]
        found.append(DatastreamInfo(path=str(path), name=path.name, product=product))
    return found


def detect_content(config: Config | None = None) -> ContentInfo:
    """Pick the SCAP datastream for this system (config override > OS match > any)."""
    config = load_config() if config is None else config
    os_release = _read_os_release()
    available = _available_datastreams()
    os_info = OsInfo(
        id=os_release.get("ID", ""),
        version_id=os_release.get("VERSION_ID", ""),
        pretty_name=os_release.get("PRETTY_NAME", ""),
    )

    override = config.get("datastream")
    if override and Path(override).is_file():
        return ContentInfo(datastream_path=override, present=True, source="config", available=available, os=os_info)

    by_product = {ds["product"]: ds for ds in available}
    for product in _candidate_products(os_release):
        if product in by_product:
            path = by_product[product]["path"]
            return ContentInfo(datastream_path=path, present=True, source="detected", available=available, os=os_info)

    if available:
        # no content matches this OS: fall back to the newest product shipped on the system
        path = available[-1]["path"]
        return ContentInfo(datastream_path=path, present=True, source="fallback", available=available, os=os_info)

    return ContentInfo(datastream_path="", present=False, source="none", available=available, os=os_info)


def resolve_datastream(explicit: str | None, config: Config | None = None) -> str:
    """Return the datastream path to use, validating that it exists."""
    if explicit:
        if not Path(explicit).is_file():
            raise BridgeError(f"datastream not found: {explicit}")
        return explicit
    content = detect_content(config)
    if not content["present"]:
        raise BridgeError("no SCAP content found; install scap-security-guide")
    return content["datastream_path"]


def get_oscap_info() -> ToolInfo | None:
    oscap_path = shutil.which("oscap")
    if oscap_path is None:
        return None
    rc, stdout, _stderr = run_cmd([oscap_path, "--version"])
    version = "unknown"
    if rc == 0:
        for line in stdout.splitlines():
            if "(oscap)" in line:
                version = line.strip().split()[-1]
                break
    return ToolInfo(version=version, path=oscap_path)


def get_complyctl_info() -> ToolInfo | None:
    path = shutil.which("complyctl")
    if path is None:
        return None
    try:
        rc, stdout, _stderr = run_cmd([path, "version"])
    except BridgeError:
        return ToolInfo(version="unknown", path=path)
    version = stdout.strip().splitlines()[0] if rc == 0 and stdout.strip() else "unknown"
    return ToolInfo(version=version, path=path)


def _require_oscap() -> str:
    path = shutil.which("oscap")
    if path is None:
        raise BridgeError("oscap binary not found; install openscap-scanner")
    return path


def cmd_detect_backend(_args: list[str]) -> None:
    if DATA_DIR.is_dir() and os.access(DATA_DIR, os.W_OK):
        reconcile_scan_state()
    output_json(BackendInfo(
        api_version=API_VERSION,
        oscap=get_oscap_info(),
        complyctl=get_complyctl_info(),
        content=detect_content(),
        privileged=os.geteuid() == 0,
        data_dir=str(DATA_DIR),
    ))


# ---------------------------------------------------------------------------
# XCCDF parsing
# ---------------------------------------------------------------------------


def _xml_true(value: str | None) -> bool:
    """An xs:boolean attribute ("true"/"1", "false"/"0"); absent means true, as for XCCDF selected."""
    return value is None or value.strip() in ("true", "1")


def _text(el: ET.Element | None) -> str:
    """Return the element's text content on one line, with whitespace collapsed."""
    return " ".join(_rich_text(el).split())


_BLOCK_TAGS = {f"{{{NS_HTML}}}{t}": "\n\n" for t in ("p", "pre", "ul", "ol", "div", "table", "blockquote")}
_BLOCK_TAGS.update({f"{{{NS_HTML}}}{t}": "\n" for t in ("li", "br", "tr")})


def _rich_text(el: ET.Element | None) -> str:
    """Return text content, preserving paragraph breaks from embedded XHTML."""
    if el is None:
        return ""
    parts: list[str] = []

    def walk(node: ET.Element) -> None:
        separator = _BLOCK_TAGS.get(node.tag, "")
        parts.append(separator)
        if node.text:
            parts.append(node.text)
        for child in node:
            walk(child)
            if child.tail:
                parts.append(child.tail)
        parts.append(separator)

    walk(el)
    lines = [" ".join(line.split()) for line in "".join(parts).split("\n")]
    text = "\n".join(lines)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def load_benchmark(ds_path: str) -> ET.Element:
    """Parse a source datastream (or bare XCCDF file) and return its Benchmark element.

    Parsing stops as soon as the Benchmark element is complete, which skips the
    (much larger) OVAL components that follow it in SSG datastreams.
    """
    try:
        elem: ET.Element
        for _event, elem in ET.iterparse(ds_path, events=("end",)):  # noqa: S314
            if elem.tag == TAG_BENCHMARK:
                return elem
    except ET.ParseError as exc:
        raise BridgeError(f"failed to parse {ds_path}: {exc}") from exc
    except OSError as exc:
        raise BridgeError(f"cannot read {ds_path}: {exc}") from exc
    raise BridgeError(f"no XCCDF benchmark found in {ds_path}")


def _find_profile(benchmark: ET.Element, profile_id: str) -> ET.Element | None:
    for prof in benchmark.findall(TAG_PROFILE):
        if prof.get("id") == profile_id:
            return prof
    return None


class _BenchmarkIndex:
    """Lookup tables derived from a Benchmark: rules, groups and values."""

    def __init__(self, benchmark: ET.Element) -> None:
        self.benchmark = benchmark
        self.rules: dict[str, ET.Element] = {}
        self.groups: dict[str, ET.Element] = {}
        self.values: dict[str, ET.Element] = {}
        self.group_path: dict[str, list[str]] = {}
        self.group_rules: dict[str, list[str]] = {}
        self.rule_groups: dict[str, list[str]] = {}  # the groups above a rule, outermost first
        self._walk(benchmark, [], [])

    def _walk(self, node: ET.Element, path: list[str], group_ids: list[str]) -> None:
        for child in node:
            if child.tag == TAG_GROUP:
                gid = child.get("id", "")
                self.groups[gid] = child
                self.group_rules.setdefault(gid, [])
                self._walk(child, [*path, _text(child.find(TAG_TITLE))], [*group_ids, gid])
            elif child.tag == TAG_RULE:
                rid = child.get("id", "")
                self.rules[rid] = child
                self.group_path[rid] = path
                self.rule_groups[rid] = group_ids
                for gid in group_ids:
                    self.group_rules[gid].append(rid)
            elif child.tag == TAG_VALUE:
                self.values[child.get("id", "")] = child

    def category(self, rule_id: str) -> str:
        path = self.group_path.get(rule_id, [])
        if len(path) >= GROUP_CATEGORY_DEPTH:
            return path[GROUP_CATEGORY_DEPTH - 1]
        return path[0] if path else ""

    def profile_chain(self, profile_id: str) -> list[ET.Element]:
        """A profile and the profiles it extends, outermost ancestor first."""
        chain: list[ET.Element] = []
        seen: set[str] = set()
        current: str | None = profile_id
        while current and current not in seen:
            seen.add(current)
            profile = _find_profile(self.benchmark, current)
            if profile is None:
                break
            chain.append(profile)
            current = profile.get("extends")
        chain.reverse()
        return chain

    def selection(self, profile_id: str, extra_selects: Iterable[ET.Element] = ()) -> dict[str, bool]:
        """Rule id -> whether a scan of the profile evaluates it, decided as the scanner does.

        Every rule and group starts from its own ``selected`` attribute; the selects of the profile
        chain (ancestors first) and then ``extra_selects`` (a tailoring's) override the item they
        name, the last one winning. A rule is evaluated only when it and every group above it are
        selected: switching a group on does not reach a rule that is off by itself, and a rule
        switched on inside a group that is off stays skipped.
        """
        state = {rid: _xml_true(rule.get("selected")) for rid, rule in self.rules.items()}
        state.update({gid: _xml_true(group.get("selected")) for gid, group in self.groups.items()})
        selects = [sel for profile in self.profile_chain(profile_id) for sel in profile.findall(TAG_SELECT)]
        for sel in [*selects, *extra_selects]:
            idref = sel.get("idref", "")
            if idref in state:
                state[idref] = _xml_true(sel.get("selected"))
        return {rid: state[rid] and all(state[gid] for gid in self.rule_groups[rid]) for rid in self.rules}

    def profile_values(self, profile_id: str) -> tuple[dict[str, str], dict[str, str]]:
        """Return (refine-value selectors, set-values) for a profile, honouring ``extends``."""
        selectors: dict[str, str] = {}
        set_values: dict[str, str] = {}
        chain: list[ET.Element] = []
        pid: str | None = profile_id
        seen: set[str] = set()
        while pid and pid not in seen:
            seen.add(pid)
            prof = _find_profile(self.benchmark, pid)
            if prof is None:
                break
            chain.insert(0, prof)
            pid = prof.get("extends")
        for prof in chain:
            for rv in prof.findall(TAG_REFINE_VALUE):
                selectors[rv.get("idref", "")] = rv.get("selector", "")
            for sv in prof.findall(TAG_SET_VALUE):
                set_values[sv.get("idref", "")] = (sv.text or "").strip()
        return selectors, set_values

    def value_refs(self, rule_id: str) -> set[str]:
        """Return the Value ids exported to a rule's checks."""
        rule = self.rules.get(rule_id)
        if rule is None:
            return set()
        return {
            export.get("value-id", "")
            for check in rule.findall(_x("check"))
            for export in check.findall(_x("check-export"))
            if export.get("value-id")
        }


def _has_bash_fix(rule: ET.Element) -> bool:
    """Whether the rule ships the fix this plugin can apply (``oscap generate fix --fix-type bash``)."""
    return any(fix.get("system") == FIX_SYSTEM_BASH for fix in rule.findall(_x("fix")))


def _rule_info(index: _BenchmarkIndex, rule_id: str, *, selected: bool) -> RuleInfo:
    rule = index.rules[rule_id]
    return RuleInfo(
        id=rule_id,
        title=_text(rule.find(TAG_TITLE)),
        severity=rule.get("severity", "unknown"),
        description=_rich_text(rule.find(TAG_DESCRIPTION)),
        selected=selected,
        group=index.category(rule_id),
        group_path=index.group_path.get(rule_id, []),
        has_fix=_has_bash_fix(rule),
    )


def _value_info(value: ET.Element, selector: str, set_value: str | None) -> ValueInfo:
    options: list[ValueOption] = []
    default = ""
    for v in value.findall(_x("value")):
        sel = v.get("selector", "")
        text = (v.text or "").strip()
        if sel:
            options.append(ValueOption(selector=sel, value=text))
        else:
            default = text
    effective = default
    if set_value is not None:
        effective = set_value
    elif selector:
        effective = next((o["value"] for o in options if o["selector"] == selector), default)
    return ValueInfo(
        id=value.get("id", ""),
        title=_text(value.find(TAG_TITLE)),
        description=_rich_text(value.find(TAG_DESCRIPTION)),
        type=value.get("type", "string"),
        default=default,
        value=effective,
        selector=selector,
        set_value=set_value,
        options=options,
    )


def list_profiles(ds_path: str, config: Config) -> list[ProfileInfo]:
    benchmark = load_benchmark(ds_path)
    index = _BenchmarkIndex(benchmark)
    profiles: list[ProfileInfo] = []
    for prof in benchmark.findall(TAG_PROFILE):
        pid = prof.get("id", "")
        if not pid or prof.get("abstract") == "true":
            continue
        tailoring, tailoring_path, problem = _registered_tailoring(config, pid, benchmark, ds_path, quiet=True)
        profiles.append(ProfileInfo(
            id=pid,
            title=_text(prof.find(TAG_TITLE)),
            description=_rich_text(prof.find(TAG_DESCRIPTION)),
            rule_count=sum(1 for v in index.selection(pid).values() if v),
            extends=prof.get("extends"),
            tailoring_path=tailoring_path,
            tailored_profile_id=tailoring["profile_id"] if tailoring else None,
            tailoring_problem=problem,
        ))
    return profiles


def profile_rules(ds_path: str, profile_id: str) -> ProfileRules:
    benchmark = load_benchmark(ds_path)
    index = _BenchmarkIndex(benchmark)
    profile = _find_profile(benchmark, profile_id)
    if profile is None:
        raise BridgeError(f"profile not found in datastream: {profile_id}")

    selection = index.selection(profile_id)
    rules = [_rule_info(index, rid, selected=selection.get(rid, False)) for rid in index.rules]

    selectors, set_values = index.profile_values(profile_id)
    referenced: set[str] = set(selectors) | set(set_values)
    for rid, is_selected in selection.items():
        if is_selected:
            referenced |= index.value_refs(rid)
    values = [
        _value_info(index.values[vid], selectors.get(vid, ""), set_values.get(vid))
        for vid in sorted(referenced) if vid in index.values
    ]
    values.sort(key=lambda v: v["title"].lower())
    return ProfileRules(profile_id=profile_id, title=_text(profile.find(TAG_TITLE)), rules=rules, values=values)


def rule_detail(ds_path: str, rule_id: str) -> RuleDetail:
    benchmark = load_benchmark(ds_path)
    index = _BenchmarkIndex(benchmark)
    rule = index.rules.get(rule_id)
    if rule is None:
        raise BridgeError(f"rule not found: {rule_id}")
    fixes = rule.findall(_x("fix"))
    return RuleDetail(
        id=rule_id,
        title=_text(rule.find(TAG_TITLE)),
        severity=rule.get("severity", "unknown"),
        description=_rich_text(rule.find(TAG_DESCRIPTION)),
        rationale=_rich_text(rule.find(TAG_RATIONALE)),
        warnings=[_rich_text(w) for w in rule.findall(TAG_WARNING)],
        references=[Reference(href=r.get("href", ""), text=_text(r)) for r in rule.findall(_x("reference"))],
        idents=[Ident(system=i.get("system", ""), text=_text(i)) for i in rule.findall(_x("ident"))],
        group_path=index.group_path.get(rule_id, []),
        has_fix=_has_bash_fix(rule),
        fix_systems=sorted({f.get("system", "") for f in fixes}),
        content_substituted=False,
    )


def cmd_list_profiles(args: list[str]) -> None:
    config = load_config()
    positional = _positional(args)
    ds_path = resolve_datastream(_opt(args, "--datastream") or (positional[0] if positional else None), config)
    output_json(list_profiles(ds_path, config))


def cmd_profile_rules(args: list[str]) -> None:
    positional = _positional(args)
    if not positional:
        raise BridgeError("profile-rules requires a profile id argument")
    ds_path = resolve_datastream(_opt(args, "--datastream") or (positional[1] if len(positional) > 1 else None))
    output_json(profile_rules(ds_path, positional[0]))


def cmd_rule_info(args: list[str]) -> None:
    positional = _positional(args)
    if not positional:
        raise BridgeError("rule-info requires a rule id argument")
    requested = _opt(args, "--datastream")
    substituted = False
    if requested:
        try:
            Path(requested).stat()
        except FileNotFoundError:
            # results record the content they were scanned with; once it is gone the configured
            # content still describes the rule (ids are shared across SSG products)
            log.info("datastream %s is gone; describing %s from the configured content", requested, positional[0])
            requested = None
            substituted = True
        except OSError as exc:
            raise BridgeError(f"cannot read datastream {requested}: {exc}") from exc
    ds_path = resolve_datastream(requested)
    try:
        detail = rule_detail(ds_path, positional[0])
    except BridgeError as exc:
        if not substituted:
            raise
        raise BridgeError(f"the content this scan used, {Path(_opt(args, '--datastream') or '').name}, is no longer "
                          f"installed and {Path(ds_path).name} does not describe this rule ({exc})") from exc
    detail["content_substituted"] = substituted
    output_json(detail)


# ---------------------------------------------------------------------------
# Tailoring
# ---------------------------------------------------------------------------


def _profile_short_name(profile_id: str) -> str:
    """xccdf_org.ssgproject.content_profile_ospp -> ospp."""
    match = re.search(r"_profile_(.+)$", profile_id)
    return match.group(1) if match else profile_id.rsplit("_", maxsplit=1)[-1]


def _tailoring_path_for(base_profile_id: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", _profile_short_name(base_profile_id))
    return TAILORING_DIR / f"{safe}-tailoring.xml"


# control characters XML 1.0 cannot carry, and lone surrogates (JSON can encode them, UTF-8 cannot)
_XML_UNSAFE_RE = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]")


def _validate_xml_text(raw: object, what: str, max_length: int) -> str:
    """Text destined for an XML document: a string without characters XML 1.0 cannot carry."""
    if not isinstance(raw, str):
        raise BridgeError(f"{what} must be a string")
    if len(raw) > max_length:
        raise BridgeError(f"{what} may have at most {max_length} characters")
    if _XML_UNSAFE_RE.search(raw):
        raise BridgeError(f"{what} may not contain control characters")
    return raw


def _validate_remark(raw: object) -> str:
    """A rule's justification with its whitespace collapsed, empty when there is none."""
    return " ".join(_validate_xml_text(raw, "a remark", MAX_REMARK_LENGTH).split())


def _validate_modifications(raw: object) -> list[TailoringModification]:
    if not isinstance(raw, list):
        raise BridgeError("modifications must be a JSON array")
    mods: list[TailoringModification] = []
    for item in raw:
        if not isinstance(item, dict):
            raise BridgeError("each modification must be a JSON object")
        idref = item.get("idref") or item.get("rule_id")
        action = item.get("action")
        if not isinstance(idref, str) or not XCCDF_ID_RE.match(idref):
            raise BridgeError(f"invalid modification idref: {idref!r}")
        if action not in TAILORING_ACTIONS:
            raise BridgeError(f"invalid modification action: {action!r}")
        mod = TailoringModification(idref=idref, action=action)
        if action in (ACTION_SELECT, ACTION_UNSELECT):
            remark = _validate_remark(item.get("remark", ""))
            if remark:
                mod["remark"] = remark
        elif action == ACTION_SET_VALUE:
            mod["value"] = _validate_xml_text(item.get("value", ""), "a value", MAX_VALUE_LENGTH)
        elif action == ACTION_REFINE_VALUE:
            selector = item.get("selector", "")
            if not isinstance(selector, str) or not selector:
                raise BridgeError("refine-value requires a selector")
            mod["selector"] = selector
        mods.append(mod)
    return mods


def build_tailoring_xml(
    base_profile_id: str,
    base_title: str,
    modifications: list[TailoringModification],
    datastream: str,
) -> tuple[str, str]:
    """Return (tailored profile id, XCCDF 1.2 tailoring XML)."""
    tailoring = ET.Element(TAG_TAILORING, {"id": TAILORING_ID})
    ET.SubElement(tailoring, _x("benchmark"), {"href": datastream})
    version = ET.SubElement(tailoring, _x("version"), {"time": _iso(_now_utc())})
    version.text = "1"

    profile_id = f"{base_profile_id}{TAILORED_SUFFIX}"
    profile = ET.SubElement(tailoring, TAG_PROFILE, {"id": profile_id, "extends": base_profile_id})
    title = ET.SubElement(profile, TAG_TITLE)
    title.text = f"{base_title or _profile_short_name(base_profile_id)} (customized)"

    for mod in modifications:
        action = mod["action"]
        idref = mod["idref"]
        if action in (ACTION_SELECT, ACTION_UNSELECT):
            selected = str(action == ACTION_SELECT).lower()
            select = ET.SubElement(profile, TAG_SELECT, {"idref": idref, "selected": selected})
            if mod.get("remark"):
                ET.SubElement(select, TAG_REMARK).text = mod["remark"]
        elif action == ACTION_SET_VALUE:
            ET.SubElement(profile, TAG_SET_VALUE, {"idref": idref}).text = mod.get("value", "")
        elif action == ACTION_REFINE_VALUE:
            ET.SubElement(profile, TAG_REFINE_VALUE, {"idref": idref, "selector": mod.get("selector", "")})

    return profile_id, _serialize_tailoring(tailoring)


def _serialize_tailoring(root: ET.Element) -> str:
    ET.register_namespace("xccdf", NS_XCCDF)
    ET.indent(root)
    return f'<?xml version="1.0" encoding="UTF-8"?>\n{ET.tostring(root, encoding="unicode")}\n'


def _select_remark(sel: ET.Element) -> str:
    """A select's justification; SCAP Workbench and other tools may attach several remarks."""
    return " ".join(filter(None, (_text(r) for r in sel.findall(TAG_REMARK))))


# the elements a Profile may hold between its title and any trailing metadata or signature
_PROFILE_CHOICE_TAGS = frozenset(
    (TAG_SELECT, TAG_SET_VALUE, TAG_REFINE_VALUE, _x("refine-rule"), _x("set-complex-value")))


def _edit_tailoring_select(xml_text: str, rule_id: str, *, selected: bool, remark: str) -> str:
    """The tailoring document with one rule's select replaced; everything else stays as it was."""
    root = ET.fromstring(xml_text)  # noqa: S314  (the caller parsed it already)
    profile = root.find(TAG_PROFILE)
    if profile is None:
        raise BridgeError("tailoring document does not contain a Profile element")
    for old in profile.findall(TAG_SELECT):
        if old.get("idref") == rule_id:
            profile.remove(old)
    select = ET.Element(TAG_SELECT, {"idref": rule_id, "selected": str(selected).lower()})
    if remark:
        ET.SubElement(select, TAG_REMARK).text = remark
    # after the last select/refine element, else before metadata or a signature, else last
    children = list(profile)
    choices = [i for i, child in enumerate(children) if child.tag in _PROFILE_CHOICE_TAGS]
    trailing = [i for i, child in enumerate(children)
                if child.tag == _x("metadata") or child.tag.endswith("}Signature")]
    profile.insert(choices[-1] + 1 if choices else trailing[0] if trailing else len(children), select)
    version = root.find(_x("version"))
    if version is not None:
        version.set("time", _iso(_now_utc()))
    return _serialize_tailoring(root)


def parse_tailoring_xml(xml_text: str, path: str = "") -> TailoringInfo:
    try:
        root = ET.fromstring(xml_text)  # noqa: S314
    except ET.ParseError as exc:
        raise BridgeError(f"invalid tailoring XML: {exc}") from exc
    if root.tag != TAG_TAILORING:
        raise BridgeError("not an XCCDF 1.2 tailoring document")
    profile = root.find(TAG_PROFILE)
    if profile is None:
        raise BridgeError("tailoring document does not contain a Profile element")

    modifications: list[TailoringModification] = []
    for sel in profile.findall(TAG_SELECT):
        action = ACTION_SELECT if _xml_true(sel.get("selected")) else ACTION_UNSELECT
        mod = TailoringModification(idref=sel.get("idref", ""), action=action)
        remark = _select_remark(sel)
        if remark:
            mod["remark"] = remark
        modifications.append(mod)
    for rv in profile.findall(TAG_REFINE_VALUE):
        modifications.append(TailoringModification(
            idref=rv.get("idref", ""), action=ACTION_REFINE_VALUE, selector=rv.get("selector", "")))
    for sv in profile.findall(TAG_SET_VALUE):
        modifications.append(TailoringModification(
            idref=sv.get("idref", ""), action=ACTION_SET_VALUE, value=(sv.text or "").strip()))

    bench = root.find(_x("benchmark"))
    return TailoringInfo(
        path=path,
        profile_id=profile.get("id", ""),
        base_profile_id=profile.get("extends", ""),
        title=_text(profile.find(TAG_TITLE)),
        benchmark_href=bench.get("href", "") if bench is not None else "",
        modifications=modifications,
        tailoring_xml=xml_text,
        warning="",
    )


def parse_tailoring_file(path: str) -> TailoringInfo:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, ValueError) as exc:  # ValueError: not UTF-8
        raise BridgeError(f"cannot read tailoring file {path}: {exc}") from exc
    return parse_tailoring_xml(text, path)


def _content_stem(name: str) -> str:
    """ssg-rhel9-ds-1.2.xml, ssg-rhel9-ds.xml and ssg-rhel9-xccdf.xml all describe the same content."""
    return re.sub(r"(?:-(?:ds|xccdf))?(?:-1\.2)?$", "", Path(name).stem)


def _href_mismatch(tailoring: TailoringInfo, ds_path: str) -> str:
    """A note when the tailoring names other SCAP content than ``ds_path``, or "" (an href is only a hint)."""
    href = tailoring["benchmark_href"].strip()
    if not href or not href.lower().endswith(".xml") or _content_stem(href) == _content_stem(ds_path):
        return ""
    return f"It was created for {Path(href).name}; scans on this system use {Path(ds_path).name}."


def _tailoring_problem(tailoring: TailoringInfo, benchmark: ET.Element, ds_path: str) -> str:
    """Why oscap could not evaluate this tailoring against the content in ``ds_path``, or "" when it can.

    Rule ids are shared across SSG products (RHEL, CentOS Stream, Alma, ...), so a different
    datastream name is not a problem by itself; a base profile that does not exist is.
    """
    base = tailoring["base_profile_id"]
    if base and _find_profile(benchmark, base) is None:
        return f"It customizes the profile {base}, which is not part of {Path(ds_path).name}."
    return ""


def _registered_tailoring(config: Config, base_profile_id: str, benchmark: ET.Element, ds_path: str, *,
                          quiet: bool = False) -> tuple[TailoringInfo | None, str | None, str]:
    """(usable tailoring, registered file, problem) for a profile.

    The file is reported even when the tailoring cannot be used, so the UI can show why and offer
    to remove it; ``problem`` is "" when the tailoring applies.
    """
    path = config.get("tailorings", {}).get(base_profile_id)
    if not path or not Path(path).is_file():
        return None, None, ""
    try:
        info = parse_tailoring_file(path)
    except BridgeError as exc:
        problem = f"The customization file cannot be read: {exc}."
    else:
        problem = _tailoring_problem(info, benchmark, ds_path)
        if not problem:
            note = _href_mismatch(info, ds_path)
            if note and not quiet:
                log.info("tailoring %s: %s", path, note)
            return info, path, ""
    (log.debug if quiet else log.warning)("ignoring tailoring %s: %s", path, problem)
    return None, path, problem


def _register_tailoring(base_profile_id: str, path: Path) -> None:
    config = load_config()
    tailorings = config.setdefault("tailorings", {})
    tailorings[base_profile_id] = str(path)
    save_config(config)


def cmd_create_tailoring(args: list[str]) -> None:
    positional = _positional(args)
    if len(positional) < REQUIRED_PAIR:
        raise BridgeError("create-tailoring requires a base profile id and a modifications JSON array")
    base_profile_id = positional[0]
    modifications = _validate_modifications(_parse_json_arg(positional[1], "modifications"))
    ds_path = resolve_datastream(_opt(args, "--datastream"))
    profile = _find_profile(load_benchmark(ds_path), base_profile_id)
    if profile is None:
        raise BridgeError(f"profile not found in datastream: {base_profile_id}")
    output_json(_write_tailoring(base_profile_id, profile, modifications, ds_path))


def _write_tailoring(base_profile_id: str, profile: ET.Element, modifications: list[TailoringModification],
                     ds_path: str) -> TailoringInfo:
    """Write the profile's customization file and register it, once the document is known to parse."""
    base_title = _text(profile.find(TAG_TITLE))
    profile_id, xml_text = build_tailoring_xml(base_profile_id, base_title, modifications, ds_path)
    path = _tailoring_path_for(base_profile_id)
    info = parse_tailoring_xml(xml_text, str(path))
    info["profile_id"] = profile_id
    _atomic_write(path, xml_text)
    _register_tailoring(base_profile_id, path)
    return info


def cmd_tailor_rule(args: list[str]) -> None:
    """tailor-rule <base profile id> <rule id> enable|disable [--remark text]

    Enable or disable one rule in the profile's customization (created when there is none), with
    an optional justification; the other customizations stay as they are. The customization applies
    to scans of the installed content, so that is what the profile and rule are checked against.
    """
    positional = _positional(args)
    if len(positional) < REQUIRED_TRIPLE:
        raise BridgeError("tailor-rule requires a base profile id, a rule id and enable or disable")
    base_profile_id, rule_id, state = positional[:REQUIRED_TRIPLE]
    if state not in ("enable", "disable"):
        raise BridgeError(f"tailor-rule expects enable or disable, not {state!r}")
    if not XCCDF_ID_RE.match(rule_id):
        raise BridgeError(f"invalid rule id: {rule_id!r}")
    remark = _validate_remark(_opt(args, "--remark") or "")
    config = load_config()
    ds_path = resolve_datastream(None, config)
    benchmark = load_benchmark(ds_path)
    profile = _find_profile(benchmark, base_profile_id)
    if profile is None:
        raise BridgeError(f"profile not found in datastream: {base_profile_id}")
    if rule_id not in _BenchmarkIndex(benchmark).rules:
        raise BridgeError(f"rule not found in datastream: {rule_id}")
    registered, path, problem = _registered_tailoring(config, base_profile_id, benchmark, ds_path, quiet=True)
    if problem:
        raise BridgeError(f"the profile's customization cannot be changed as it is. {problem}")
    selected = state == "enable"
    if registered is None or path is None:
        change = TailoringModification(idref=rule_id, action=ACTION_SELECT if selected else ACTION_UNSELECT)
        if remark:
            change["remark"] = remark
        output_json(_write_tailoring(base_profile_id, profile, [change], ds_path))
        return
    # an imported file may hold more than the editor models (refine-rule, further profiles): edit it in place
    xml_text = _edit_tailoring_select(registered["tailoring_xml"], rule_id, selected=selected, remark=remark)
    info = parse_tailoring_xml(xml_text, path)
    _atomic_write(Path(path), xml_text)
    output_json(info)


def _read_stdin_or_file(arg: str) -> str:
    if arg == "-":
        return sys.stdin.read()
    return parse_tailoring_file(arg)["tailoring_xml"]


def cmd_parse_tailoring(args: list[str]) -> None:
    if not args:
        raise BridgeError("parse-tailoring requires a file path (or '-' for stdin)")
    output_json(parse_tailoring_xml(_read_stdin_or_file(args[0]), "" if args[0] == "-" else args[0]))


def cmd_import_tailoring(args: list[str]) -> None:
    positional = _positional(args)
    if len(positional) < REQUIRED_PAIR:
        raise BridgeError("import-tailoring requires a base profile id and a file path (or '-' for stdin)")
    base_profile_id, source = positional[0], positional[1]
    xml_text = _read_stdin_or_file(source)
    info = parse_tailoring_xml(xml_text)
    ds_path = resolve_datastream(_opt(args, "--datastream"))
    benchmark = load_benchmark(ds_path)
    if _find_profile(benchmark, base_profile_id) is None:
        raise BridgeError(f"profile not found in datastream: {base_profile_id}")
    problem = _tailoring_problem(info, benchmark, ds_path)
    if problem:
        raise BridgeError(f"the tailoring cannot be used on this system. {problem}")
    notes: list[str] = []
    if info["base_profile_id"] and info["base_profile_id"] != base_profile_id:
        notes.append(f"The imported tailoring extends profile '{info['base_profile_id']}', "
                     f"not '{base_profile_id}'. Its customizations were applied where possible.")
    notes.append(_href_mismatch(info, ds_path))
    warning = " ".join(note for note in notes if note)
    path = _tailoring_path_for(base_profile_id)
    _atomic_write(path, xml_text)
    _register_tailoring(base_profile_id, path)
    info["path"] = str(path)
    info["warning"] = warning
    output_json(info)


def cmd_delete_tailoring(args: list[str]) -> None:
    if not args:
        raise BridgeError("delete-tailoring requires a base profile id")
    config = load_config()
    tailorings = config.get("tailorings", {})
    path = tailorings.pop(args[0], None)
    if path:
        Path(path).unlink(missing_ok=True)
    if not tailorings:
        config.pop("tailorings", None)
    save_config(config)
    output_json({"deleted": bool(path), "profile_id": args[0]})


# ---------------------------------------------------------------------------
# Results storage
# ---------------------------------------------------------------------------


def _check_result_id(result_id: str) -> str:
    if not RESULT_ID_RE.match(result_id) or ".." in result_id:
        raise BridgeError(f"invalid result id: {result_id}")
    return result_id


def _result_paths(result_id: str) -> tuple[Path, Path]:
    _check_result_id(result_id)
    return RESULTS_DIR / f"{result_id}.json", RESULTS_DIR / f"{result_id}.arf.xml"


def _normalize_timestamp(value: object) -> str:
    """Accept ISO 8601 or the legacy compact YYYY-MM-DDTHHMMSS (UTC) format."""
    if not isinstance(value, str) or not value:
        return ""
    match = re.match(r"^(\d{4}-\d{2}-\d{2})T(\d{2})(\d{2})(\d{2})$", value)
    if match:
        return f"{match.group(1)}T{match.group(2)}:{match.group(3)}:{match.group(4)}+00:00"
    return value


def _count_results(results: list[RuleResultItem]) -> dict[str, int]:
    counts = dict.fromkeys(RESULT_KINDS, 0)
    for item in results:
        key = item["result"] if item["result"] in counts else "unknown"
        counts[key] += 1
    return counts


def _coerce_result_items(raw: object) -> list[RuleResultItem]:
    items: list[RuleResultItem] = []
    if not isinstance(raw, list):
        return items
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        items.append(RuleResultItem(
            rule_id=str(entry.get("rule_id", "")),
            result=str(entry.get("result", "unknown")),
            title=str(entry.get("title", "")),
            severity=str(entry.get("severity", "unknown")),
            group=str(entry.get("group", "")),
            message=str(entry.get("message", "")),
        ))
    return items


def _coerce_exclusions(raw: object) -> list[RuleExclusion]:
    if not isinstance(raw, list):
        return []
    return [RuleExclusion(rule_id=str(entry.get("rule_id", "")), title=str(entry.get("title", "")),
                          remark=str(entry.get("remark", "")))
            for entry in raw if isinstance(entry, dict) and entry.get("rule_id")]


def _existing_arf(arf_path: Path, legacy: object) -> str:
    """The ARF file of a result: the canonical location, a legacy recorded path, or "" when it is gone."""
    if arf_path.is_file():
        return str(arf_path)
    if isinstance(legacy, str) and legacy and Path(legacy).is_file():
        return legacy
    return ""


def _load_result(result_id: str) -> ScanResult:
    """Load a saved result, filling defaults for files written by older versions."""
    json_path, arf_path = _result_paths(result_id)
    raw = _read_json_file(json_path)
    if raw is None:
        raise BridgeError(f"scan result not found: {result_id}")
    results = _coerce_result_items(raw.get("results"))
    counts_raw = raw.get("counts")
    counts = ({k: int(v) for k, v in counts_raw.items() if isinstance(v, int)}
              if isinstance(counts_raw, dict) else _count_results(results))
    for kind in RESULT_KINDS:
        counts.setdefault(kind, 0)
    score = raw.get("score")
    xccdf_score = raw.get("xccdf_score")
    tailoring_path = raw.get("tailoring_path")
    return ScanResult(
        id=result_id,
        timestamp=_normalize_timestamp(raw.get("timestamp")),
        start_time=str(raw.get("start_time", "")),
        end_time=str(raw.get("end_time", "")),
        profile_id=str(raw.get("profile_id", "")),
        profile_title=str(raw.get("profile_title", "")),
        base_profile_id=str(raw.get("base_profile_id", raw.get("profile_id", ""))),
        benchmark_id=str(raw.get("benchmark_id", "")),
        benchmark_version=str(raw.get("benchmark_version", "")),
        datastream=str(raw.get("datastream", "")),
        tailoring_path=tailoring_path if isinstance(tailoring_path, str) else None,
        tailored=bool(raw.get("tailored", False)),
        test_result_id=str(raw.get("test_result_id", "")),
        status=str(raw.get("status", "complete")),
        score=float(score) if isinstance(score, (int, float)) else 0.0,
        xccdf_score=float(xccdf_score) if isinstance(xccdf_score, (int, float)) else None,
        counts=counts,
        results=results,
        exclusions=_coerce_exclusions(raw.get("exclusions")),
        currently_excluded=[],
        arf_path=_existing_arf(arf_path, raw.get("arf_path")),
        json_path=str(json_path),
    )


def _duration_seconds(start: str, end: str) -> int:
    try:
        started = datetime.fromisoformat(start)
        ended = datetime.fromisoformat(end)
    except ValueError:
        return 0
    if (started.tzinfo is None) != (ended.tzinfo is None):
        return 0  # one offset-aware, one naive: not comparable
    return max(0, int((ended - started).total_seconds()))


def _summarize(result: ScanResult) -> ResultSummary:
    return ResultSummary(
        id=result["id"],
        timestamp=result["timestamp"],
        profile_id=result["profile_id"],
        base_profile_id=result["base_profile_id"],
        datastream=result["datastream"],
        duration_seconds=_duration_seconds(result["start_time"], result["end_time"]),
        profile_title=result["profile_title"],
        score=result["score"],
        counts=result["counts"],
        total=len(result["results"]),
        status=result["status"],
        tailored=result["tailored"],
        has_arf=bool(result["arf_path"]),
    )


def list_results() -> list[ResultSummary]:
    summaries: list[ResultSummary] = []
    if not RESULTS_DIR.is_dir():
        return summaries
    for path in RESULTS_DIR.glob("*.json"):
        result_id = path.name[:-len(".json")]
        if not RESULT_ID_RE.match(result_id):
            continue
        try:
            summaries.append(_summarize(_load_result(result_id)))
        except BridgeError:
            continue
    summaries.sort(key=lambda s: (s["timestamp"], s["id"]), reverse=True)
    return summaries


_REMEDIATION_NAME_RE = re.compile(r"^(?P<time>\d{4}-\d{2}-\d{2}T\d{6})-(?P<result>.+)$")


def record_path_for(script: Path) -> Path:
    """The JSON audit record that belongs to a remediation script."""
    return script.with_suffix(".json")


def prune_results(max_results: int) -> None:
    """Delete the oldest result files beyond ``max_results``; ids sort chronologically."""
    if not RESULTS_DIR.is_dir():
        return
    ids = sorted({p.name[:-len(".json")] for p in RESULTS_DIR.glob("*.json")
                  if RESULT_ID_RE.match(p.name[:-len(".json")])})
    kept = set(ids[-max_results:]) if max_results > 0 else set(ids)
    for old in ids:
        if old not in kept:
            for path in (RESULTS_DIR / f"{old}.json", RESULTS_DIR / f"{old}.arf.xml"):
                path.unlink(missing_ok=True)
    # the audit trail follows its scan: runs of a kept result stay, however many there are, while
    # runs of a pruned one go, as do runs whose result vanished behind the bridge's back
    _remove_remediations(lambda result_id: result_id not in kept)


def _remove_remediations(gone: Callable[[str], bool]) -> None:
    """Remove the scripts and audit records of the runs whose result id ``gone`` accepts."""
    if not REMEDIATION_DIR.is_dir():
        return
    for script in REMEDIATION_DIR.glob("*.sh"):
        match = _REMEDIATION_NAME_RE.match(script.stem)
        if match and gone(match.group("result")):
            script.unlink(missing_ok=True)
            record_path_for(script).unlink(missing_ok=True)


def _delete_remediations(result_id: str) -> None:
    """Remove the scripts and audit records of every remediation run of a result."""
    _remove_remediations(lambda candidate: candidate == result_id)


def cmd_list_results(_args: list[str]) -> None:
    if DATA_DIR.is_dir() and os.access(DATA_DIR, os.W_OK):
        reconcile_scan_state()
    output_json(list_results())


def _currently_excluded(base_profile_id: str) -> list[str]:
    """The rules the profile's registered customization takes out of a scan today.

    Resolved against the installed content like the scanner does, which is loaded only when the
    customization disables something. A customization scans cannot apply (its base profile is gone
    from the content, say) still reports its own unselects: the result page must not offer to
    exclude what the file already excludes, and tailor-rule would refuse anyway.
    """
    config = load_config()
    path = config.get("tailorings", {}).get(base_profile_id)
    if not path:
        return []
    try:
        info = parse_tailoring_file(path)
    except BridgeError:
        return []
    unselected = sorted({mod["idref"] for mod in info["modifications"] if mod["action"] == ACTION_UNSELECT})
    return _resolved_exclusions(config, base_profile_id) if unselected else []


def _resolved_exclusions(config: Config, base_profile_id: str) -> list[str]:
    """What the registered customization excludes as the scanner would see it, else what its file says."""
    try:
        ds_path = resolve_datastream(None, config)
        benchmark = load_benchmark(ds_path)
        registered, _path, _problem = _registered_tailoring(config, base_profile_id, benchmark, ds_path, quiet=True)
        if registered is None:
            raise BridgeError("the customization cannot be applied")
        profile = ET.fromstring(registered["tailoring_xml"]).find(TAG_PROFILE)  # noqa: S314  (parsed already)
        if profile is None:
            raise BridgeError("no profile")
    except BridgeError:
        info = parse_tailoring_file(str(config.get("tailorings", {}).get(base_profile_id)))
        return sorted({mod["idref"] for mod in info["modifications"] if mod["action"] == ACTION_UNSELECT})
    return sorted(_customization_exclusions(_BenchmarkIndex(benchmark), profile))


DEFAULT_HISTORY_LIMIT = 20
MAX_HISTORY_LIMIT = 200


def rule_history(rule_id: str, base_profile_id: str, limit: int, datastream: str = "") -> list[RuleHistoryPoint]:
    """How a rule fared in the last ``limit`` complete scans of a profile, newest first.

    Only scans of the same content count when ``datastream`` is given (a result from before the
    content path was recorded matches any, as the result page's comparison has it).
    """
    points: list[RuleHistoryPoint] = []
    if not RESULTS_DIR.is_dir():
        return points
    # ids sort chronologically; each result file is read once
    ids = sorted((p.name[:-len(".json")] for p in RESULTS_DIR.glob("*.json")), reverse=True)
    for result_id in ids:
        if not RESULT_ID_RE.match(result_id):
            continue
        try:
            result = _load_result(result_id)
        except BridgeError:
            continue
        if (result["base_profile_id"] != base_profile_id or result["status"] != "complete"
                or (datastream and result["datastream"] and result["datastream"] != datastream)):
            continue
        outcome = next((r["result"] for r in result["results"] if r["rule_id"] == rule_id), RESULT_NOTSELECTED)
        points.append(RuleHistoryPoint(id=result["id"], timestamp=result["timestamp"], score=result["score"],
                                       result=outcome))
        if len(points) >= limit:
            break
    return points


def cmd_rule_history(args: list[str]) -> None:
    """rule-history <rule id> <base profile id> [--limit N] [--datastream path]"""
    positional = _positional(args)
    if len(positional) < REQUIRED_PAIR:
        raise BridgeError("rule-history requires a rule id and a base profile id")
    rule_id, base_profile_id = positional[:REQUIRED_PAIR]
    if not XCCDF_ID_RE.match(rule_id) or not XCCDF_ID_RE.match(base_profile_id):
        raise BridgeError("invalid rule or profile id")
    raw_limit = _opt(args, "--limit")
    try:
        limit = int(raw_limit) if raw_limit is not None else DEFAULT_HISTORY_LIMIT
    except ValueError as exc:
        raise BridgeError(f"invalid --limit: {raw_limit!r}") from exc
    if not 1 <= limit <= MAX_HISTORY_LIMIT:
        raise BridgeError(f"--limit must be between 1 and {MAX_HISTORY_LIMIT}")
    output_json(rule_history(rule_id, base_profile_id, limit, _opt(args, "--datastream") or ""))


def cmd_get_result(args: list[str]) -> None:
    if not args:
        raise BridgeError("get-result requires a result id")
    result = _load_result(args[0])
    result["currently_excluded"] = _currently_excluded(result["base_profile_id"])
    output_json(result)


def cmd_delete_result(args: list[str]) -> None:
    if not args:
        raise BridgeError("delete-result requires a result id")
    json_path, arf_path = _result_paths(args[0])
    if not json_path.is_file():
        raise BridgeError(f"scan result not found: {args[0]}")
    json_path.unlink()
    arf_path.unlink(missing_ok=True)
    _delete_remediations(args[0])
    output_json({"deleted": True, "id": args[0]})


# ---------------------------------------------------------------------------
# ARF result parsing
# ---------------------------------------------------------------------------


class ParsedArf(TypedDict):
    test_result_id: str
    profile_id: str
    benchmark_id: str
    benchmark_version: str
    start_time: str
    end_time: str
    xccdf_score: float | None
    score: float
    results: list[RuleResultItem]
    exclusions: list[RuleExclusion]


def _customization_exclusions(index: _BenchmarkIndex, profile: ET.Element) -> dict[str, str]:
    """The rules a tailoring profile takes out of a scan of its base profile, each with the remark of
    the select that did it (the rule's own, else the nearest group's), in the content's order."""
    selects = profile.findall(TAG_SELECT)
    base = index.selection(profile.get("extends", ""))
    tailored = index.selection(profile.get("extends", ""), selects)
    switched_off: dict[str, str] = {}  # item id -> remark of the select that last switched it off
    for sel in selects:
        idref = sel.get("idref", "")
        if _xml_true(sel.get("selected")):
            switched_off.pop(idref, None)
        else:
            switched_off[idref] = _select_remark(sel)
    excluded: dict[str, str] = {}
    for rule_id in index.rules:
        if not base[rule_id] or tailored[rule_id]:
            continue
        culprits = [rule_id, *reversed(index.rule_groups[rule_id])]
        excluded[rule_id] = next((switched_off[item] for item in culprits if item in switched_off), "")
    return excluded


def _arf_exclusions(root: ET.Element, index: _BenchmarkIndex | None, not_selected: set[str]) -> list[RuleExclusion]:
    """The rules the embedded tailoring took out of the scan, with their remarks."""
    tailoring = next(root.iter(TAG_TAILORING), None)
    profile = tailoring.find(TAG_PROFILE) if tailoring is not None else None
    if profile is None or index is None:
        return []
    return [RuleExclusion(rule_id=rule_id, title=_text(index.rules[rule_id].find(TAG_TITLE)), remark=remark)
            for rule_id, remark in _customization_exclusions(index, profile).items() if rule_id in not_selected]


def parse_arf(arf_path: str) -> ParsedArf:
    """Extract the TestResult from an ARF (or bare XCCDF results) document.

    The score is computed as pass / (pass + fail + error) * 100; rules that are
    not selected are omitted and rules with other results are excluded from the
    denominator.  The official XCCDF score is reported alongside.
    """
    try:
        root = ET.parse(arf_path).getroot()  # noqa: S314
    except ET.ParseError as exc:
        raise BridgeError(f"failed to parse results XML: {exc}") from exc
    except OSError as exc:
        raise BridgeError(f"cannot read results file: {exc}") from exc

    test_result = next(root.iter(TAG_TEST_RESULT), None)
    if test_result is None:
        raise BridgeError("results document does not contain a TestResult")

    benchmark = next(root.iter(TAG_BENCHMARK), None)
    index = _BenchmarkIndex(benchmark) if benchmark is not None else None

    results: list[RuleResultItem] = []
    not_selected: set[str] = set()
    tally = dict.fromkeys(SCORED_RESULTS, 0)
    for rr in test_result.findall(TAG_RULE_RESULT):
        rule_id = rr.get("idref", "")
        result = _text(rr.find(TAG_RESULT)) or "unknown"
        if result == RESULT_NOTSELECTED:
            not_selected.add(rule_id)
            continue
        rule = index.rules.get(rule_id) if index else None
        severity = rr.get("severity", "") or (rule.get("severity", "unknown") if rule is not None else "unknown")
        results.append(RuleResultItem(
            rule_id=rule_id,
            result=result,
            title=_text(rule.find(TAG_TITLE)) if rule is not None else "",
            severity=severity,
            group=index.category(rule_id) if index else "",
            message="; ".join(_text(m) for m in rr.findall(TAG_MESSAGE)),
        ))
        if result in tally:
            tally[result] += 1

    denominator = sum(tally.values())
    score = round(tally[RESULT_PASS] / denominator * 100.0, 2) if denominator else 0.0
    score_el = test_result.find(_x("score"))
    xccdf_score: float | None = None
    if score_el is not None and score_el.text:
        try:
            xccdf_score = round(float(score_el.text), 2)
        except ValueError:
            xccdf_score = None

    profile_el = test_result.find(_x("profile"))
    bench_el = test_result.find(_x("benchmark"))
    return ParsedArf(
        test_result_id=test_result.get("id", ""),
        profile_id=profile_el.get("idref", "") if profile_el is not None else "",
        benchmark_id=bench_el.get("id", "") if bench_el is not None else "",
        benchmark_version=test_result.get("version", ""),
        start_time=test_result.get("start-time", ""),
        end_time=test_result.get("end-time", ""),
        xccdf_score=xccdf_score,
        score=score,
        results=results,
        exclusions=_arf_exclusions(root, index, not_selected),
    )


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


class ScanRequest(TypedDict):
    profile_id: str
    base_profile_id: str
    profile_title: str
    datastream: str
    tailoring_path: str | None
    #: the tailoring recorded in the result: the user's file, even when a temporary copy was evaluated
    tailoring_origin: str | None
    temp_files: list[str]
    source: str
    total_rules: int


def _write_scan_state(state: JsonDict) -> None:
    try:
        _atomic_write(SCAN_STATE_PATH, json.dumps(state) + "\n")
    except BridgeError:
        log.warning("cannot write scan state file")


def _scan_lock() -> int:
    """Take the scan lock; raise if another scan is running."""
    _ensure_dir(DATA_DIR)
    fd = os.open(SCAN_LOCK_PATH, os.O_RDWR | os.O_CREAT, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        os.close(fd)
        raise BridgeError("a compliance scan is already running") from exc
    return fd


def reconcile_scan_state() -> None:
    """Mark a "running" scan state as failed when no scan actually holds the lock (e.g. after a crash)."""
    state = _read_json_file(SCAN_STATE_PATH)
    if not state or not state.get("running") or not SCAN_LOCK_PATH.is_file():
        return
    try:
        fd = _scan_lock()
    except BridgeError:
        return  # a scan really is running
    os.close(fd)
    log.warning("scan state claims a running scan but the lock is free; marking it as failed")
    _write_scan_state({"running": False, "status": "failed", "finished": _iso(_now_utc()),
                       "error": "the scan process ended unexpectedly", "profile_id": state.get("profile_id", ""),
                       "profile_title": state.get("profile_title", ""), "source": state.get("source", "")})


def _rescan_tailoring(previous: ScanResult, config: Config, benchmark: ET.Element,
                      datastream: str) -> tuple[TailoringInfo | None, str | None, str | None, list[str]]:
    """The tailoring to repeat a scan with: (info, file to evaluate, file to record, temporary files).

    The copy embedded in the ARF is exactly what was evaluated, so it is preferred even when the
    user's tailoring file changed or was removed since.
    """
    if not previous["tailored"]:
        return None, None, None, []
    embedded = extract_arf_tailoring(previous["arf_path"]) if previous["arf_path"] else None
    if embedded:
        try:
            info = parse_tailoring_file(embedded)
            problem = _tailoring_problem(info, benchmark, datastream)
        except BridgeError as exc:
            problem = str(exc)
        if not problem:
            return info, embedded, previous["tailoring_path"], [embedded]
        Path(embedded).unlink(missing_ok=True)
        log.warning("cannot reuse the tailoring recorded in %s: %s", previous["id"], problem)
    registered, path, _problem = _registered_tailoring(config, previous["base_profile_id"], benchmark, datastream)
    if registered is None:
        log.warning("rescanning %s without its customizations: no usable tailoring is left", previous["id"])
        return None, None, None, []
    return registered, path, path, []


def _resolve_scan_request(args: list[str]) -> ScanRequest:
    config = load_config()
    positional = _positional(args)
    previous: ScanResult | None = None
    rescan_of = _opt(args, "--rescan-of")
    if rescan_of:
        previous = _load_result(rescan_of)
        base_profile_id: str | None = previous["base_profile_id"] or previous["profile_id"]
    else:
        base_profile_id = positional[0] if positional else config.get("active_profile")
    if not base_profile_id:
        raise BridgeError("no profile given and no active profile configured")
    if not XCCDF_ID_RE.match(base_profile_id):
        raise BridgeError(f"invalid profile id: {base_profile_id}")

    requested_ds = _opt(args, "--datastream")
    if previous is not None and requested_ds is None and Path(previous["datastream"]).is_file():
        requested_ds = previous["datastream"]
    datastream = resolve_datastream(requested_ds, config)
    benchmark = load_benchmark(datastream)
    index = _BenchmarkIndex(benchmark)
    profile = _find_profile(benchmark, base_profile_id)
    if profile is None:
        raise BridgeError(f"profile not found in datastream: {base_profile_id}")
    selection = index.selection(base_profile_id)
    profile_id = base_profile_id
    profile_title = _text(profile.find(TAG_TITLE))

    tailoring: TailoringInfo | None = None
    temp_files: list[str] = []
    tailoring_path = _opt(args, "--tailoring-path")
    tailoring_origin = tailoring_path
    if previous is not None:
        tailoring, tailoring_path, tailoring_origin, temp_files = _rescan_tailoring(previous, config, benchmark,
                                                                                   datastream)
    elif tailoring_path is not None:
        tailoring = parse_tailoring_file(tailoring_path)
        problem = _tailoring_problem(tailoring, benchmark, datastream)
        if problem:
            raise BridgeError(f"the tailoring cannot be used. {problem}")
    elif "--no-tailoring" not in args:
        tailoring, tailoring_path, _problem = _registered_tailoring(config, base_profile_id, benchmark, datastream)
        tailoring_path = tailoring_origin = tailoring_path if tailoring else None
    if tailoring is not None:
        profile_id = tailoring["profile_id"]
        profile_title = tailoring["title"] or profile_title
        selects = [
            ET.Element(TAG_SELECT, {"idref": m["idref"], "selected": str(m["action"] == ACTION_SELECT).lower()})
            for m in tailoring["modifications"] if m["action"] in (ACTION_SELECT, ACTION_UNSELECT)
        ]
        selection = index.selection(base_profile_id, selects)

    return ScanRequest(
        profile_id=profile_id,
        base_profile_id=base_profile_id,
        profile_title=profile_title,
        datastream=datastream,
        tailoring_path=tailoring_path,
        tailoring_origin=tailoring_origin,
        temp_files=temp_files,
        source=_opt(args, "--source") or "interactive",
        total_rules=sum(1 for v in selection.values() if v),
    )


class _OscapRun:
    """Run ``oscap xccdf eval --progress`` while streaming progress and forwarding termination."""

    def __init__(self, cmd: list[str], request: ScanRequest, started: str) -> None:
        self.cmd = cmd
        self.request = request
        self.started = started
        self.interrupted = False
        self.output_closed = False
        self.proc: subprocess.Popen[str] | None = None
        self.current = 0
        self.last_state_write = 0.0

    def _on_signal(self, _signum: int, _frame: object) -> None:
        self.interrupted = True
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()

    def _state(self, rule_id: str, result: str) -> JsonDict:
        total = max(self.request["total_rules"], self.current)
        return {
            "running": True,
            "pid": os.getpid(),
            "source": self.request["source"],
            "profile_id": self.request["profile_id"],
            "profile_title": self.request["profile_title"],
            "started": self.started,
            "current": self.current,
            "total": total,
            "progress": int(self.current / total * 100) if total else 0,
            "rule_id": rule_id,
            "result": result,
        }

    def _progress(self, rule_id: str, result: str) -> None:
        self.current += 1
        state = self._state(rule_id, result)
        if self.request["source"] == "interactive" and not self.output_closed:
            try:
                output_json({"type": "progress", **state})
            except OSError:
                # Cockpit closed the channel; keep scanning so the result is still saved
                self.output_closed = True
                _silence_stdout()
                log.warning("progress reader went away; the scan continues in the background")
        now = time.monotonic()
        if now - self.last_state_write >= STATE_WRITE_INTERVAL:
            self.last_state_write = now
            _write_scan_state(state)

    def run(self) -> tuple[int, str]:
        """Return (exit status, stderr text)."""
        signals = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
        handlers = {sig: signal.signal(sig, self._on_signal) for sig in signals}
        _write_scan_state(self._state("", ""))
        try:
            with tempfile.TemporaryFile(mode="w+") as stderr_file:
                self.proc = subprocess.Popen(self.cmd, stdout=subprocess.PIPE, stderr=stderr_file, text=True)
                if self.proc.stdout is None:
                    raise BridgeError("failed to capture oscap output")
                for line in self.proc.stdout:
                    rule_id, sep, result = line.strip().partition(":")
                    if sep and rule_id.startswith("xccdf_"):
                        self._progress(rule_id, result)
                rc = self.proc.wait()
                stderr_file.seek(0)
                stderr = stderr_file.read()
        finally:
            for sig, handler in handlers.items():
                signal.signal(sig, handler)
        return rc, stderr


def _save_result(request: ScanRequest, parsed: ParsedArf, *, result_id: str, timestamp: str,
                 status: str) -> ScanResult:
    json_path, arf_path = _result_paths(result_id)
    result = ScanResult(
        id=result_id,
        timestamp=timestamp,
        start_time=parsed["start_time"],
        end_time=parsed["end_time"],
        profile_id=parsed["profile_id"] or request["profile_id"],
        profile_title=request["profile_title"],
        base_profile_id=request["base_profile_id"],
        benchmark_id=parsed["benchmark_id"],
        benchmark_version=parsed["benchmark_version"],
        datastream=request["datastream"],
        tailoring_path=request["tailoring_origin"],
        tailored=request["tailoring_path"] is not None,
        test_result_id=parsed["test_result_id"],
        status=status,
        score=parsed["score"],
        xccdf_score=parsed["xccdf_score"],
        counts=_count_results(parsed["results"]),
        results=parsed["results"],
        exclusions=parsed["exclusions"],
        currently_excluded=[],
        arf_path=str(arf_path),
        json_path=str(json_path),
    )
    stored = {key: value for key, value in result.items() if key != "currently_excluded"}
    _atomic_write(json_path, json.dumps(stored, indent=1) + "\n")
    return result


def run_scan(args: list[str]) -> ScanResult:
    oscap_path = _require_oscap()
    request = _resolve_scan_request(args)
    try:
        lock_fd = _scan_lock()
    except BridgeError:
        for name in request["temp_files"]:
            Path(name).unlink(missing_ok=True)
        raise
    runner: _OscapRun | None = None
    settled = False
    arf_path: Path | None = None
    try:
        _ensure_dir(RESULTS_DIR)
        started_dt = _now_utc()
        result_id = f"{started_dt.strftime('%Y-%m-%dT%H%M%S')}-{_profile_short_name(request['base_profile_id'])}"
        _json_path, arf_path = _result_paths(result_id)

        cmd = [oscap_path, "xccdf", "eval", "--progress", "--profile", request["profile_id"],
               "--results-arf", str(arf_path)]
        if request["tailoring_path"]:
            cmd += ["--tailoring-file", request["tailoring_path"]]
        cmd.append(request["datastream"])
        log.info("starting scan: %s", " ".join(cmd))

        runner = _OscapRun(cmd, request, _iso(started_dt))
        rc, stderr = runner.run()
        finished = _iso(_now_utc())

        def fail(message: str, status: str) -> BridgeError:
            nonlocal settled
            settled = True
            _write_scan_state({"running": False, "status": status, "finished": finished, "error": message,
                               "profile_id": request["profile_id"], "profile_title": request["profile_title"],
                               "source": request["source"]})
            arf_path.unlink(missing_ok=True)
            return BridgeError(message)

        if runner.interrupted:
            raise fail("the scan was cancelled", "cancelled")
        if rc == OSCAP_EXIT_ERROR:
            raise fail(f"oscap failed: {stderr.strip()[-ERROR_TAIL:] or 'unknown error'}", "failed")
        if not arf_path.is_file():
            raise fail(f"oscap did not produce a results file: {stderr.strip()[-ERROR_TAIL:]}", "failed")

        parsed = parse_arf(str(arf_path))
        result = _save_result(request, parsed, result_id=result_id, timestamp=_iso(started_dt), status="complete")
        prune_results(load_config().get("max_results", DEFAULT_MAX_RESULTS))
        _write_scan_state({"running": False, "status": "complete", "finished": finished, "result_id": result_id,
                           "score": result["score"], "profile_id": request["profile_id"],
                           "profile_title": request["profile_title"], "source": request["source"],
                           "counts": result["counts"]})
        settled = True
        log.info("scan complete: %s score=%.1f", result_id, result["score"])
        return result
    finally:
        if runner is not None and not settled:
            _write_scan_state({"running": False, "status": "failed", "finished": _iso(_now_utc()),
                               "error": "the scan ended unexpectedly", "profile_id": request["profile_id"],
                               "profile_title": request["profile_title"], "source": request["source"]})
            if arf_path is not None:
                arf_path.unlink(missing_ok=True)
        for name in request["temp_files"]:
            Path(name).unlink(missing_ok=True)
        os.close(lock_fd)


def cmd_scan(args: list[str]) -> None:
    result = run_scan(args)
    output_json({"type": "done", "result": result})


# ---------------------------------------------------------------------------
# Remediation
# ---------------------------------------------------------------------------

_RISK_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"/etc/sudoers"), RISK_HIGH, "Changes sudo policy and may lock out administrators"),
    (re.compile(r"/etc/pam\.d/|(?:^|\s)authselect\b", re.MULTILINE), RISK_HIGH,
     "Changes authentication configuration and may prevent logins"),
    (re.compile(r"/etc/firewalld/|(?:^|\s)firewall-cmd\b|(?:^|\s)nft\b|(?:^|\s)iptables\b", re.MULTILINE), RISK_HIGH,
     "Changes firewall rules and may block network access, including Cockpit"),
    (re.compile(r"/etc/selinux/|(?:^|\s)semanage\b|(?:^|\s)setsebool\b", re.MULTILINE), RISK_HIGH,
     "Changes SELinux policy and may break services"),
    (re.compile(r"\bsshd_config\b"), RISK_HIGH, "Changes SSH server configuration and may lock out remote sessions"),
    (re.compile(r"/etc/fstab|(?:^|\s)mount\b", re.MULTILINE), RISK_HIGH, "Changes mount options and may affect boot"),
    (re.compile(r"/etc/default/grub|(?:^|\s)grub2?-mkconfig\b|(?:^|\s)grubby\b", re.MULTILINE), RISK_HIGH,
     "Changes boot loader configuration"),
    (re.compile(r"(?:^|\s)systemctl\b", re.MULTILINE), RISK_MEDIUM, "Starts, stops or masks system services"),
    (re.compile(r"/etc/audit/|/etc/rsyslog|/etc/cron|/etc/login\.defs|/etc/security/"), RISK_MEDIUM,
     "Changes system-wide policy files"),
    (re.compile(r"(?:^|\s)(?:dnf|yum|apt(?:-get)?|zypper)\s+(?:-y\s+)?(?:remove|erase|purge)\b", re.MULTILINE),
     RISK_MEDIUM, "Removes software packages"),
]

# oscap emits: "# BEGIN fix (N / M) for 'rule_id'" ... "# END fix for 'rule_id'"
# (older releases: "# BEGIN fix (rule_id) for 'short_name'" ... "# END fix (rule_id) ...")
_FIX_BLOCK_RE = re.compile(
    r"^#+ BEGIN fix \(([^)]*)\)(?: for '([^']*)')?[^\n]*\n(.*?)^#+ END fix\b[^\n]*$",
    re.MULTILINE | re.DOTALL,
)
_MISSING_FIX_RE = re.compile(r"IS MISSING!")
_RULE_LINE_RE = re.compile(r"^#{3,}\s*$")


def classify_risk(snippet: str) -> tuple[str, str]:
    """Return (risk level, reason) for a remediation snippet."""
    for pattern, level, reason in _RISK_PATTERNS:
        if pattern.search(snippet):
            return level, reason
    return RISK_LOW, ""


def parse_fix_script(script: str) -> list[FixRuleInfo]:
    rules: list[FixRuleInfo] = []
    for match in _FIX_BLOCK_RE.finditer(script):
        head, quoted, body = match.group(1), match.group(2), match.group(3)
        rule_id = quoted if quoted and quoted.startswith("xccdf_") else head
        lines = [line.rstrip() for line in body.splitlines() if not _RULE_LINE_RE.match(line)]
        snippet = "\n".join(lines).strip("\n").strip()
        risk, reason = classify_risk(snippet)
        rules.append(FixRuleInfo(id=rule_id, title="", fix_snippet=snippet, risk_level=risk, risk_reason=reason,
                                 has_fix=not _MISSING_FIX_RE.search(snippet)))
    return rules


def extract_arf_tailoring(arf_path: str) -> str | None:
    """Write the tailoring embedded in an ARF (if any) to a temporary file and return its path.

    A scan run with a tailoring file records that tailoring inside the ARF.  ``oscap
    xccdf generate fix`` cannot resolve the customized profile from the ARF alone, so
    the embedded copy (exactly what was evaluated) is handed back to it.
    """
    try:
        root = ET.parse(arf_path).getroot()  # noqa: S314
    except (ET.ParseError, OSError) as exc:
        raise BridgeError(f"cannot read results file: {exc}") from exc
    tailoring = next(root.iter(TAG_TAILORING), None)
    if tailoring is None:
        return None
    fd, name = tempfile.mkstemp(prefix="cockpit-oscap-tailoring-", suffix=".xml")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(_serialize_tailoring(tailoring))
    return name


FIX_TYPES = ("bash", "ansible")


def generate_fix(result: ScanResult, fix_type: str = "bash") -> FixInfo:
    """Generate remediation (bash script or Ansible playbook) for the rules that failed in a saved result."""
    if fix_type not in FIX_TYPES:
        raise BridgeError(f"unsupported fix type: {fix_type} (expected one of {', '.join(FIX_TYPES)})")
    oscap_path = _require_oscap()
    if not result["arf_path"] or not Path(result["arf_path"]).is_file():
        raise BridgeError("the results file for this scan is no longer available")
    test_result_id = result["test_result_id"] or parse_arf(result["arf_path"])["test_result_id"]
    cmd = [oscap_path, "xccdf", "generate", "fix", "--fix-type", fix_type, "--result-id", test_result_id]
    tailoring_file = extract_arf_tailoring(result["arf_path"])
    if tailoring_file:
        cmd += ["--tailoring-file", tailoring_file]
    cmd.append(result["arf_path"])
    try:
        rc, stdout, stderr = run_cmd(cmd, timeout=FIX_TIMEOUT)
    finally:
        if tailoring_file:
            Path(tailoring_file).unlink(missing_ok=True)
    if rc != 0:
        raise BridgeError(f"oscap generate fix failed: {stderr.strip()[-ERROR_TAIL:]}")
    titles = {r["rule_id"]: r["title"] for r in result["results"]}
    # per-rule blocks (and risk classification) only apply to bash scripts
    rules = parse_fix_script(stdout) if fix_type == "bash" else []
    for rule in rules:
        rule["title"] = titles.get(rule["id"], "")
    return FixInfo(result_id=result["id"], fix_type=fix_type, script=stdout, rules=rules)


def cmd_generate_fix(args: list[str]) -> None:
    positional = _positional(args)
    if not positional:
        raise BridgeError("generate-fix requires a result id")
    output_json(generate_fix(_load_result(positional[0]), _opt(args, "--type") or "bash"))


def _rule_ids_arg(args: list[str]) -> list[str]:
    raw = _parse_json_arg(_opt(args, "--rules") or "[]", "rules")
    if not isinstance(raw, list) or not all(isinstance(r, str) and XCCDF_ID_RE.match(r) for r in raw):
        raise BridgeError("--rules must be a JSON array of rule ids")
    return list(dict.fromkeys(raw))


def remediate(result: ScanResult, rule_ids: list[str]) -> RemediateResult:
    """Apply the generated fix for each selected rule, one rule at a time."""
    fix = generate_fix(result)
    snippets = {r["id"]: r for r in fix["rules"]}
    missing = [rid for rid in rule_ids if rid not in snippets or not snippets[rid]["has_fix"]]
    if missing:
        raise BridgeError(f"no remediation is available for: {', '.join(missing)}")

    _ensure_dir(REMEDIATION_DIR)
    script_path = REMEDIATION_DIR / f"{_now_utc().strftime('%Y-%m-%dT%H%M%S')}-{result['id']}.sh"
    header = ["#!/usr/bin/env bash", f"# Remediation applied by cockpit-oscap for scan {result['id']}", ""]
    body = [f"# --- {rid} ---\n{snippets[rid]['fix_snippet']}\n" for rid in rule_ids]
    _atomic_write(script_path, "\n".join(header + body), mode=0o700)

    # the audit trail next to the script, kept current after every rule so an interrupted run
    # still records what was applied; fix output can contain system details, hence root-only
    record_path = record_path_for(script_path)
    outcomes: list[RuleRemediation] = []

    def write_record(*, done: bool) -> None:
        record = {"timestamp": _iso(_now_utc()), "result_id": result["id"], "script_path": str(script_path),
                  "planned": len(rule_ids), "rules": outcomes,
                  "success": all(o["success"] for o in outcomes) if done else None}
        _atomic_write(record_path, json.dumps(record, indent=1) + "\n", mode=0o600)

    write_record(done=False)
    for i, rid in enumerate(rule_ids, start=1):
        output_json({"type": "progress", "current": i, "total": len(rule_ids), "rule_id": rid})
        try:
            proc = subprocess.run(["bash", "-c", snippets[rid]["fix_snippet"]], capture_output=True,
                                  text=True, check=False, timeout=REMEDIATE_RULE_TIMEOUT)
            outcome = RuleRemediation(rule_id=rid, success=proc.returncode == 0, exit_status=proc.returncode,
                                      output=proc.stdout[-ERROR_TAIL * 4:], errors=proc.stderr[-ERROR_TAIL * 4:])
        except subprocess.TimeoutExpired:
            outcome = RuleRemediation(rule_id=rid, success=False, exit_status=-1, output="",
                                      errors=f"timed out after {REMEDIATE_RULE_TIMEOUT} seconds")
        except OSError as exc:
            outcome = RuleRemediation(rule_id=rid, success=False, exit_status=-1, output="", errors=str(exc))
        log.info("remediation %s: rc=%d", rid, outcome["exit_status"])
        outcomes.append(outcome)
        write_record(done=i == len(rule_ids))
    return RemediateResult(result_id=result["id"], success=all(o["success"] for o in outcomes),
                           script_path=str(script_path), rules=outcomes)


class RemediationRun(TypedDict):
    id: str
    timestamp: str
    result_id: str
    script_path: str
    #: None while a run is in progress or was interrupted, and for scripts from before the audit trail
    success: bool | None
    #: rules the run set out to apply
    planned: int
    applied: int
    failed: int
    rules: list[RuleRemediation]




def list_remediations(result_id: str | None = None) -> list[RemediationRun]:
    """Every remediation run recorded under REMEDIATION_DIR, newest first (optionally for one result)."""
    runs: list[RemediationRun] = []
    if not REMEDIATION_DIR.is_dir():
        return runs
    for script in REMEDIATION_DIR.glob("*.sh"):
        match = _REMEDIATION_NAME_RE.match(script.stem)
        if not match or (result_id and match.group("result") != result_id):
            continue
        # records and scripts are root-only: a read-only session sees no history rather than a wrong one
        try:
            record = _read_json_file(record_path_for(script), raise_permission=True) or {}
        except PermissionError:
            continue
        outcomes: list[RuleRemediation] = []
        planned = 0
        success: bool | None = None
        timestamp = ""
        try:
            raw_rules = record.get("rules", [])
            for raw in raw_rules if isinstance(raw_rules, list) else []:
                if isinstance(raw, dict):
                    status = raw.get("exit_status", -1)
                    outcomes.append(RuleRemediation(
                        rule_id=str(raw.get("rule_id", "")), success=bool(raw.get("success")),
                        exit_status=int(status) if isinstance(status, (int, str)) else -1,
                        output=str(raw.get("output", "")), errors=str(raw.get("errors", ""))))
            raw_planned = record.get("planned", len(outcomes))
            planned = int(raw_planned) if isinstance(raw_planned, (int, str)) else len(outcomes)
            success = bool(record["success"]) if record.get("success") is not None else None
            raw_timestamp = record.get("timestamp")
            timestamp = raw_timestamp if isinstance(raw_timestamp, str) else ""
        except (TypeError, ValueError, AttributeError):
            log.warning("remediation record %s is malformed; listing it without outcomes", record_path_for(script))
            outcomes, planned, success = [], 0, None
        applied = sum(1 for o in outcomes if o["success"])
        if not record:
            # script from before the audit trail existed: count its rule blocks, outcome unknown
            try:
                planned = sum(1 for line in script.read_text().splitlines() if line.startswith("# --- "))
            except PermissionError:
                continue
            except OSError:
                planned = 0
        runs.append(RemediationRun(
            id=script.stem,
            timestamp=timestamp or _normalize_timestamp(match.group("time")),
            result_id=match.group("result"),
            script_path=str(script),
            success=success,
            planned=max(planned, len(outcomes)),
            applied=applied,
            failed=len(outcomes) - applied,
            rules=outcomes,
        ))
    runs.sort(key=lambda r: r["timestamp"], reverse=True)
    return runs


def cmd_list_remediations(args: list[str]) -> None:
    positional = _positional(args)
    output_json(list_remediations(_check_result_id(positional[0]) if positional else None))


def cmd_remediate(args: list[str]) -> None:
    positional = _positional(args)
    if not positional:
        raise BridgeError("remediate requires a result id")
    rule_ids = _rule_ids_arg(args)
    if not rule_ids:
        raise BridgeError("no rules selected for remediation")
    output_json({"type": "done", "result": remediate(_load_result(positional[0]), rule_ids)})


def generate_report(arf_path: str) -> str:
    """The scanner's HTML report of an ARF."""
    rc, stdout, stderr = run_cmd([_require_oscap(), "xccdf", "generate", "report", arf_path], timeout=REPORT_TIMEOUT)
    if rc != 0:
        raise BridgeError(f"oscap generate report failed: {stderr.strip()[-ERROR_TAIL:]}")
    return stdout


def cmd_generate_report(args: list[str]) -> None:
    if not args:
        raise BridgeError("generate-report requires a result id")
    result = _load_result(args[0])
    if not result["arf_path"] or not Path(result["arf_path"]).is_file():
        raise BridgeError("the results file for this scan is no longer available")
    output_json({"id": result["id"], "html": generate_report(result["arf_path"])})


# ---------------------------------------------------------------------------
# Evidence bundle
# ---------------------------------------------------------------------------


_CSV_FORMULA_RE = re.compile(r"^[=+\-@\t\r]")


def _csv_cell(text: str) -> str:
    """A cell that a spreadsheet will not run as a formula (the page's CSV does the same)."""
    return f"'{text}" if _CSV_FORMULA_RE.match(text) else text


def _rules_csv(result: ScanResult) -> str:
    """The rule results as CSV, the columns and escaping the page's download uses."""
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\r\n")
    writer.writerow(["rule_id", "title", "result", "severity", "category", "message"])
    for rule in result["results"]:
        writer.writerow([_csv_cell(rule["rule_id"]), _csv_cell(rule["title"]), _csv_cell(rule["result"]),
                         _csv_cell(rule["severity"]), _csv_cell(rule["group"]), _csv_cell(rule["message"])])
    return out.getvalue()


# bookkeeping of this host, not evidence: not for the bundle's summary
_BUNDLE_PRIVATE_KEYS = frozenset(("arf_path", "json_path", "tailoring_path", "currently_excluded"))


def _bundle_readme(result: ScanResult, members: list[str], notes: list[str]) -> str:
    """A plain-text cover sheet for whoever receives the bundle."""
    lines = [
        f"Compliance evidence for {os.uname().nodename}",
        "=" * 72,
        "",
        f"Profile:     {result['profile_title'] or result['profile_id']} ({result['profile_id']})",
        f"Scanned:     {result['timestamp']}",
        f"Score:       {result['score']:.1f}% ({result['counts'].get('pass', 0)} passed, "
        f"{result['counts'].get('fail', 0)} failed, {result['counts'].get('error', 0)} errors)",
        f"Status:      {result['status']}",
        f"Content:     {result['datastream'] or 'unknown'}"
        + (f" (benchmark {result['benchmark_id']} {result['benchmark_version']})" if result["benchmark_id"] else ""),
        f"System:      {_read_os_release().get('PRETTY_NAME') or 'unknown'}",
        f"Customized:  {'yes' if result['tailored'] else 'no'}",
        f"Generated:   {_iso(_now_utc())} by cockpit-oscap (bridge API {API_VERSION})",
        "",
        "Files",
        "-----",
    ]
    descriptions = {
        "summary.json": "the scan as the Compliance page records it, every rule result and the excluded rules",
        "rules.csv": "one row per evaluated rule",
        "results.arf.xml": "the scanner's Asset Reporting Format output, the primary evidence",
        "report.html": "the scanner's HTML report of this ARF",
        "tailoring.xml": "the customization the scan applied, with the justification of every change",
    }
    for member in members:
        if member.startswith("remediation/"):
            lines.append(f"{member}: a remediation run applied to this scan (script and record)")
        else:
            lines.append(f"{member}: {descriptions.get(member, '')}".rstrip(": "))
    if notes:
        lines += ["", "Notes", "-----", *notes]
    return "\n".join(lines) + "\n"


def _bundle_arf(bundle: zipfile.ZipFile, result: ScanResult, add: Callable[[str, str | bytes], None],
                members: list[str], notes: list[str]) -> None:
    """The ARF and what is derived from it: the report, and the customization the scan applied."""
    arf_path = result["arf_path"]
    if not arf_path or not Path(arf_path).is_file():
        notes.append("results.arf.xml: the scanner's output of this scan is no longer stored, "
                     "so there is no report.html and no tailoring.xml either")
        return
    bundle.write(arf_path, "results.arf.xml")  # streamed, not slurped: ARFs run to tens of MB
    members.append("results.arf.xml")
    try:
        add("report.html", generate_report(arf_path))
    except BridgeError as exc:
        notes.append(f"report.html: not rendered ({exc})")
    if not result["tailored"]:
        return
    try:
        tailoring = next(ET.parse(arf_path).getroot().iter(TAG_TAILORING), None)  # noqa: S314
    except (ET.ParseError, OSError) as exc:
        notes.append(f"tailoring.xml: the ARF could not be read ({exc})")
        return
    if tailoring is None:
        notes.append("tailoring.xml: the ARF does not carry the customization this scan applied")
    else:
        add("tailoring.xml", _serialize_tailoring(tailoring))


def _bundle_remediations(result_id: str, add: Callable[[str, str | bytes], None], notes: list[str]) -> None:
    """The scripts and records of every remediation run of the scan (root-only files)."""
    if not REMEDIATION_DIR.is_dir():
        return
    denied = False
    for script in sorted(REMEDIATION_DIR.glob("*.sh")):
        match = _REMEDIATION_NAME_RE.match(script.stem)
        if not match or match.group("result") != result_id:
            continue
        for path in (script, record_path_for(script)):
            if not path.is_file():
                continue
            try:
                add(f"remediation/{path.name}", path.read_bytes())
            except PermissionError:
                denied = True
    if denied:
        notes.append("remediation/: the scripts and records of this scan's remediation runs need "
                     "administrative access; export the bundle from an administrative session for them")


def export_bundle(result: ScanResult) -> tuple[str, bytes]:
    """(file name, ZIP bytes): everything recorded about a scan, for auditors and tickets."""
    members: list[str] = []
    notes: list[str] = []
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        def add(name: str, content: str | bytes) -> None:
            bundle.writestr(name, content)
            members.append(name)

        summary = {key: value for key, value in result.items() if key not in _BUNDLE_PRIVATE_KEYS}
        add("summary.json", json.dumps(summary, indent=1) + "\n")
        add("rules.csv", _rules_csv(result))
        _bundle_arf(bundle, result, add, members, notes)
        _bundle_remediations(result["id"], add, notes)
        bundle.writestr("README.txt", _bundle_readme(result, members, notes))
    return f"compliance-evidence-{result['id']}.zip", buffer.getvalue()


def cmd_export_bundle(args: list[str]) -> None:
    if not args:
        raise BridgeError("export-bundle requires a result id")
    filename, content = export_bundle(_load_result(args[0]))
    output_json({"id": args[0], "filename": filename, "content_base64": base64.b64encode(content).decode("ascii")})


# ---------------------------------------------------------------------------
# Scheduled scans (systemd timer)
# ---------------------------------------------------------------------------


def _systemctl_show(unit: str, properties: list[str]) -> dict[str, str]:
    rc, stdout, _stderr = run_cmd(["systemctl", "show", unit, f"--property={','.join(properties)}"])
    props: dict[str, str] = {}
    if rc != 0:
        return props
    for line in stdout.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            props[key] = value
    return props


def _parse_systemd_time(value: str) -> str:
    """Convert systemctl's 'Thu 2026-03-26 00:00:00 UTC' into ISO 8601 (local zone unless UTC)."""
    if not value or value in ("n/a", "0"):
        return ""
    match = re.match(r"^(?:\w{3} )?(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?: (\S+))?$", value.strip())
    if not match:
        return value
    naive = datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S")  # noqa: DTZ007
    zone = match.group(2) or ""
    aware = naive.replace(tzinfo=timezone.utc) if zone == "UTC" else naive.astimezone()
    return _iso(aware)


def _read_calendar_override() -> str:
    override = TIMER_OVERRIDE_DIR / "override.conf"
    if override.is_file():
        for line in override.read_text().splitlines():
            if line.startswith("OnCalendar=") and line[len("OnCalendar="):].strip():
                return line[len("OnCalendar="):].strip()
    return DEFAULT_TIMER_FREQUENCY


def get_timer_status() -> TimerStatus:
    timer = _systemctl_show(TIMER_UNIT, ["LoadState", "ActiveState", "UnitFileState", "NextElapseUSecRealtime",
                                        "LastTriggerUSec", "TimersCalendar"])
    service = _systemctl_show(SERVICE_UNIT, ["ActiveState", "Result", "ExecMainExitTimestamp"])
    installed = timer.get("LoadState", "not-found") not in ("not-found", "")
    calendar = _read_calendar_override()
    if not installed:
        calendar = ""
    return TimerStatus(
        status=timer.get("ActiveState", "unknown") if installed else "not-found",
        enabled=timer.get("UnitFileState", "") in ("enabled", "enabled-runtime", "linked", "static"),
        installed=installed,
        next_run=_parse_systemd_time(timer.get("NextElapseUSecRealtime", "")),
        last_run=_parse_systemd_time(timer.get("LastTriggerUSec", "")),
        calendar=calendar,
        service_state=service.get("ActiveState", "unknown"),
        service_result=service.get("Result", ""),
        last_scan_finished=_parse_systemd_time(service.get("ExecMainExitTimestamp", "")),
    )


def _normalize_time(value: str) -> str:
    match = re.match(r"^(\d{1,2}):(\d{1,2})(?::(\d{2}))?$", value.strip())
    if not match:
        raise BridgeError(f"invalid time: {value}")
    hour, minute = int(match.group(1)), int(match.group(2))
    if hour >= HOURS_PER_DAY or minute >= MINUTES_PER_HOUR:
        raise BridgeError(f"invalid time: {value}")
    return f"{hour:02d}:{minute:02d}:00"


def build_on_calendar(config: JsonDict) -> str:
    """Translate the schedule form into a systemd OnCalendar expression."""
    frequency = str(config.get("frequency", DEFAULT_TIMER_FREQUENCY))
    day = str(config.get("day", "") or "")
    time_str = _normalize_time(str(config.get("time", "") or "03:00"))

    if frequency == "custom":
        calendar = str(config.get("calendar", "") or "").strip()
        if not calendar:
            raise BridgeError("a custom schedule requires a calendar expression")
        check = validate_calendar(calendar)
        if not check["valid"]:
            raise BridgeError(check["error"] or f"invalid calendar expression: {calendar}")
        return check["normalized"] or calendar
    if frequency == "daily":
        return f"*-*-* {time_str}"
    if frequency == "weekly":
        weekday = day.title()[:3] if day else "Mon"
        if weekday not in WEEKDAYS:
            raise BridgeError(f"invalid day of week: {day}")
        return f"{weekday} *-*-* {time_str}"
    if frequency == "monthly":
        try:
            day_num = int(day or "1")
        except ValueError as exc:
            raise BridgeError(f"invalid day of month: {day}") from exc
        if not 1 <= day_num <= MAX_DAY_OF_MONTH:
            raise BridgeError(f"day of month must be between 1 and {MAX_DAY_OF_MONTH}")
        return f"*-*-{day_num:02d} {time_str}"
    raise BridgeError(f"unknown frequency: {frequency}")


def validate_calendar(spec: str) -> CalendarCheck:
    """Validate a calendar expression with systemd-analyze when available."""
    if not spec.strip() or "\n" in spec:
        return CalendarCheck(valid=False, normalized="", next_elapse="", error="empty calendar expression")
    analyze = shutil.which("systemd-analyze")
    if analyze is None:
        return CalendarCheck(valid=True, normalized=spec.strip(), next_elapse="", error="")
    rc, stdout, stderr = run_cmd([analyze, "calendar", "--", spec.strip()])
    if rc != 0:
        return CalendarCheck(valid=False, normalized="", next_elapse="",
                             error=(stderr or stdout).strip().splitlines()[-1] if (stderr or stdout).strip() else
                             "invalid calendar expression")
    normalized = ""
    next_elapse = ""
    for line in stdout.splitlines():
        key, _, value = line.partition(":")
        if key.strip() == "Normalized form":
            normalized = value.strip()
        elif key.strip() == "Next elapse":
            next_elapse = _parse_systemd_time(value.strip())
    return CalendarCheck(valid=True, normalized=normalized or spec.strip(), next_elapse=next_elapse, error="")


def _systemctl(*argv: str) -> None:
    rc, _stdout, stderr = run_cmd(["systemctl", *argv])
    if rc != 0:
        raise BridgeError(f"systemctl {' '.join(argv)} failed: {stderr.strip()[-ERROR_TAIL:]}")


def _timer_configure(config_json: str) -> None:
    raw = _parse_json_arg(config_json, "timer configuration")
    if not isinstance(raw, dict):
        raise BridgeError("timer configuration must be a JSON object")
    on_calendar = build_on_calendar(raw)
    profile_id = raw.get("profile_id")
    if profile_id is not None:
        if not isinstance(profile_id, str) or not XCCDF_ID_RE.match(profile_id):
            raise BridgeError("invalid profile id")
        save_config(_config_patch(load_config(), {"active_profile": profile_id}))
    _atomic_write(TIMER_OVERRIDE_DIR / "override.conf",
                  f"# Managed by cockpit-oscap\n[Timer]\nOnCalendar=\nOnCalendar={on_calendar}\n")
    _systemctl("daemon-reload")
    if get_timer_status()["status"] == "active":
        _systemctl("restart", TIMER_UNIT)


def cmd_manage_timer(args: list[str]) -> None:
    actions = ("status", "enable", "disable", "configure", "run-now")
    if not args or args[0] not in actions:
        raise BridgeError(f"manage-timer requires an action: {', '.join(actions)}")
    action = args[0]
    if action == "enable":
        _systemctl("enable", "--now", TIMER_UNIT)
    elif action == "disable":
        _systemctl("disable", "--now", TIMER_UNIT)
    elif action == "configure":
        if len(args) < REQUIRED_PAIR:
            raise BridgeError("manage-timer configure requires a JSON configuration argument")
        _timer_configure(args[1])
    elif action == "run-now":
        _systemctl("start", "--no-block", SERVICE_UNIT)
    output_json(get_timer_status())


def cmd_validate_calendar(args: list[str]) -> None:
    if not args:
        raise BridgeError("validate-calendar requires a calendar expression")
    output_json(validate_calendar(args[0]))


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

HANDLERS: dict[str, Callable[[list[str]], None]] = {
    "detect-backend": cmd_detect_backend,
    "get-config": cmd_get_config,
    "set-config": cmd_set_config,
    "list-profiles": cmd_list_profiles,
    "profile-rules": cmd_profile_rules,
    "rule-info": cmd_rule_info,
    "scan": cmd_scan,
    "list-results": cmd_list_results,
    "get-result": cmd_get_result,
    "delete-result": cmd_delete_result,
    "generate-report": cmd_generate_report,
    "generate-fix": cmd_generate_fix,
    "remediate": cmd_remediate,
    "create-tailoring": cmd_create_tailoring,
    "parse-tailoring": cmd_parse_tailoring,
    "import-tailoring": cmd_import_tailoring,
    "delete-tailoring": cmd_delete_tailoring,
    "tailor-rule": cmd_tailor_rule,
    "list-remediations": cmd_list_remediations,
    "rule-history": cmd_rule_history,
    "export-bundle": cmd_export_bundle,
    "manage-timer": cmd_manage_timer,
    "validate-calendar": cmd_validate_calendar,
}


def main(argv: list[str] | None = None) -> None:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        output_error(f"usage: oscap-bridge.py <command> [args...]; commands: {', '.join(HANDLERS)}")
        return
    command, args = argv[0], argv[1:]
    handler = HANDLERS.get(command)
    if handler is None:
        output_error(f"unknown command: {command}")
        return
    log.debug("command=%s args=%s", command, args)
    try:
        try:
            handler(args)
        except BridgeError as exc:
            output_error(str(exc))
        except BrokenPipeError:
            raise
        except Exception:
            log.error("command=%s unhandled exception:\n%s", command, traceback.format_exc())
            output_error(f"internal error: {traceback.format_exc().strip().splitlines()[-1]}")
    except BrokenPipeError:
        # Cockpit closed the channel (e.g. the scan was cancelled): nothing is listening any more
        _silence_stdout()
        log.warning("command=%s: the reader closed the output", command)
        sys.exit(1)


if __name__ == "__main__":
    main()
