/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * TypeScript shapes mirroring the TypedDicts in src/oscap-bridge.py.
 * Keep the two in sync: a field added, removed or renamed in the bridge
 * must be reflected here.
 */

// ---------------------------------------------------------------------------
// detect-backend
// ---------------------------------------------------------------------------

export interface ToolInfo {
    version: string;
    path: string;
}

export interface DatastreamInfo {
    path: string;
    name: string;
    product: string;
}

export interface OsInfo {
    id: string;
    version_id: string;
    pretty_name: string;
}

export type ContentSource = "config" | "detected" | "fallback" | "none";

export interface ContentInfo {
    datastream_path: string;
    present: boolean;
    source: ContentSource;
    available: DatastreamInfo[];
    os: OsInfo;
}

export interface BackendInfo {
    api_version: number;
    oscap: ToolInfo | null;
    complyctl: ToolInfo | null;
    content: ContentInfo;
    privileged: boolean;
    data_dir: string;
}

// ---------------------------------------------------------------------------
// Configuration (config.json)
// ---------------------------------------------------------------------------

export interface Config {
    active_profile?: string;
    datastream?: string;
    max_results?: number;
    tailorings?: Record<string, string>;
}

export interface ConfigPatch {
    active_profile?: string | null;
    datastream?: string | null;
    max_results?: number | null;
}

// ---------------------------------------------------------------------------
// Profiles, rules and values
// ---------------------------------------------------------------------------

export interface ProfileInfo {
    id: string;
    title: string;
    description: string;
    rule_count: number;
    extends: string | null;
    tailoring_path: string | null;
    tailored_profile_id: string | null;
    /** Why the registered customization is not applied ("" when it is, or there is none). */
    tailoring_problem: string;
}

export type Severity = "high" | "medium" | "low" | "unknown";

export interface RuleInfo {
    id: string;
    title: string;
    severity: string;
    description: string;
    selected: boolean;
    group: string;
    group_path: string[];
    has_fix: boolean;
}

export interface ValueOption {
    selector: string;
    value: string;
}

export interface ValueInfo {
    id: string;
    title: string;
    description: string;
    type: string;
    default: string;
    value: string;
    selector: string;
    set_value: string | null;
    options: ValueOption[];
}

export interface ProfileRules {
    profile_id: string;
    title: string;
    rules: RuleInfo[];
    values: ValueInfo[];
}

export interface Reference {
    href: string;
    text: string;
}

export interface Ident {
    system: string;
    text: string;
}

export interface RuleDetail {
    id: string;
    title: string;
    severity: string;
    description: string;
    rationale: string;
    warnings: string[];
    references: Reference[];
    idents: Ident[];
    group_path: string[];
    has_fix: boolean;
    fix_systems: string[];
}

// ---------------------------------------------------------------------------
// Scan results
// ---------------------------------------------------------------------------

export type RuleResultStatus =
    | "pass"
    | "fail"
    | "error"
    | "notapplicable"
    | "notchecked"
    | "informational"
    | "fixed"
    | "unknown";

export const RESULT_KINDS: RuleResultStatus[] = [
    "pass", "fail", "error", "notapplicable", "notchecked", "informational", "fixed", "unknown",
];

export type ResultCounts = Record<RuleResultStatus, number>;

export interface RuleResultItem {
    rule_id: string;
    result: string;
    title: string;
    severity: string;
    group: string;
    message: string;
}

export type ScanStatus = "complete" | "interrupted" | string;

export interface ScanResult {
    id: string;
    timestamp: string;
    start_time: string;
    end_time: string;
    profile_id: string;
    profile_title: string;
    base_profile_id: string;
    benchmark_id: string;
    benchmark_version: string;
    datastream: string;
    tailoring_path: string | null;
    tailored: boolean;
    test_result_id: string;
    status: ScanStatus;
    score: number;
    xccdf_score: number | null;
    counts: ResultCounts;
    results: RuleResultItem[];
    arf_path: string;
    json_path: string;
}

export interface ResultSummary {
    id: string;
    timestamp: string;
    profile_id: string;
    base_profile_id: string;
    profile_title: string;
    score: number;
    counts: ResultCounts;
    total: number;
    status: ScanStatus;
    tailored: boolean;
    has_arf: boolean;
}

export interface ReportInfo {
    id: string;
    html: string;
}

// ---------------------------------------------------------------------------
// Streaming progress (scan / remediate) and the scan-state.json file
// ---------------------------------------------------------------------------

export interface ScanProgress {
    type: "progress";
    running: true;
    pid: number;
    source: "interactive" | "scheduled" | string;
    profile_id: string;
    profile_title: string;
    started: string;
    current: number;
    total: number;
    progress: number;
    rule_id: string;
    result: string;
}

export interface ScanState {
    running: boolean;
    status?: "complete" | "failed" | "cancelled";
    source?: string;
    profile_id?: string;
    profile_title?: string;
    started?: string;
    finished?: string;
    current?: number;
    total?: number;
    progress?: number;
    rule_id?: string;
    result_id?: string;
    score?: number;
    counts?: ResultCounts;
    error?: string;
    pid?: number;
}

export interface RemediateProgress {
    type: "progress";
    current: number;
    total: number;
    rule_id: string;
}

// ---------------------------------------------------------------------------
// Remediation
// ---------------------------------------------------------------------------

export type RiskLevel = "low" | "medium" | "high";

export interface FixRuleInfo {
    id: string;
    title: string;
    fix_snippet: string;
    risk_level: RiskLevel | string;
    risk_reason: string;
    has_fix: boolean;
}

export type FixType = "bash" | "ansible";

export interface FixInfo {
    result_id: string;
    fix_type: FixType;
    /** The full script (Bash) or playbook (Ansible) as generated by oscap. */
    script: string;
    /** Per-rule blocks; only Bash scripts are split into rules. */
    rules: FixRuleInfo[];
}

export interface RuleRemediation {
    rule_id: string;
    success: boolean;
    exit_status: number;
    output: string;
    errors: string;
}

export interface RemediateResult {
    result_id: string;
    success: boolean;
    script_path: string;
    rules: RuleRemediation[];
}

// ---------------------------------------------------------------------------
// Tailoring
// ---------------------------------------------------------------------------

export type TailoringAction = "select" | "unselect" | "set-value" | "refine-value";

export interface TailoringModification {
    idref: string;
    action: TailoringAction;
    value?: string;
    selector?: string;
}

export interface TailoringInfo {
    path: string;
    profile_id: string;
    base_profile_id: string;
    title: string;
    benchmark_href: string;
    modifications: TailoringModification[];
    tailoring_xml: string;
    warning: string;
}

// ---------------------------------------------------------------------------
// Scheduled scans
// ---------------------------------------------------------------------------

export interface TimerStatus {
    status: string;
    enabled: boolean;
    installed: boolean;
    next_run: string;
    last_run: string;
    calendar: string;
    service_state: string;
    service_result: string;
    last_scan_finished: string;
}

export type ScheduleFrequency = "daily" | "weekly" | "monthly" | "custom";

export interface TimerConfig {
    frequency: ScheduleFrequency;
    day?: string;
    time?: string;
    calendar?: string;
    profile_id?: string;
}

export interface CalendarCheck {
    valid: boolean;
    normalized: string;
    next_elapse: string;
    error: string;
}
