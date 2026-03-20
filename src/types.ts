/*
 * TypeScript interfaces mirroring the Python TypedDicts in oscap-bridge.py.
 *
 * Keep in sync with the bridge — any field added/removed/renamed there
 * must be reflected here.
 */

// ---------------------------------------------------------------------------
// Enums as string unions
// ---------------------------------------------------------------------------

/** Risk classification for remediation scripts. */
export type RiskLevel = "low" | "medium" | "high" | "critical";

/** Possible results for a single SCAP rule evaluation. */
export type RuleResultStatus =
    | "pass"
    | "fail"
    | "error"
    | "notapplicable"
    | "notchecked"
    | "notselected"
    | "informational"
    | "fixed";

// ---------------------------------------------------------------------------
// detect-backend
// ---------------------------------------------------------------------------

/** Information about the oscap binary. */
export interface OscapInfo {
    version: string;
    path: string;
}

/** Information about the complyctl binary. */
export interface ComplyctlInfo {
    version: string;
    path: string;
}

/** Information about installed SCAP content. */
export interface ContentInfo {
    datastream_path: string;
    present: boolean;
}

/** Response shape for detect-backend command. */
export interface BackendInfo {
    oscap: OscapInfo;
    complyctl: ComplyctlInfo | null;
    content: ContentInfo;
}

// ---------------------------------------------------------------------------
// list-profiles / profile-rules
// ---------------------------------------------------------------------------

/** Profile metadata from an XCCDF datastream. */
export interface ProfileInfo {
    id: string;
    title: string;
    description: string;
    rule_count: number;
}

/** Rule metadata from an XCCDF datastream. */
export interface RuleInfo {
    id: string;
    title: string;
    severity: string;
    description: string;
    selected: boolean;
}

// ---------------------------------------------------------------------------
// scan
// ---------------------------------------------------------------------------

/** A single rule's evaluation result from an ARF report. */
export interface RuleResultItem {
    rule_id: string;
    result: string;
    title: string;
    severity: string;
}

/** Response shape for the scan command. */
export interface ScanResult {
    score: number;
    results: RuleResultItem[];
    arf_path: string;
    json_path: string;
    timestamp: string;
    profile_id: string;
    status: string;
}

// ---------------------------------------------------------------------------
// generate-fix / apply-fix
// ---------------------------------------------------------------------------

/** Per-rule fix snippet with risk classification. */
export interface FixRuleInfo {
    id: string;
    fix_snippet: string;
    risk_level: string;
}

/** Response shape for the generate-fix command. */
export interface FixInfo {
    script: string;
    rules: FixRuleInfo[];
}

/** Response shape for the apply-fix command. */
export interface ApplyResult {
    success: boolean;
    output: string;
    errors: string;
}

// ---------------------------------------------------------------------------
// Tailoring
// ---------------------------------------------------------------------------

/** A single rule modification inside a tailoring profile. */
export interface TailoringModification {
    rule_id: string;
    action: string;
    value?: string;
}

/** Response shape for the create-tailoring command. */
export interface TailoringResult {
    tailoring_xml: string;
    path: string;
}

/** Response shape for the parse-tailoring command. */
export interface ParsedTailoring {
    base_profile: string;
    modifications: TailoringModification[];
}

// ---------------------------------------------------------------------------
// Timer management
// ---------------------------------------------------------------------------

/** Response shape for manage-timer status/enable/disable/configure. */
export interface TimerStatus {
    status: string;
    next_run: string;
    frequency: string;
}

// ---------------------------------------------------------------------------
// Error / Config
// ---------------------------------------------------------------------------

/** Error response from the bridge. */
export interface ErrorResponse {
    error: string;
}

/** Persistent configuration stored in /var/lib/cockpit-oscap/config.json. */
export interface Config {
    active_profile?: string;
    [key: string]: string | undefined;
}
