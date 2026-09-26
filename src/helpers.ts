/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

import cockpit from "cockpit";

import type { ResultCounts, ResultSummary, RuleResultItem, RuleResultStatus, Severity } from "./types";

const _ = cockpit.gettext;

export type ScoreVariant = "success" | "warning" | "danger";

export const SCORE_GOOD = 90;
export const SCORE_FAIR = 70;

export function scoreVariant(score: number): ScoreVariant {
    if (score >= SCORE_GOOD)
        return "success";
    if (score >= SCORE_FAIR)
        return "warning";
    return "danger";
}

export function formatScore(score: number): string {
    return cockpit.format("$0%", Number.isInteger(score) ? score.toString() : score.toFixed(1));
}

/** "xccdf_org.ssgproject.content_profile_ospp" -> "ospp" */
export function profileShortName(profileId: string): string {
    const match = /_profile_(.+)$/.exec(profileId);
    if (match)
        return match[1];
    const parts = profileId.split("_");
    return parts[parts.length - 1] || profileId;
}

/** "xccdf_org.ssgproject.content_rule_sshd_disable_root_login" -> "sshd_disable_root_login" */
export function ruleShortName(ruleId: string): string {
    const match = /_rule_(.+)$/.exec(ruleId);
    return match ? match[1] : ruleId;
}

export const SEVERITIES: Severity[] = ["high", "medium", "low", "unknown"];

export function normalizeSeverity(severity: string): Severity {
    const lower = severity.toLowerCase();
    return (SEVERITIES as string[]).includes(lower) ? lower as Severity : "unknown";
}

export function severityLabel(severity: string): string {
    switch (normalizeSeverity(severity)) {
    case "high":
        return _("High");
    case "medium":
        return _("Medium");
    case "low":
        return _("Low");
    default:
        return _("Unknown");
    }
}

const SEVERITY_ORDER: Record<Severity, number> = { high: 0, medium: 1, low: 2, unknown: 3 };

export function compareSeverity(a: string, b: string): number {
    return SEVERITY_ORDER[normalizeSeverity(a)] - SEVERITY_ORDER[normalizeSeverity(b)];
}

export function normalizeResult(result: string): RuleResultStatus {
    switch (result) {
    case "pass":
    case "fail":
    case "error":
    case "notapplicable":
    case "notchecked":
    case "informational":
    case "fixed":
        return result;
    default:
        return "unknown";
    }
}

export function resultLabel(result: string): string {
    switch (normalizeResult(result)) {
    case "pass":
        return _("Pass");
    case "fail":
        return _("Fail");
    case "error":
        return _("Error");
    case "notapplicable":
        return _("Not applicable");
    case "notchecked":
        return _("Not checked");
    case "informational":
        return _("Informational");
    case "fixed":
        return _("Fixed");
    default:
        return _("Unknown");
    }
}

export type RuleChange = "fixed" | "regressed" | "changed";

const FAILING = ["fail", "error"];
const PASSING = ["pass", "fixed"];

/** How a rule's result moved since an earlier scan, or null when it did not (or was not evaluated before). */
export function ruleChange(before: string | undefined, after: string): RuleChange | null {
    if (before === undefined)
        return null;
    const was = normalizeResult(before);
    const now = normalizeResult(after);
    if (was === now)
        return null;
    if (FAILING.includes(now) && !FAILING.includes(was))
        return "regressed";
    if (FAILING.includes(was) && PASSING.includes(now))
        return "fixed";
    return "changed";
}

export function emptyCounts(): ResultCounts {
    return { pass: 0, fail: 0, error: 0, notapplicable: 0, notchecked: 0, informational: 0, fixed: 0, unknown: 0 };
}

/** Rules that were actually evaluated (pass, fail or error). */
export function scoredTotal(counts: ResultCounts): number {
    return counts.pass + counts.fail + counts.error;
}

/** A copy of `set` with `member` added or removed. */
export function withMember<T>(set: Set<T>, member: T, present: boolean): Set<T> {
    const next = new Set(set);
    if (present)
        next.add(member);
    else
        next.delete(member);
    return next;
}

/**
 * One [base profile id, title] pair per profile that has been scanned, sorted by title. The title comes
 * from the newest scan without customizations when there is one, so a tailored name does not stand
 * for the whole profile.
 */
export function profileChoices(summaries: ResultSummary[]): [string, string][] {
    const best = new Map<string, ResultSummary>();
    for (const summary of summaries) {
        const current = best.get(summary.base_profile_id);
        const better = !current ||
            (current.tailored && !summary.tailored) ||
            (current.tailored === summary.tailored && summary.timestamp > current.timestamp);
        if (better)
            best.set(summary.base_profile_id, summary);
    }
    return Array.from(best.values(), (s): [string, string] => [s.base_profile_id, s.profile_title || s.base_profile_id])
            .sort((a, b) => a[1].localeCompare(b[1]));
}

/** "45 seconds", "2 minutes", "1 hour 5 minutes": how long something took, coarsely. */
export function formatDuration(seconds: number): string {
    const total = Math.max(0, Math.round(seconds));
    if (total < 60)
        return cockpit.format(cockpit.ngettext("$0 second", "$0 seconds", total), total);
    const minutes = Math.round(total / 60);
    if (minutes < 60)
        return cockpit.format(cockpit.ngettext("$0 minute", "$0 minutes", minutes), minutes);
    const hours = Math.floor(minutes / 60);
    const rest = minutes % 60;
    const hoursText = cockpit.format(cockpit.ngettext("$0 hour", "$0 hours", hours), hours);
    return rest === 0 ? hoursText : cockpit.format("$0 $1", hoursText, cockpit.format(cockpit.ngettext("$0 minute", "$0 minutes", rest), rest));
}

export interface HistoryCounts { failed: number; passed: number; skipped: number; other: number }

/** How often a rule failed, passed, was skipped or otherwise reported across scans (for a history strip). */
export function countHistory(points: { result: string }[]): HistoryCounts {
    const counts: HistoryCounts = { failed: 0, passed: 0, skipped: 0, other: 0 };
    for (const point of points) {
        const kind = normalizeResult(point.result);
        if (kind === "fail" || kind === "error")
            counts.failed += 1;
        else if (kind === "pass" || kind === "fixed")
            counts.passed += 1;
        else if (point.result === "notselected")
            counts.skipped += 1;
        else
            counts.other += 1;
    }
    return counts;
}

/** "Last 8 scans: 5 failed, 3 passed" (parts a translator can order, joined as a list). */
export function describeHistory(points: { result: string }[]): string {
    const counts = countHistory(points);
    const parts = [
        cockpit.format(_("$0 failed"), counts.failed),
        cockpit.format(_("$0 passed"), counts.passed),
        ...counts.skipped > 0 ? [cockpit.format(_("$0 not evaluated"), counts.skipped)] : [],
        ...counts.other > 0 ? [cockpit.format(_("$0 other"), counts.other)] : [],
    ];
    return cockpit.format(cockpit.ngettext("Last $0 scan: $1", "Last $0 scans: $1", points.length), points.length, parts.join(", "));
}

/** A rule result as the history strip names it ("notselected" is "Not evaluated" there). */
export function historyResultLabel(result: string): string {
    return result === "notselected" ? _("Not evaluated") : resultLabel(result);
}

interface SeriesMember { base_profile_id: string; datastream: string }

/** Scans of the same profile against the same content form a series; only those compare. */
export function sameSeries(a: SeriesMember, b: SeriesMember): boolean {
    return a.base_profile_id === b.base_profile_id && sameContent(a.datastream, b.datastream);
}

/**
 * The scans a result can be compared with: complete scans of its series taken before it, newest
 * first (so the first one is the immediately preceding scan).
 */
export function comparableScans(result: SeriesMember & { id: string; timestamp: string },
    summaries: ResultSummary[]): ResultSummary[] {
    const at = parseTimestamp(result.timestamp)?.getTime() ?? 0;
    const timed = summaries
            .map(s => ({ s, time: parseTimestamp(s.timestamp)?.getTime() ?? 0 }))
            .filter(({ s, time }) => s.id !== result.id && sameSeries(s, result) && s.status === "complete" && time < at);
    return timed.sort((a, b) => b.time - a.time).map(({ s }) => s);
}

/** Results from before the content path was recorded (empty) belong to every series. */
export function sameContent(a: string, b: string): boolean {
    return !a || !b || a === b;
}

function csvCell(value: string): string {
    // a leading =, +, -, @ or control character would make spreadsheets evaluate the cell as a formula
    const text = /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

/** Every rule result of a scan as CSV (RFC 4180), for spreadsheets and audit evidence. */
export function resultsToCsv(result: { results: RuleResultItem[] }): string {
    const rows = [["rule_id", "title", "result", "severity", "category", "message"]];
    for (const rule of result.results)
        rows.push([rule.rule_id, rule.title, rule.result, rule.severity, rule.group, rule.message]);
    return rows.map(row => row.map(csvCell).join(",")).join("\r\n") + "\r\n";
}

/** The bytes of a base64 string (what the bridge sends binary content as). */
export function decodeBase64(text: string): Uint8Array<ArrayBuffer> {
    const binary = atob(text);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++)
        bytes[i] = binary.charCodeAt(i);
    return bytes;
}

/** Offer `content` as a download named `filename`. */
export function downloadFile(filename: string, content: string | Uint8Array<ArrayBuffer>,
    type = "application/octet-stream"): void {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    // give the browser a moment to start the download before revoking
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** A file name fragment safe for downloads: keeps letters, digits, dot, dash and underscore. */
export function safeFilename(text: string): string {
    return text.replace(/[^A-Za-z0-9._-]+/g, "_");
}

/** Parse an ISO timestamp from the bridge; returns null when missing or invalid. */
export function parseTimestamp(value: string | undefined | null): Date | null {
    if (!value)
        return null;
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? null : date;
}

/** Hostname of a URL, used to label references compactly. */
export function referenceSource(href: string): string {
    try {
        return new URL(href).hostname.replace(/^www\./, "");
    } catch {
        return href;
    }
}

/** Case-insensitive substring match across several fields. */
export function matchesSearch(needle: string, ...fields: string[]): boolean {
    if (!needle)
        return true;
    const lower = needle.toLowerCase();
    return fields.some(field => field.toLowerCase().includes(lower));
}

export function errorMessage(error: unknown): string {
    if (error instanceof Error)
        return error.message;
    return String(error);
}
