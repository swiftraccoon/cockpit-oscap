/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Typed wrappers around the Python bridge (src/oscap-bridge.py).
 *
 * Every bridge command prints one JSON document on stdout; errors are
 * reported as {"error": "..."} with exit status 1.  Long running commands
 * (scan, remediate) stream newline-delimited progress objects first and
 * finish with {"type": "done", "result": ...}.
 *
 * All commands run with `superuser: "try"`, so Cockpit escalates through
 * polkit when the session has administrative access and falls back to
 * the unprivileged user otherwise.
 */

import cockpit from "cockpit";
import * as python from "python";

import bridgeScript from "./oscap-bridge.py";
import type {
    BackendInfo,
    BundleInfo,
    CalendarCheck,
    Config,
    ConfigPatch,
    FixInfo,
    FixType,
    ProfileInfo,
    ProfileRules,
    RemediateProgress,
    RemediateResult,
    RemediationRun,
    ReportInfo,
    ResultSummary,
    RuleDetail,
    RuleHistoryPoint,
    ScanProgress,
    ScanResult,
    TailoringInfo,
    TailoringModification,
    TimerConfig,
    TimerStatus,
} from "./types";

const _ = cockpit.gettext;

export const DATA_DIR = "/var/lib/cockpit-oscap";
export const RESULTS_DIR = `${DATA_DIR}/results`;
export const SCAN_STATE_PATH = `${DATA_DIR}/scan-state.json`;
export const TIMER_UNIT = "cockpit-oscap-scan.timer";
export const SERVICE_UNIT = "cockpit-oscap-scan.service";

/** An error reported by the bridge (or by the process running it). */
export class BridgeError extends Error {
    readonly exitStatus: number | null;
    readonly cancelled: boolean;

    constructor(message: string, exitStatus: number | null = null, cancelled = false) {
        super(message);
        this.name = "BridgeError";
        this.exitStatus = exitStatus;
        this.cancelled = cancelled;
    }
}

// ---------------------------------------------------------------------------
// Low-level plumbing
// ---------------------------------------------------------------------------

/* cockpit.spawn() rejects with (ProcessError, stdout) — the second argument
 * is not part of the standard Promise typing, so describe the subset we use. */
interface SpawnLike {
    then(fn: (data: string) => void): SpawnLike;
    catch(fn: (ex: unknown, data?: string) => void): SpawnLike;
    stream(fn: (data: string) => void): SpawnLike;
    input(data: string, stream: boolean): unknown;
    close(problem?: string): void;
}

interface ErrorObject { error: string }
interface ProgressLine { type: "progress" }
interface DoneLine<T> { type: "done"; result: T }

function parseJsonLine(line: string): unknown {
    try {
        return JSON.parse(line);
    } catch {
        return undefined;
    }
}

function lastJsonLine(text: string): unknown {
    const lines = text.split("\n").map(l => l.trim())
            .filter(l => l.length > 0);
    for (let i = lines.length - 1; i >= 0; i--) {
        const parsed = parseJsonLine(lines[i]);
        if (parsed !== undefined)
            return parsed;
    }
    return undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === "object" && value !== null;
}

function isErrorObject(value: unknown): value is ErrorObject {
    return isRecord(value) && typeof value.error === "string";
}

function isProgress(value: unknown): value is ProgressLine {
    return isRecord(value) && value.type === "progress";
}

function isDone<T>(value: unknown): value is DoneLine<T> {
    return isRecord(value) && value.type === "done" && "result" in value;
}

/** Turn a rejection from cockpit.spawn (plus any stdout captured) into a useful Error. */
export function toError(ex: unknown, data?: string): BridgeError {
    if (data) {
        const parsed = lastJsonLine(data);
        if (isErrorObject(parsed))
            return new BridgeError(parsed.error);
    }
    if (ex instanceof BridgeError)
        return ex;
    if (isRecord(ex)) {
        const problem = typeof ex.problem === "string" ? ex.problem : null;
        const exitStatus = typeof ex.exit_status === "number" ? ex.exit_status : null;
        if (problem === "cancelled")
            return new BridgeError(_("The operation was cancelled"), exitStatus, true);
        if (problem === "access-denied")
            return new BridgeError(_("Administrative access is required for this operation"), exitStatus);
        if (typeof ex.message === "string" && ex.message.trim())
            return new BridgeError(ex.message.trim(), exitStatus);
        if (problem)
            return new BridgeError(cockpit.message(problem), exitStatus);
    }
    if (ex instanceof Error)
        return new BridgeError(ex.message);
    return new BridgeError(String(ex));
}

function spawnBridge(args: string[], input?: string): SpawnLike {
    const proc = python.spawn(bridgeScript, args, { superuser: "try", err: "message" }) as unknown as SpawnLike;
    if (input !== undefined)
        proc.input(input, false);
    return proc;
}

/** Run a bridge command and resolve with its (single) JSON document. */
export function run<T>(command: string, args: string[] = [], input?: string): Promise<T> {
    return new Promise<T>((resolve, reject) => {
        spawnBridge([command, ...args], input)
                .then(out => {
                    const parsed = lastJsonLine(out);
                    if (parsed === undefined)
                        reject(new BridgeError(cockpit.format(_("The bridge returned no data for $0"), command)));
                    else if (isErrorObject(parsed))
                        reject(new BridgeError(parsed.error));
                    else
                        resolve(parsed as T);
                })
                .catch((ex, data) => reject(toError(ex, data)));
    });
}

export interface StreamHandle<T> {
    promise: Promise<T>;
    cancel: () => void;
}

/** Run a streaming bridge command, invoking onProgress for each progress line. */
export function stream<T, P extends ProgressLine>(
    command: string,
    args: string[],
    onProgress: (progress: P) => void,
): StreamHandle<T> {
    const proc = spawnBridge([command, ...args]);
    let buffer = "";
    let result: T | undefined;
    let error: BridgeError | undefined;

    const handleLine = (line: string) => {
        const parsed = parseJsonLine(line);
        if (isErrorObject(parsed))
            error = new BridgeError(parsed.error);
        else if (isDone<T>(parsed))
            result = parsed.result;
        else if (isProgress(parsed))
            onProgress(parsed as P);
    };

    proc.stream(chunk => {
        buffer += chunk;
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";
        lines.forEach(handleLine);
    });

    const promise = new Promise<T>((resolve, reject) => {
        proc
                .then(() => {
                    if (buffer.trim())
                        handleLine(buffer);
                    if (error)
                        reject(error);
                    else if (result !== undefined)
                        resolve(result);
                    else
                        reject(new BridgeError(cockpit.format(_("The bridge returned no result for $0"), command)));
                })
                .catch((ex, data) => {
                    if (buffer.trim())
                        handleLine(buffer);
                    reject(error ?? toError(ex, data));
                });
    });

    return { promise, cancel: () => proc.close("cancelled") };
}

// ---------------------------------------------------------------------------
// Backend and configuration
// ---------------------------------------------------------------------------

export const detectBackend = () => run<BackendInfo>("detect-backend");

export const getConfig = () => run<Config>("get-config");

export const setConfig = (patch: ConfigPatch) => run<Config>("set-config", [JSON.stringify(patch)]);

// ---------------------------------------------------------------------------
// Profiles and rules
// ---------------------------------------------------------------------------

function datastreamArgs(datastream?: string): string[] {
    return datastream ? ["--datastream", datastream] : [];
}

export const listProfiles = (datastream?: string) =>
    run<ProfileInfo[]>("list-profiles", datastreamArgs(datastream));

export const profileRules = (profileId: string, datastream?: string) =>
    run<ProfileRules>("profile-rules", [profileId, ...datastreamArgs(datastream)]);

/** How a rule fared in the last scans of a profile (against the given content), newest first. */
export const ruleHistory = (ruleId: string, baseProfileId: string, datastream?: string, limit = 20) =>
    run<RuleHistoryPoint[]>("rule-history", [ruleId, baseProfileId, "--limit", String(limit), ...datastreamArgs(datastream)]);

export const ruleInfo = (ruleId: string, datastream?: string) =>
    run<RuleDetail>("rule-info", [ruleId, ...datastreamArgs(datastream)]);

// ---------------------------------------------------------------------------
// Scanning and results
// ---------------------------------------------------------------------------

export interface ScanOptions {
    profileId?: string;
    datastream?: string;
    tailoringPath?: string;
    noTailoring?: boolean;
    /** Repeat an earlier scan: same profile, datastream and the tailoring recorded in its results. */
    rescanOf?: string;
}

export function scan(options: ScanOptions, onProgress: (progress: ScanProgress) => void): StreamHandle<ScanResult> {
    const args: string[] = [];
    if (options.profileId)
        args.push(options.profileId);
    args.push(...datastreamArgs(options.datastream));
    if (options.tailoringPath)
        args.push("--tailoring-path", options.tailoringPath);
    if (options.noTailoring)
        args.push("--no-tailoring");
    if (options.rescanOf)
        args.push("--rescan-of", options.rescanOf);
    args.push("--source", "interactive");
    return stream<ScanResult, ScanProgress>("scan", args, onProgress);
}

export const listResults = () => run<ResultSummary[]>("list-results");

export const getResult = (id: string) => run<ScanResult>("get-result", [id]);

export const deleteResult = (id: string) => run<{ deleted: boolean; id: string }>("delete-result", [id]);

export const generateReport = (id: string) => run<ReportInfo>("generate-report", [id]);

// ---------------------------------------------------------------------------
// Remediation
// ---------------------------------------------------------------------------

export const generateFix = (id: string, type: FixType = "bash") =>
    run<FixInfo>("generate-fix", [id, "--type", type]);

/** Remediation runs recorded on this system, newest first, optionally only those of one scan. */
export const listRemediations = (resultId?: string) =>
    run<RemediationRun[]>("list-remediations", resultId ? [resultId] : []);

export function remediate(
    id: string,
    ruleIds: string[],
    onProgress: (progress: RemediateProgress) => void,
): StreamHandle<RemediateResult> {
    return stream<RemediateResult, RemediateProgress>("remediate", [id, "--rules", JSON.stringify(ruleIds)], onProgress);
}

// ---------------------------------------------------------------------------
// Tailoring
// ---------------------------------------------------------------------------

export const createTailoring = (baseProfileId: string, modifications: TailoringModification[], datastream?: string) =>
    run<TailoringInfo>("create-tailoring",
                       [baseProfileId, JSON.stringify(modifications), ...datastreamArgs(datastream)]);

export const parseTailoring = (xml: string) => run<TailoringInfo>("parse-tailoring", ["-"], xml);

/** Everything recorded about a scan (ARF, report, CSV, tailoring, remediation records) as a ZIP. */
export const exportBundle = (id: string) => run<BundleInfo>("export-bundle", [id]);

export const parseTailoringFile = (path: string) => run<TailoringInfo>("parse-tailoring", [path]);

export const importTailoring = (baseProfileId: string, xml: string) =>
    run<TailoringInfo>("import-tailoring", [baseProfileId, "-"], xml);

export const deleteTailoring = (baseProfileId: string) =>
    run<{ deleted: boolean; profile_id: string }>("delete-tailoring", [baseProfileId]);

/**
 * Enable or disable one rule in the profile's customization, keeping the rest; `remark` is the
 * justification. The customization applies to the installed content, which is what it is checked against.
 */
export const tailorRule = (baseProfileId: string, ruleId: string, enabled: boolean, remark: string) =>
    run<TailoringInfo>("tailor-rule", [baseProfileId, ruleId, enabled ? "enable" : "disable",
        ...remark ? ["--remark", remark] : []]);

// ---------------------------------------------------------------------------
// Scheduled scans
// ---------------------------------------------------------------------------

export function manageTimer(action: "status" | "enable" | "disable" | "run-now"): Promise<TimerStatus>;
export function manageTimer(action: "configure", config: TimerConfig): Promise<TimerStatus>;
export function manageTimer(action: string, config?: TimerConfig): Promise<TimerStatus> {
    const args = [action];
    if (action === "configure" && config)
        args.push(JSON.stringify(config));
    return run<TimerStatus>("manage-timer", args);
}

export const validateCalendar = (spec: string) => run<CalendarCheck>("validate-calendar", [spec]);

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

/** Read a file owned by root (ARF results, tailoring XML) as text. */
export function readFile(path: string): Promise<string> {
    return cockpit.file(path, { superuser: "try" }).read()
            .then(content => {
                if (content === null || content === undefined)
                    throw new BridgeError(cockpit.format(_("$0 does not exist"), path));
                return content;
            });
}
