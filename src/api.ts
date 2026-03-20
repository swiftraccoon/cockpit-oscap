/*
 * Typed API layer wrapping cockpit.spawn() calls to oscap-bridge.py.
 *
 * Each function corresponds to one bridge command.  All calls run
 * with `superuser: "try"` so Cockpit can elevate via polkit when the
 * user session lacks privileges.
 */

import cockpit from "cockpit";

import bridgeScript from "./oscap-bridge.py";

import type {
    ApplyResult,
    BackendInfo,
    Config,
    FixInfo,
    ParsedTailoring,
    ProfileInfo,
    RuleInfo,
    ScanResult,
    TailoringModification,
    TailoringResult,
    TimerStatus,
} from "./types";

// ---------------------------------------------------------------------------
// Generic spawn helper
// ---------------------------------------------------------------------------

const CONFIG_PATH = "/var/lib/cockpit-oscap/config.json";

/**
 * Spawn the Python bridge with the given command and arguments,
 * parse the JSON response, and return it typed as `T`.
 */
function spawn<T>(command: string, ...args: string[]): Promise<T> {
    console.debug(`[cockpit-oscap] spawn: ${command}`, args);
    return cockpit
            .spawn(
                ["python3", "-c", bridgeScript, command, ...args],
                { superuser: "try", err: "message" },
            )
            .then(raw => {
                let parsed: T;
                try {
                    parsed = JSON.parse(raw) as T;
                } catch (e) {
                    console.error(`[cockpit-oscap] ${command}: invalid JSON response:`, raw);
                    throw new Error(`Bridge returned invalid JSON for ${command}`);
                }
                console.debug(`[cockpit-oscap] ${command}: success`);
                return parsed;
            })
            .catch(error => {
                console.error(`[cockpit-oscap] ${command}: failed:`, error);
                throw error;
            });
}

// ---------------------------------------------------------------------------
// Public API functions
// ---------------------------------------------------------------------------

/** Detect installed oscap/complyctl binaries and SCAP content. */
export function detectBackend(): Promise<BackendInfo> {
    return spawn<BackendInfo>("detect-backend");
}

/** List available XCCDF profiles from the datastream. */
export function listProfiles(datastreamPath?: string): Promise<ProfileInfo[]> {
    const args: string[] = [];
    if (datastreamPath !== undefined) {
        args.push(datastreamPath);
    }
    return spawn<ProfileInfo[]>("list-profiles", ...args);
}

/** List rules for a specific profile. */
export function profileRules(profileId: string, datastreamPath?: string): Promise<RuleInfo[]> {
    const args = [profileId];
    if (datastreamPath !== undefined) {
        args.push(datastreamPath);
    }
    return spawn<RuleInfo[]>("profile-rules", ...args);
}

/** Run an OpenSCAP scan. */
export function scan(
    profileId?: string,
    options?: { tailoringPath?: string; datastream?: string },
): Promise<ScanResult> {
    const args: string[] = [];
    if (profileId !== undefined) {
        args.push(profileId);
    }
    if (options?.tailoringPath !== undefined) {
        args.push("--tailoring-path", options.tailoringPath);
    }
    if (options?.datastream !== undefined) {
        args.push("--datastream", options.datastream);
    }
    return spawn<ScanResult>("scan", ...args);
}

/** Generate a bash remediation fix script for a profile. */
export function generateFix(profileId: string, datastreamPath?: string): Promise<FixInfo> {
    const args = [profileId];
    if (datastreamPath !== undefined) {
        args.push(datastreamPath);
    }
    return spawn<FixInfo>("generate-fix", ...args);
}

/** Apply a previously generated fix script. */
export function applyFix(scriptPath: string): Promise<ApplyResult> {
    return spawn<ApplyResult>("apply-fix", scriptPath);
}

/** Create a tailoring file from a base profile and modifications. */
export function createTailoring(
    baseProfileId: string,
    modifications: TailoringModification[],
): Promise<TailoringResult> {
    return spawn<TailoringResult>(
        "create-tailoring",
        baseProfileId,
        JSON.stringify(modifications),
    );
}

/** Parse an existing tailoring XML file. */
export function parseTailoring(tailoringPath: string): Promise<ParsedTailoring> {
    return spawn<ParsedTailoring>("parse-tailoring", tailoringPath);
}

/** Manage the systemd scan timer (status/enable/disable/configure). */
export function manageTimer(
    action: "status" | "enable" | "disable",
): Promise<TimerStatus>;
export function manageTimer(
    action: "configure",
    config: { frequency?: string; day?: string; time?: string; profile_id?: string },
): Promise<TimerStatus>;
export function manageTimer(
    action: string,
    config?: { frequency?: string; day?: string; time?: string; profile_id?: string },
): Promise<TimerStatus> {
    if (action === "configure" && config !== undefined) {
        return spawn<TimerStatus>("manage-timer", action, JSON.stringify(config));
    }
    return spawn<TimerStatus>("manage-timer", action);
}

/** Read the persistent config from /var/lib/cockpit-oscap/config.json. */
export function loadConfig(): Promise<Config> {
    return cockpit
            .file(CONFIG_PATH, { superuser: "try" })
            .read()
            .then(content => {
                if (content === null || content === undefined) {
                    return {} as Config;
                }
                return JSON.parse(content) as Config;
            });
}
