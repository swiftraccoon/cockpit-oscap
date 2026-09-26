/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * systemd OnCalendar expressions as the schedule page reads and describes them.
 */

import cockpit from "cockpit";

import * as timeformat from "timeformat";

import type { ScheduleFrequency } from "./types";

const _ = cockpit.gettext;

export const WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
export const DEFAULT_TIME = "03:00";

export interface ParsedCalendar {
    frequency: ScheduleFrequency;
    weekday: string;
    monthday: number;
    time: string;
    calendar: string;
}

/** Localized weekday name for a systemd weekday abbreviation. */
export function weekdayName(short: string, style: "long" | "short" = "long"): string {
    const index = WEEKDAYS.indexOf(short);
    if (index < 0)
        return short;
    // 2024-01-01 is a Monday
    const date = new Date(2024, 0, 1 + index, 12);
    return timeformat.formatter({ weekday: style }).format(date);
}

/** Interpret the OnCalendar expression written by the bridge (or the packaged default). */
export function parseCalendar(raw: string): ParsedCalendar {
    const defaults: ParsedCalendar = { frequency: "weekly", weekday: "Mon", monthday: 1, time: DEFAULT_TIME, calendar: raw };
    const spec = raw.trim();
    if (!spec || spec === "weekly")
        return { ...defaults, time: "00:00" };
    if (spec === "daily")
        return { ...defaults, frequency: "daily", time: "00:00" };
    if (spec === "monthly")
        return { ...defaults, frequency: "monthly", time: "00:00" };

    let match = /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun) \*-\*-\* (\d{2}):(\d{2}):\d{2}$/.exec(spec);
    if (match)
        return { ...defaults, frequency: "weekly", weekday: match[1], time: `${match[2]}:${match[3]}` };
    match = /^\*-\*-\* (\d{2}):(\d{2}):\d{2}$/.exec(spec);
    if (match)
        return { ...defaults, frequency: "daily", time: `${match[1]}:${match[2]}` };
    match = /^\*-\*-(\d{2}) (\d{2}):(\d{2}):\d{2}$/.exec(spec);
    if (match)
        return { ...defaults, frequency: "monthly", monthday: parseInt(match[1], 10), time: `${match[2]}:${match[3]}` };
    return { ...defaults, frequency: "custom" };
}

export function describeCalendar(raw: string): string {
    const parsed = parseCalendar(raw);
    switch (parsed.frequency) {
    case "daily":
        return cockpit.format(_("Daily at $0"), parsed.time);
    case "weekly":
        return cockpit.format(_("Weekly on $0 at $1"), weekdayName(parsed.weekday), parsed.time);
    case "monthly":
        return cockpit.format(_("Monthly on day $0 at $1"), parsed.monthday, parsed.time);
    default:
        return raw;
    }
}
