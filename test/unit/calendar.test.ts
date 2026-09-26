/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { describeCalendar, parseCalendar } from "../../src/calendar";

describe("parseCalendar", () => {
    it("understands the bridge's own expressions", () => {
        assert.deepEqual(parseCalendar("Mon *-*-* 03:00:00"),
                         { frequency: "weekly", weekday: "Mon", monthday: 1, time: "03:00", calendar: "Mon *-*-* 03:00:00" });
        assert.deepEqual(parseCalendar("*-*-* 22:30:00"),
                         { frequency: "daily", weekday: "Mon", monthday: 1, time: "22:30", calendar: "*-*-* 22:30:00" });
        assert.deepEqual(parseCalendar("*-*-15 04:00:00"),
                         { frequency: "monthly", weekday: "Mon", monthday: 15, time: "04:00", calendar: "*-*-15 04:00:00" });
    });

    it("maps systemd shorthands to midnight", () => {
        assert.equal(parseCalendar("weekly").time, "00:00");
        assert.equal(parseCalendar("daily").frequency, "daily");
        assert.equal(parseCalendar("monthly").frequency, "monthly");
        assert.equal(parseCalendar("").frequency, "weekly");
    });

    it("keeps anything else as a custom expression", () => {
        const parsed = parseCalendar("*-*-1..7 04:00:00");
        assert.equal(parsed.frequency, "custom");
        assert.equal(parsed.calendar, "*-*-1..7 04:00:00");
    });
});

describe("describeCalendar", () => {
    it("describes the regular schedules and echoes custom ones", () => {
        assert.equal(describeCalendar("*-*-* 22:30:00"), "Daily at 22:30");
        assert.match(describeCalendar("Mon *-*-* 03:00:00"), /^Weekly on \w+ at 03:00$/);
        assert.equal(describeCalendar("*-*-15 04:00:00"), "Monthly on day 15 at 04:00");
        assert.equal(describeCalendar("*-*-1..7 04:00:00"), "*-*-1..7 04:00:00");
    });
});
