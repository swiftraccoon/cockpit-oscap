/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
    comparableScans,
    emptyCounts,
    formatDuration,
    formatScore,
    matchesSearch,
    parseTimestamp,
    profileChoices,
    profileShortName,
    resultsToCsv,
    ruleChange,
    ruleShortName,
    safeFilename,
    sameContent,
    scoreVariant,
    scoredTotal,
    withMember,
} from "../../src/helpers";

describe("score thresholds", () => {
    it("maps scores to the three variants", () => {
        assert.equal(scoreVariant(100), "success");
        assert.equal(scoreVariant(90), "success");
        assert.equal(scoreVariant(89.9), "warning");
        assert.equal(scoreVariant(70), "warning");
        assert.equal(scoreVariant(69.9), "danger");
        assert.equal(scoreVariant(0), "danger");
    });

    it("formats whole and fractional scores", () => {
        assert.equal(formatScore(100), "100%");
        assert.equal(formatScore(56.789), "56.8%");
    });
});

describe("ruleChange", () => {
    it("ignores rules without a previous result or without a change", () => {
        assert.equal(ruleChange(undefined, "fail"), null);
        assert.equal(ruleChange("fail", "fail"), null);
        assert.equal(ruleChange("pass", "pass"), null);
    });

    it("classifies transitions", () => {
        assert.equal(ruleChange("fail", "pass"), "fixed");
        assert.equal(ruleChange("error", "fixed"), "fixed");
        assert.equal(ruleChange("pass", "fail"), "regressed");
        assert.equal(ruleChange("notchecked", "fail"), "regressed");
        assert.equal(ruleChange("notapplicable", "error"), "regressed");
        assert.equal(ruleChange("fail", "notapplicable"), "changed");
        assert.equal(ruleChange("pass", "notchecked"), "changed");
    });
});

describe("resultsToCsv", () => {
    const csv = resultsToCsv({
        results: [
            { rule_id: "r1", title: 'Quote "me", please', result: "fail", severity: "high", group: "SSH", message: "" },
            { rule_id: "r2", title: "=HYPERLINK(\"http://evil\")", result: "pass", severity: "low", group: "", message: "line1\nline2" },
        ],
    });
    const lines = csv.split("\r\n");

    it("starts with a header and ends with a line break", () => {
        assert.equal(lines[0], "rule_id,title,result,severity,category,message");
        assert.ok(csv.endsWith("\r\n"));
    });

    it("quotes commas, quotes and line breaks", () => {
        assert.equal(lines[1], 'r1,"Quote ""me"", please",fail,high,SSH,');
    });

    it("neutralizes cells a spreadsheet would evaluate as formulas", () => {
        assert.ok(lines[2].startsWith("r2,\"'=HYPERLINK("));
        assert.ok(csv.includes('"line1\nline2"'));
    });
});

describe("small helpers", () => {
    it("matches searches against any field, case-insensitively", () => {
        assert.equal(matchesSearch("", "anything"), true);
        assert.equal(matchesSearch("SSH", "Disable root login", "xccdf_org.ssgproject.content_rule_sshd_x"), true);
        assert.equal(matchesSearch("firewall", "Disable root login", "sshd"), false);
    });

    it("parses ISO timestamps and rejects junk", () => {
        assert.equal(parseTimestamp("2026-09-26T00:07:37+00:00")?.toISOString(), "2026-09-26T00:07:37.000Z");
        assert.equal(parseTimestamp(""), null);
        assert.equal(parseTimestamp(undefined), null);
        assert.equal(parseTimestamp("not a date"), null);
    });

    it("shortens ids and sanitizes file names", () => {
        assert.equal(profileShortName("xccdf_org.ssgproject.content_profile_cis"), "cis");
        assert.equal(ruleShortName("xccdf_org.ssgproject.content_rule_sshd_disable_root_login"), "sshd_disable_root_login");
        assert.match(safeFilename("2026-09-26T00:07:37 weird/name"), /^[A-Za-z0-9._-]+$/);
    });

    it("treats a missing content path as matching any series", () => {
        assert.equal(sameContent("", "/a.xml"), true);
        assert.equal(sameContent("/a.xml", "/a.xml"), true);
        assert.equal(sameContent("/a.xml", "/b.xml"), false);
    });

    it("copies a set with a member added or removed", () => {
        const base = new Set(["a"]);
        assert.deepEqual([...withMember(base, "b", true)], ["a", "b"]);
        assert.deepEqual([...withMember(base, "a", false)], []);
        assert.deepEqual([...base], ["a"]);  // untouched
    });

    it("offers the complete earlier scans of a series for comparison, newest first", () => {
        const scan = (id: string, base: string, status = "complete", datastream = "/ds.xml") => ({
            id,
            // ids are compact, the recorded timestamps ISO 8601
            timestamp: `${id.slice(0, 11)}${id.slice(11, 13)}:${id.slice(13, 15)}:${id.slice(15, 17)}+00:00`,
            base_profile_id: base,
            profile_title: base,
            tailored: false,
            profile_id: base,
            datastream,
            duration_seconds: 0,
            score: 0,
            counts: emptyCounts(),
            total: 0,
            status,
            has_arf: true,
        });
        const current = scan("2026-04-05T000000-cis", "cis");
        const summaries = [
            scan("2026-04-06T000000-cis", "cis"),  // later: not a comparison
            current,
            scan("2026-04-03T000000-cis", "cis"),
            scan("2026-04-04T000000-cis", "cis", "interrupted"),
            scan("2026-04-04T000000-anssi", "anssi"),
            scan("2026-04-02T000000-cis", "cis", "complete", "/other.xml"),
            scan("2026-04-01T000000-cis", "cis", "complete", ""),  // content unknown: any series
        ];
        assert.deepEqual(comparableScans(current, summaries).map(s => s.id),
                         ["2026-04-03T000000-cis", "2026-04-01T000000-cis"]);
        assert.deepEqual(comparableScans(current, [current]), []);
    });

    it("names each scanned profile after its newest scan without customizations", () => {
        const scan = (id: string, base: string, title: string, tailored: boolean) => ({
            id,
            timestamp: id.slice(0, 17),
            base_profile_id: base,
            profile_title: title,
            tailored,
            profile_id: tailored ? `${base}_customized` : base,
            datastream: "",
            duration_seconds: 0,
            score: 0,
            counts: emptyCounts(),
            total: 0,
            status: "complete" as const,
            has_arf: true,
        });
        const choices = profileChoices([
            scan("2026-04-03T000000-cis", "cis", "CIS (customized)", true),
            scan("2026-04-02T000000-cis", "cis", "CIS Benchmark", false),
            scan("2026-04-01T000000-cis", "cis", "CIS Benchmark (old title)", false),
            scan("2026-04-01T000000-anssi", "anssi", "", false),
        ]);
        assert.deepEqual(choices, [["anssi", "anssi"], ["cis", "CIS Benchmark"]]);
        assert.deepEqual(profileChoices([]), []);
    });

    it("describes durations coarsely", () => {
        assert.equal(formatDuration(0), "0 seconds");
        assert.equal(formatDuration(1), "1 second");
        assert.equal(formatDuration(59.4), "59 seconds");
        assert.equal(formatDuration(150), "3 minutes");
        assert.equal(formatDuration(3600), "1 hour");
        assert.equal(formatDuration(3900), "1 hour 5 minutes");
    });

    it("counts only evaluated rules toward the total", () => {
        assert.equal(scoredTotal({ ...emptyCounts(), pass: 2, fail: 1, error: 1, notapplicable: 3, notchecked: 2 }), 4);
    });
});
