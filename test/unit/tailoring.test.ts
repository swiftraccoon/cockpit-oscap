/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
    applyModifications,
    baseState,
    computeModifications,
    describeModifications,
    describeValue,
    statesEqual,
    withRemark,
    withRuleSelection,
} from "../../src/tailoring";
import type { RuleInfo, ValueInfo } from "../../src/types";

const rule = (id: string, selected: boolean): RuleInfo => ({
    id, title: `Rule ${id}`, severity: "medium", description: "", selected, group: "", group_path: [], has_fix: false,
});
const RULES = [rule("a", true), rule("b", false)];
const TIMEOUT: ValueInfo = {
    id: "timeout",
    title: "Session timeout",
    description: "",
    type: "number",
    default: "600",
    value: "600",
    selector: "10_minutes",
    set_value: null,
    options: [
        { selector: "10_minutes", value: "600" },
        { selector: "5_minutes", value: "300" },
        { selector: "default", value: "300" },
        { selector: "none", value: "" },
    ],
};
const VALUES = [TIMEOUT];

describe("editor state", () => {
    it("starts from the profile as the content defines it", () => {
        assert.deepEqual(baseState(RULES, VALUES), {
            selection: { a: true, b: false }, values: { timeout: "600" }, remarks: {},
        });
    });

    it("applies a tailoring file, remarks included, and ignores unknown ids", () => {
        const state = applyModifications(baseState(RULES, VALUES), VALUES, [
            { idref: "a", action: "unselect", remark: "handled elsewhere" },
            { idref: "zzz", action: "select" },
            { idref: "timeout", action: "refine-value", selector: "5_minutes" },
            { idref: "other", action: "set-value", value: "1" },
        ]);
        assert.deepEqual(state, { selection: { a: false, b: false }, values: { timeout: "300" }, remarks: { a: "handled elsewhere" } });
        // a select without a remark drops an earlier one
        const cleared = applyModifications(state, VALUES, [{ idref: "a", action: "unselect" }]);
        assert.deepEqual(cleared.remarks, {});
    });

    it("derives modifications from what differs, with remarks on selects only", () => {
        const base = baseState(RULES, VALUES);
        let current = withRuleSelection(base, base, ["a", "b"], false);
        current = withRemark(current, "a", "  handled elsewhere ");
        current = { ...current, values: { timeout: "300" } };
        assert.deepEqual(computeModifications(base, current, VALUES), [
            { idref: "a", action: "unselect", remark: "handled elsewhere" },
            { idref: "timeout", action: "refine-value", selector: "5_minutes" },
        ]);
        assert.deepEqual(computeModifications(base, { ...base, values: { timeout: "42" } }, VALUES),
                         [{ idref: "timeout", action: "set-value", value: "42" }]);
        // a changed remark alone is a modification too (it is what the review dialog lists)
        const reworded = withRemark(current, "a", "ticket 42");
        assert.deepEqual(computeModifications(current, reworded, VALUES), [{ idref: "a", action: "unselect", remark: "ticket 42" }]);
    });

    it("drops the remark of a rule back at its profile default", () => {
        const base = baseState(RULES, VALUES);
        const disabled = withRemark(withRuleSelection(base, base, ["a"], false), "a", "why");
        assert.equal(disabled.remarks.a, "why");
        const restored = withRuleSelection(disabled, base, ["a"], true);
        assert.deepEqual(restored.remarks, {});
        assert.deepEqual(withRemark(disabled, "a", "   ").remarks, {});
        assert.equal(statesEqual(restored, base), true);
        assert.equal(statesEqual(disabled, withRuleSelection(base, base, ["a"], false)), false);
        assert.equal(statesEqual(null, base), false);
    });
});

describe("change descriptions", () => {
    it("names values by their chosen option and quotes free text", () => {
        assert.equal(describeValue(TIMEOUT, "600"), "10 minutes (600)");
        assert.equal(describeValue(TIMEOUT, "300", "default"), "default (300)");
        assert.equal(describeValue(TIMEOUT, "300"), '"300"');  // two options share it: no guess
        assert.equal(describeValue(TIMEOUT, "", "none"), "none (empty)");
        assert.equal(describeValue(TIMEOUT, ""), "none (empty)");  // the only option with that value
        assert.equal(describeValue(TIMEOUT, "42"), '"42"');
        assert.equal(describeValue(undefined, "x"), '"x"');
        assert.equal(describeValue(undefined, ""), "(empty)");
    });

    it("describes rule, justification and value changes", () => {
        const base = baseState(RULES, VALUES);
        let current = withRemark(withRuleSelection(base, base, ["a"], false), "a", "handled elsewhere");
        current = { ...current, values: { timeout: "300" } };
        const mods = computeModifications(base, current, VALUES);
        assert.deepEqual(describeModifications(mods, RULES, VALUES, base, current), [
            { key: "a", item: "Rule a", change: "Rule disabled", remark: "handled elsewhere" },
            { key: "timeout", item: "Session timeout", change: "Value changed from 10 minutes (600) to 5 minutes (300)", remark: "" },
        ]);
        const reworded = withRemark(current, "a", "ticket 42");
        assert.deepEqual(describeModifications(computeModifications(current, reworded, VALUES), RULES, VALUES, current, reworded),
                         [{ key: "a", item: "Rule a", change: "Justification changed", remark: "ticket 42" }]);
        const removed = withRemark(current, "a", "");
        assert.deepEqual(describeModifications(computeModifications(current, removed, VALUES), RULES, VALUES, current, removed),
                         [{ key: "a", item: "Rule a", change: "Justification removed", remark: "" }]);
    });
});
