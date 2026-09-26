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
    optionLabel,
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
const BASE = baseState(RULES, VALUES);

describe("editor state", () => {
    it("starts from the profile as the content defines it", () => {
        assert.deepEqual(BASE, { selection: { a: true, b: false }, values: { timeout: "600" }, remarks: {} });
    });

    it("applies a tailoring file, remarks included, and ignores unknown ids", () => {
        const state = applyModifications(BASE, VALUES, [
            { idref: "a", action: "unselect", remark: "handled elsewhere" },
            { idref: "zzz", action: "select" },
            { idref: "timeout", action: "refine-value", selector: "5_minutes" },
            { idref: "other", action: "set-value", value: "1" },
        ]);
        assert.deepEqual(state, { selection: { a: false, b: false }, values: { timeout: "300" }, remarks: { a: "handled elsewhere" } });
        // a select without a remark drops an earlier one
        assert.deepEqual(applyModifications(state, VALUES, [{ idref: "a", action: "unselect" }]).remarks, {});
        // a remark on a select that changes nothing (another tool's file) is not a customization
        assert.deepEqual(applyModifications(BASE, VALUES, [{ idref: "a", action: "select", remark: "noted" }]), BASE);
    });

    it("derives modifications from what differs, with remarks on selects only", () => {
        let current = withRuleSelection(BASE, ["a", "b"], false);
        current = withRemark(current, "a", "  handled elsewhere ");
        current = { ...current, values: { timeout: "300" } };
        assert.deepEqual(computeModifications(BASE, current, VALUES), [
            { idref: "a", action: "unselect", remark: "handled elsewhere" },
            { idref: "timeout", action: "refine-value", selector: "5_minutes" },
        ]);
        assert.deepEqual(computeModifications(BASE, { ...BASE, values: { timeout: "42" } }, VALUES),
                         [{ idref: "timeout", action: "set-value", value: "42" }]);
        // a changed remark alone is a modification too (it is what the review dialog lists)
        const reworded = withRemark(current, "a", "ticket 42");
        assert.deepEqual(computeModifications(current, reworded, VALUES, BASE), [{ idref: "a", action: "unselect", remark: "ticket 42" }]);
        // whitespace around a remark is not a change
        assert.deepEqual(computeModifications(current, withRemark(current, "a", "handled elsewhere"), VALUES, BASE), []);
    });

    it("keeps a justification through a double toggle and only saves it while the rule differs", () => {
        const disabled = withRemark(withRuleSelection(BASE, ["a"], false), "a", "why");
        const restored = withRuleSelection(disabled, ["a"], true);
        assert.equal(restored.remarks.a, "why");
        // back at the profile default: nothing to save, nothing pending against the saved state
        assert.deepEqual(computeModifications(BASE, restored, VALUES), []);
        assert.deepEqual(computeModifications(disabled, withRuleSelection(restored, ["a"], false), VALUES, BASE), []);
        assert.deepEqual(withRemark(disabled, "a", "   ").remarks, {});
    });
});

describe("change descriptions", () => {
    it("names values by their chosen option and quotes free text", () => {
        assert.equal(optionLabel({ selector: "5_minutes", value: "300" }), "5 minutes (300)");
        assert.equal(optionLabel({ selector: "none", value: "" }), "none (empty)");
        assert.equal(describeValue(TIMEOUT, "600"), "10 minutes (600)");
        assert.equal(describeValue(TIMEOUT, "300", "default"), "default (300)");
        assert.equal(describeValue(TIMEOUT, "300"), '"300"');  // two options share it: no guess
        assert.equal(describeValue(TIMEOUT, ""), "none (empty)");  // the only option with that value
        assert.equal(describeValue(TIMEOUT, "42"), '"42"');
        assert.equal(describeValue(undefined, "x"), '"x"');
        assert.equal(describeValue(undefined, ""), "(empty)");
    });

    it("describes rule, justification and value changes", () => {
        let current = withRemark(withRuleSelection(BASE, ["a"], false), "a", "handled elsewhere");
        current = { ...current, values: { timeout: "300" } };
        const mods = computeModifications(BASE, current, VALUES);
        assert.deepEqual(describeModifications(mods, RULES, VALUES, BASE, current), [
            { key: "a", item: "Rule a", change: "Rule disabled", remark: "handled elsewhere", remarkRemoved: false },
            {
                key: "timeout",
                item: "Session timeout",
                change: "Value changed from 10 minutes (600) to 5 minutes (300)",
                remark: "",
                remarkRemoved: false,
            },
        ]);
        const reworded = withRemark(current, "a", "ticket 42");
        assert.deepEqual(describeModifications(computeModifications(current, reworded, VALUES, BASE), RULES, VALUES, current, reworded),
                         [{ key: "a", item: "Rule a", change: "Justification changed", remark: "ticket 42", remarkRemoved: false }]);
        // dropping a justification shows which one goes
        const removed = withRemark(current, "a", "");
        assert.deepEqual(describeModifications(computeModifications(current, removed, VALUES, BASE), RULES, VALUES, current, removed),
                         [{ key: "a", item: "Rule a", change: "Justification removed", remark: "handled elsewhere", remarkRemoved: true }]);
    });
});
