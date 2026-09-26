/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * The profile editor's state and its translation to and from XCCDF tailoring
 * modifications: pure functions, unit-tested without a browser.
 */

import cockpit from "cockpit";

import { ruleShortName } from "./helpers";
import type { RuleInfo, TailoringModification, ValueInfo } from "./types";

const _ = cockpit.gettext;

export interface EditorState {
    /** Rule id → enabled. */
    selection: Record<string, boolean>;
    /** Value id → its text. */
    values: Record<string, string>;
    /** Rule id → why it was enabled or disabled (only for rules whose selection differs from the profile). */
    remarks: Record<string, string>;
}

export interface ChangeDescription {
    key: string;
    item: string;
    change: string;
    remark: string;
}

/** The editor state for the profile as the content defines it. */
export function baseState(rules: RuleInfo[], values: ValueInfo[]): EditorState {
    const state: EditorState = { selection: {}, values: {}, remarks: {} };
    rules.forEach(rule => { state.selection[rule.id] = rule.selected });
    values.forEach(value => { state.values[value.id] = value.value });
    return state;
}

/** The state with a tailoring file's modifications applied; unknown rules and values are ignored. */
export function applyModifications(base: EditorState, values: ValueInfo[], mods: TailoringModification[]): EditorState {
    const state: EditorState = { selection: { ...base.selection }, values: { ...base.values }, remarks: { ...base.remarks } };
    const valuesById = new Map(values.map(v => [v.id, v]));
    for (const mod of mods) {
        if (mod.action === "select" || mod.action === "unselect") {
            if (mod.idref in state.selection) {
                state.selection[mod.idref] = mod.action === "select";
                if (mod.remark)
                    state.remarks[mod.idref] = mod.remark;
                else
                    delete state.remarks[mod.idref];
            }
        } else if (mod.action === "refine-value") {
            const option = valuesById.get(mod.idref)?.options.find(o => o.selector === mod.selector);
            if (option)
                state.values[mod.idref] = option.value;
        } else if (mod.action === "set-value" && mod.idref in state.values) {
            state.values[mod.idref] = mod.value ?? "";
        }
    }
    return state;
}

/**
 * The modifications that turn `base` into `current`: a select or unselect per rule whose selection or
 * remark differs, a refine-value where the text is one of the content's options, else a set-value.
 */
export function computeModifications(base: EditorState, current: EditorState, values: ValueInfo[]): TailoringModification[] {
    const mods: TailoringModification[] = [];
    for (const [id, selected] of Object.entries(current.selection)) {
        const remark = (current.remarks[id] ?? "").trim();
        if (base.selection[id] !== selected || (base.remarks[id] ?? "") !== remark)
            mods.push({ idref: id, action: selected ? "select" : "unselect", ...remark && { remark } });
    }
    for (const value of values) {
        const text = current.values[value.id] ?? "";
        if (text === base.values[value.id])
            continue;
        const option = value.options.find(o => o.value === text);
        mods.push(option
            ? { idref: value.id, action: "refine-value", selector: option.selector }
            : { idref: value.id, action: "set-value", value: text });
    }
    return mods;
}

/** The state with one rule enabled or disabled; a rule back at its profile default loses its remark. */
export function withRuleSelection(state: EditorState, base: EditorState, ids: string[], selected: boolean): EditorState {
    const selection = { ...state.selection };
    const remarks = { ...state.remarks };
    for (const id of ids) {
        selection[id] = selected;
        if (base.selection[id] === selected)
            delete remarks[id];
    }
    return { ...state, selection, remarks };
}

/** The state with one rule's remark replaced (removed when blank). */
export function withRemark(state: EditorState, id: string, remark: string): EditorState {
    const remarks = { ...state.remarks };
    if (remark.trim())
        remarks[id] = remark;
    else
        delete remarks[id];
    return { ...state, remarks };
}

export function statesEqual(a: EditorState | null, b: EditorState | null): boolean {
    if (!a || !b)
        return a === b;
    return JSON.stringify(a.selection) === JSON.stringify(b.selection) &&
        JSON.stringify(a.values) === JSON.stringify(b.values) &&
        JSON.stringify(a.remarks) === JSON.stringify(b.remarks);
}

/**
 * A value as the review dialog shows it: by option name when it is one of the content's choices
 * (the chosen selector when known, else the only option with that value), quoted otherwise.
 */
export function describeValue(value: ValueInfo | undefined, text: string, selector?: string): string {
    const candidates = value?.options.filter(o => o.value === text) ?? [];
    const option = selector ? candidates.find(o => o.selector === selector) : candidates.length === 1 ? candidates[0] : undefined;
    if (option)
        return `${option.selector.replace(/_/g, " ")} (${text || _("empty")})`;
    return text === "" ? _("(empty)") : JSON.stringify(text);
}

/** One line per pending customization, for the review dialog. */
export function describeModifications(mods: TailoringModification[], rules: RuleInfo[], values: ValueInfo[],
    base: EditorState, current: EditorState): ChangeDescription[] {
    const ruleTitle = new Map(rules.map(r => [r.id, r.title || ruleShortName(r.id)]));
    const valuesById = new Map(values.map(v => [v.id, v]));
    return mods.map(mod => {
        if (mod.action === "select" || mod.action === "unselect") {
            const enabled = mod.action === "select";
            const remark = mod.remark ?? "";
            let change: string;
            if (base.selection[mod.idref] !== enabled)
                change = enabled ? _("Rule enabled") : _("Rule disabled");
            else if (remark)
                change = _("Justification changed");
            else
                change = _("Justification removed");
            return { key: mod.idref, item: ruleTitle.get(mod.idref) ?? mod.idref, change, remark };
        }
        const value = valuesById.get(mod.idref);
        const before = base.values[mod.idref] ?? "";
        return {
            key: mod.idref,
            item: value?.title || mod.idref,
            change: cockpit.format(_("Value changed from $0 to $1"),
                                   // the content's own selector names the untouched value
                                   describeValue(value, before, value && before === value.value ? value.selector : undefined),
                                   describeValue(value, current.values[mod.idref] ?? "", mod.selector)),
            remark: "",
        };
    });
}
