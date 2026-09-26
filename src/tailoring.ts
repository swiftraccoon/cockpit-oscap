/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * The profile editor's state and its translation to and from XCCDF tailoring
 * modifications: pure functions, unit-tested without a browser.
 */

import cockpit from "cockpit";

import { ruleShortName } from "./helpers";
import type { RuleInfo, TailoringModification, ValueInfo, ValueOption } from "./types";

const _ = cockpit.gettext;

/** The bridge's limit for a justification (MAX_REMARK_LENGTH there). */
export const MAX_REMARK_LENGTH = 4000;

export interface EditorState {
    /** Rule id → enabled. */
    selection: Record<string, boolean>;
    /** Value id → its text. */
    values: Record<string, string>;
    /**
     * Rule id → why it was enabled or disabled. Only meaningful (and saved) for rules whose selection
     * differs from the profile's; a rule toggled back to its default keeps the text so that toggling
     * it again restores the justification.
     */
    remarks: Record<string, string>;
}

export interface ChangeDescription {
    key: string;
    item: string;
    change: string;
    remark: string;
    /** The remark is the one being dropped, not a new one. */
    remarkRemoved: boolean;
}

/** How a value option is named everywhere: "5 minutes (300)". */
export function optionLabel(option: ValueOption): string {
    return `${option.selector.replace(/_/g, " ")} (${option.value || _("empty")})`;
}

/** The editor state for the profile as the content defines it. */
export function baseState(rules: RuleInfo[], values: ValueInfo[]): EditorState {
    const state: EditorState = { selection: {}, values: {}, remarks: {} };
    rules.forEach(rule => { state.selection[rule.id] = rule.selected });
    values.forEach(value => { state.values[value.id] = value.value });
    return state;
}

/**
 * The state with a tailoring file's modifications applied; unknown rules and values are ignored, and
 * so is a remark on a select that does not change the rule (nothing in the editor could show it).
 */
export function applyModifications(base: EditorState, values: ValueInfo[], mods: TailoringModification[]): EditorState {
    const state: EditorState = { selection: { ...base.selection }, values: { ...base.values }, remarks: { ...base.remarks } };
    const valuesById = new Map(values.map(v => [v.id, v]));
    for (const mod of mods) {
        if (mod.action === "select" || mod.action === "unselect") {
            if (!(mod.idref in state.selection))
                continue;
            const selected = mod.action === "select";
            state.selection[mod.idref] = selected;
            if (mod.remark && base.selection[mod.idref] !== selected)
                state.remarks[mod.idref] = mod.remark;
            else
                delete state.remarks[mod.idref];
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

/** The remark that counts for a rule: none while the rule sits at the profile default. */
function effectiveRemark(state: EditorState, profile: EditorState, id: string): string {
    return state.selection[id] === profile.selection[id] ? "" : (state.remarks[id] ?? "").trim();
}

/**
 * The modifications that turn `base` into `current`: a select or unselect per rule whose selection or
 * justification differs, a refine-value where the text is one of the content's options, else a
 * set-value. `profile` is the state the content defines, which decides whether a justification counts;
 * it is `base` itself when computing what to save.
 */
export function computeModifications(base: EditorState, current: EditorState, values: ValueInfo[],
    profile: EditorState = base): TailoringModification[] {
    const mods: TailoringModification[] = [];
    for (const [id, selected] of Object.entries(current.selection)) {
        const remark = effectiveRemark(current, profile, id);
        if (base.selection[id] !== selected || effectiveRemark(base, profile, id) !== remark)
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

/** The state with rules enabled or disabled; their justifications stay for when they are toggled back. */
export function withRuleSelection(state: EditorState, ids: string[], selected: boolean): EditorState {
    const selection = { ...state.selection };
    ids.forEach(id => { selection[id] = selected });
    return { ...state, selection };
}

/** The state with one rule's justification replaced (removed when blank). */
export function withRemark(state: EditorState, id: string, remark: string): EditorState {
    const remarks = { ...state.remarks };
    if (remark.trim())
        remarks[id] = remark;
    else
        delete remarks[id];
    return { ...state, remarks };
}

/**
 * A value as the review dialog shows it: by option name when it is one of the content's choices
 * (the chosen selector when known, else the only option with that value), quoted otherwise.
 */
export function describeValue(value: ValueInfo | undefined, text: string, selector?: string): string {
    const candidates = value?.options.filter(o => o.value === text) ?? [];
    const option = selector ? candidates.find(o => o.selector === selector) : candidates.length === 1 ? candidates[0] : undefined;
    if (option)
        return optionLabel(option);
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
            const item = ruleTitle.get(mod.idref) ?? mod.idref;
            const remark = mod.remark ?? "";
            if (base.selection[mod.idref] !== enabled)
                return { key: mod.idref, item, change: enabled ? _("Rule enabled") : _("Rule disabled"), remark, remarkRemoved: false };
            if (remark)
                return { key: mod.idref, item, change: _("Justification changed"), remark, remarkRemoved: false };
            return {
                key: mod.idref,
                item,
                change: _("Justification removed"),
                remark: (base.remarks[mod.idref] ?? "").trim(),
                remarkRemoved: true,
            };
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
            remarkRemoved: false,
        };
    });
}
