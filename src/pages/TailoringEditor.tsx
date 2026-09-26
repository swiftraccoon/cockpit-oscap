/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Profile editor: enable or disable rules and adjust values, saved as an
 * XCCDF tailoring file that scans of this profile apply automatically.
 */

import React, { useEffect, useMemo, useRef, useState } from "react";
import { Alert, AlertActionCloseButton } from "@patternfly/react-core/dist/esm/components/Alert/index.js";
import { Breadcrumb, BreadcrumbItem } from "@patternfly/react-core/dist/esm/components/Breadcrumb/index.js";
import { Button } from "@patternfly/react-core/dist/esm/components/Button/index.js";
import { Content } from "@patternfly/react-core/dist/esm/components/Content/index.js";
import { DropdownItem } from "@patternfly/react-core/dist/esm/components/Dropdown/index.js";
import { FormSelect, FormSelectOption } from "@patternfly/react-core/dist/esm/components/FormSelect/index.js";
import { Label } from "@patternfly/react-core/dist/esm/components/Label/index.js";
import { PageSection } from "@patternfly/react-core/dist/esm/components/Page/index.js";
import { SearchInput } from "@patternfly/react-core/dist/esm/components/SearchInput/index.js";
import { Switch } from "@patternfly/react-core/dist/esm/components/Switch/index.js";
import { Tab, Tabs, TabTitleText } from "@patternfly/react-core/dist/esm/components/Tabs/index.js";
import { TextInput } from "@patternfly/react-core/dist/esm/components/TextInput/index.js";
import { Toolbar, ToolbarContent, ToolbarItem } from "@patternfly/react-core/dist/esm/components/Toolbar/index.js";
import { Flex, FlexItem } from "@patternfly/react-core/dist/esm/layouts/Flex/index.js";
import { Stack, StackItem } from "@patternfly/react-core/dist/esm/layouts/Stack/index.js";
import { SortByDirection } from "@patternfly/react-table";
import cockpit from "cockpit";

import { ListingTable } from "cockpit-components-table";
import type { ListingTableRowProps, RowRecord } from "cockpit-components-table";
import { SimpleSelect } from "cockpit-components-simple-select";
import { useDialogs } from "dialogs";

import { createTailoring, deleteTailoring, importTailoring, listProfiles, parseTailoringFile, profileRules } from "../api";
import { useApp } from "../app";
import { useAsync } from "../app-hooks";
import { ActionsMenu } from "../components/ActionsMenu";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { SeverityLabel } from "../components/labels";
import { RuleDetails } from "../components/RuleDetails";
import { ErrorAlert, ErrorState, Loading } from "../components/states";
import {
    SEVERITIES,
    compareSeverity,
    downloadFile,
    errorMessage,
    matchesSearch,
    normalizeSeverity,
    profileShortName,
    ruleShortName,
    safeFilename,
    severityLabel,
} from "../helpers";
import type { RuleInfo, TailoringInfo, TailoringModification, ValueInfo } from "../types";

const _ = cockpit.gettext;

interface EditorState {
    selection: Record<string, boolean>;
    values: Record<string, string>;
}

type StateFilter = "all" | "selected" | "unselected" | "changed";
const CUSTOM = "__custom__";

function baseState(rules: RuleInfo[], values: ValueInfo[]): EditorState {
    const state: EditorState = { selection: {}, values: {} };
    rules.forEach(rule => { state.selection[rule.id] = rule.selected });
    values.forEach(value => { state.values[value.id] = value.value });
    return state;
}

function applyModifications(base: EditorState, values: ValueInfo[], mods: TailoringModification[]): EditorState {
    const state: EditorState = { selection: { ...base.selection }, values: { ...base.values } };
    const valuesById = new Map(values.map(v => [v.id, v]));
    for (const mod of mods) {
        if (mod.action === "select" || mod.action === "unselect") {
            if (mod.idref in state.selection)
                state.selection[mod.idref] = mod.action === "select";
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

function computeModifications(base: EditorState, current: EditorState, values: ValueInfo[]): TailoringModification[] {
    const mods: TailoringModification[] = [];
    for (const [id, selected] of Object.entries(current.selection)) {
        if (base.selection[id] !== selected)
            mods.push({ idref: id, action: selected ? "select" : "unselect" });
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

function statesEqual(a: EditorState | null, b: EditorState | null): boolean {
    if (!a || !b)
        return a === b;
    return JSON.stringify(a.selection) === JSON.stringify(b.selection) &&
        JSON.stringify(a.values) === JSON.stringify(b.values);
}

export const TailoringEditor = ({ profileId }: { profileId: string }) => {
    const app = useApp();
    const Dialogs = useDialogs();
    const data = useAsync(async () => {
        const [rules, profiles] = await Promise.all([profileRules(profileId), listProfiles()]);
        const info = profiles.find(p => p.id === profileId);
        // only a customization the bridge will actually apply is loaded into the editor
        const tailoring: TailoringInfo | null = info?.tailored_profile_id && info.tailoring_path
            ? await parseTailoringFile(info.tailoring_path)
            : null;
        return { rules, tailoring, problem: info?.tailoring_problem ?? "" };
    }, [profileId]);

    const [tab, setTab] = useState<"rules" | "values">("rules");
    const [current, setCurrent] = useState<EditorState | null>(null);
    const [expandedRules, setExpandedRules] = useState<RowRecord>({});
    const [saved, setSaved] = useState<EditorState | null>(null);
    const [tailoring, setTailoring] = useState<TailoringInfo | null>(null);
    const [notice, setNotice] = useState<{ variant: "success" | "warning" | "info"; title: string } | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [busy, setBusy] = useState(false);
    const [search, setSearch] = useState("");
    const [stateFilter, setStateFilter] = useState<StateFilter>("all");
    const [severityFilter, setSeverityFilter] = useState("all");
    const [groupFilter, setGroupFilter] = useState("all");
    const [customValues, setCustomValues] = useState<Set<string>>(new Set());
    const fileInput = useRef<HTMLInputElement>(null);

    const rules = useMemo(() => data.data?.rules.rules ?? [], [data.data]);
    const values = useMemo(() => data.data?.rules.values ?? [], [data.data]);
    const base = useMemo(() => baseState(rules, values), [rules, values]);
    const groups = useMemo(() => Array.from(new Set(rules.map(r => r.group || ""))).sort((a, b) => a.localeCompare(b)),
                           [rules]);

    useEffect(() => {
        if (!data.data)
            return;
        const state = data.data.tailoring
            ? applyModifications(base, values, data.data.tailoring.modifications)
            : base;
        setSaved(state);
        setCurrent(state);
        setTailoring(data.data.tailoring);
        if (data.data.problem) {
            setNotice({
                variant: "warning",
                title: cockpit.format(_("The saved customization is not applied. $0 Saving replaces it."), data.data.problem),
            });
        }
    }, [data.data, base, values]);

    if (data.error) {
        return (
            <PageSection hasBodyWrapper={false} isFilled>
                <ErrorState title={_("Failed to load the profile")} error={data.error} onRetry={() => data.reload()} />
                <Button variant="link" onClick={() => cockpit.location.go(["profiles"])}>{_("Back to profiles")}</Button>
            </PageSection>
        );
    }
    if (!data.data || !current || !saved)
        return <PageSection hasBodyWrapper={false} isFilled><Loading /></PageSection>;

    const title = data.data.rules.title || profileShortName(profileId);
    const readOnly = app.superuser === false;
    const modifications = computeModifications(base, current, values);
    const changedRules = modifications.filter(m => m.action === "select" || m.action === "unselect").length;
    const changedValues = modifications.length - changedRules;
    const unsaved = !statesEqual(current, saved);
    const selectedCount = Object.values(current.selection).filter(Boolean).length;

    function setRule(id: string, selected: boolean) {
        setCurrent(prev => prev && { ...prev, selection: { ...prev.selection, [id]: selected } });
    }

    function setRules(ids: string[], selected: boolean) {
        setCurrent(prev => {
            if (!prev)
                return prev;
            const selection = { ...prev.selection };
            ids.forEach(id => { selection[id] = selected });
            return { ...prev, selection };
        });
    }

    function setValue(id: string, text: string) {
        setCurrent(prev => prev && { ...prev, values: { ...prev.values, [id]: text } });
    }

    async function guarded(action: () => Promise<void>) {
        setBusy(true);
        setError(null);
        setNotice(null);
        try {
            await action();
        } catch (err) {
            setError(errorMessage(err));
        } finally {
            setBusy(false);
        }
    }

    function save() {
        return guarded(async () => {
            if (modifications.length === 0) {
                if (tailoring)
                    await deleteTailoring(profileId);
                setTailoring(null);
                setSaved(current);
                setNotice({ variant: "info", title: _("No customizations left; scans will use the profile defaults.") });
            } else {
                const info = await createTailoring(profileId, modifications);
                setTailoring(info);
                setSaved(current);
                setNotice({ variant: "success", title: _("Customizations saved. Scans of this profile now apply them.") });
            }
            app.bump();
        });
    }

    async function removeCustomizations() {
        const confirmed = await Dialogs.run(ConfirmDialog, {
            title: _("Remove customizations?"),
            body: _("The saved tailoring file will be deleted and the editor reset to the profile defaults."),
            confirmText: _("Remove"),
            isDanger: true,
        });
        if (!confirmed)
            return;
        await guarded(async () => {
            await deleteTailoring(profileId);
            setTailoring(null);
            setSaved(base);
            setCurrent(base);
            setNotice({ variant: "info", title: _("Customizations removed.") });
            app.bump();
        });
    }

    async function importFile(event: React.ChangeEvent<HTMLInputElement>) {
        const file = event.target.files?.[0];
        event.target.value = "";
        if (!file)
            return;
        await guarded(async () => {
            const info = await importTailoring(profileId, await file.text());
            const state = applyModifications(base, values, info.modifications);
            setTailoring(info);
            setSaved(state);
            setCurrent(state);
            setNotice(info.warning
                ? { variant: "warning", title: info.warning }
                : { variant: "success", title: cockpit.format(_("Imported customizations from $0."), file.name) });
            app.bump();
        });
    }

    function exportFile() {
        if (tailoring)
            downloadFile(`${safeFilename(profileShortName(profileId))}-tailoring.xml`, tailoring.tailoring_xml, "application/xml");
    }

    const shownRules = rules.filter(rule => {
        const selected = current.selection[rule.id];
        const changed = base.selection[rule.id] !== selected;
        if (stateFilter === "selected" && !selected)
            return false;
        if (stateFilter === "unselected" && selected)
            return false;
        if (stateFilter === "changed" && !changed)
            return false;
        if (severityFilter !== "all" && normalizeSeverity(rule.severity) !== severityFilter)
            return false;
        if (groupFilter !== "all" && (rule.group || "") !== groupFilter)
            return false;
        return matchesSearch(search, rule.title, rule.id, rule.group);
    });
    const rulesById = new Map(rules.map(r => [r.id, r]));

    const sortRules = (rows: ListingTableRowProps[], direction: SortByDirection, index: number) => {
        const key = (row: ListingTableRowProps) => rulesById.get(String(row.props?.key));
        const sorted = [...rows].sort((a, b) => {
            const ra = key(a);
            const rb = key(b);
            if (!ra || !rb)
                return 0;
            switch (index) {
            case 0:
                return Number(current.selection[rb.id]) - Number(current.selection[ra.id]);
            case 2:
                return compareSeverity(ra.severity, rb.severity);
            case 3:
                return ra.group.localeCompare(rb.group) || ra.title.localeCompare(rb.title);
            default:
                return ra.title.localeCompare(rb.title);
            }
        });
        return direction === SortByDirection.asc ? sorted : sorted.reverse();
    };

    const kebab = [
        <DropdownItem key="import" isDisabled={readOnly || busy} onClick={() => fileInput.current?.click()}>
            {_("Import tailoring file…")}
        </DropdownItem>,
        <DropdownItem key="export" isDisabled={!tailoring} onClick={exportFile}>
            {_("Export tailoring file")}
        </DropdownItem>,
        <DropdownItem key="reset" isDisabled={modifications.length === 0} onClick={() => setCurrent(base)}>
            {_("Reset to profile defaults")}
        </DropdownItem>,
        <DropdownItem key="remove" isDanger isDisabled={!tailoring || readOnly || busy} onClick={removeCustomizations}>
            {_("Remove customizations")}
        </DropdownItem>,
    ];

    const rulesTable = (
        <Stack hasGutter>
            <StackItem>
                <Toolbar id="tailoring-toolbar" inset={{ default: "insetNone" }}>
                    <ToolbarContent>
                        <ToolbarItem>
                            <SearchInput
id="tailoring-search" placeholder={_("Search rules")} value={search}
                                         onChange={(_ev, value) => setSearch(value)} onClear={() => setSearch("")}
                            />
                        </ToolbarItem>
                        <ToolbarItem>
                            <SimpleSelect
                                toggleProps={{ id: "tailoring-filter-state" }}
                                options={[
                                    { value: "all", content: _("All rules") },
                                    { value: "selected", content: _("Enabled") },
                                    { value: "unselected", content: _("Disabled") },
                                    { value: "changed", content: _("Changed") },
                                ]}
                                selected={stateFilter}
                                onSelect={value => setStateFilter(value as StateFilter)}
                            />
                        </ToolbarItem>
                        <ToolbarItem>
                            <SimpleSelect
                                toggleProps={{ id: "tailoring-filter-severity" }}
                                options={[
                                    { value: "all", content: _("All severities") },
                                    ...SEVERITIES.map(s => ({ value: s, content: severityLabel(s) })),
                                ]}
                                selected={severityFilter}
                                onSelect={value => setSeverityFilter(value)}
                            />
                        </ToolbarItem>
                        {groups.length > 1 && (
                            <ToolbarItem>
                                <SimpleSelect
                                    toggleProps={{ id: "tailoring-filter-group" }}
                                    options={[
                                        { value: "all", content: _("All categories") },
                                        ...groups.map(name => ({ value: name || "__none__", content: name || _("Uncategorized") })),
                                    ]}
                                    selected={groupFilter === "" ? "__none__" : groupFilter}
                                    onSelect={value => setGroupFilter(value === "__none__" ? "" : value)}
                                />
                            </ToolbarItem>
                        )}
                        <ToolbarItem>
                            <Button
variant="link" isInline isDisabled={readOnly || shownRules.length === 0}
                                    onClick={() => setRules(shownRules.map(r => r.id), true)}
                            >
                                {_("Enable shown")}
                            </Button>
                        </ToolbarItem>
                        <ToolbarItem>
                            <Button
variant="link" isInline isDisabled={readOnly || shownRules.length === 0}
                                    onClick={() => setRules(shownRules.map(r => r.id), false)}
                            >
                                {_("Disable shown")}
                            </Button>
                        </ToolbarItem>
                        <ToolbarItem align={{ default: "alignEnd" }}>
                            <span className="oscap-toolbar-count">
                                {cockpit.format(_("$0 of $1 rules"), shownRules.length, rules.length)}
                            </span>
                        </ToolbarItem>
                    </ToolbarContent>
                </Toolbar>
            </StackItem>
            <StackItem>
                <ListingTable
                    id="tailoring-rules"
                    aria-label={_("Profile rules")}
                    variant="compact"
                    columns={[
                        { title: _("Enabled"), sortable: true, props: { modifier: "fitContent" } },
                        { title: _("Rule"), sortable: true, props: { width: 50 } },
                        { title: _("Severity"), sortable: true, props: { modifier: "fitContent" } },
                        { title: _("Category"), sortable: true },
                    ]}
                    sortBy={{ index: 3, direction: SortByDirection.asc }}
                    sortMethod={sortRules}
                    emptyCaption={_("No rules match the current filters")}
                    isEmptyStateInTable
                    onExpand={setExpandedRules}
                    rows={shownRules.map(rule => {
                        const selected = current.selection[rule.id];
                        const changed = base.selection[rule.id] !== selected;
                        return {
                            props: { key: rule.id, ...changed && { className: "oscap-row-changed" } },
                            columns: [
                                {
                                    title: (
                                        <Switch
                                            id={`rule-${safeFilename(ruleShortName(rule.id))}`}
                                            aria-label={cockpit.format(_("Enable rule $0"), rule.title)}
                                            isChecked={selected}
                                            isDisabled={readOnly}
                                            onChange={(_ev, checked) => setRule(rule.id, checked)}
                                        />
                                    ),
                                    props: { className: "oscap-table-nowrap" },
                                },
                                {
                                    title: (
                                        <>
                                            {rule.title || rule.id}
                                            {changed && <> {" "}<Label color="purple" isCompact>{_("Changed")}</Label></>}
                                        </>
                                    ),
                                },
                                { title: <SeverityLabel severity={rule.severity} /> },
                                { title: rule.group || _("Uncategorized") },
                            ],
                            expandedContent: (
                                <RuleDetails
                                    ruleId={rule.id} description={rule.description}
                                    datastream={app.backend.content.datastream_path}
                                    active={Boolean(expandedRules[rule.id])}
                                />
                            ),
                        };
                    })}
                />
            </StackItem>
        </Stack>
    );

    const valuesTable = (
        <ListingTable
            id="tailoring-values"
            aria-label={_("Profile values")}
            variant="compact"
            columns={[
                { title: _("Value"), props: { width: 40 } },
                { title: _("Setting"), props: { width: 40 } },
                { title: _("Default"), props: { modifier: "fitContent" } },
            ]}
            emptyCaption={_("The rules enabled in this profile do not use adjustable values")}
            rows={values.map(value => {
                const text = current.values[value.id] ?? "";
                const changed = base.values[value.id] !== text;
                const matched = value.options.find(o => o.value === text);
                const showInput = value.options.length === 0 || customValues.has(value.id) || !matched;
                return {
                    props: { key: value.id, ...changed && { className: "oscap-row-changed" } },
                    columns: [
                        {
                            title: (
                                <>
                                    {value.title || value.id}
                                    {changed && <> {" "}<Label color="purple" isCompact>{_("Changed")}</Label></>}
                                </>
                            ),
                        },
                        {
                            title: (
                                <Stack hasGutter className="oscap-value-input">
                                    {value.options.length > 0 && (
                                        <StackItem>
                                            <FormSelect
                                                id={`value-preset-${safeFilename(value.id)}`}
                                                aria-label={cockpit.format(_("Preset for $0"), value.title)}
                                                value={showInput ? CUSTOM : matched?.selector ?? CUSTOM}
                                                isDisabled={readOnly}
                                                onChange={(_ev, selector) => {
                                                    const next = new Set(customValues);
                                                    if (selector === CUSTOM) {
                                                        next.add(value.id);
                                                    } else {
                                                        next.delete(value.id);
                                                        const option = value.options.find(o => o.selector === selector);
                                                        if (option)
                                                            setValue(value.id, option.value);
                                                    }
                                                    setCustomValues(next);
                                                }}
                                            >
                                                {value.options.map(option => (
                                                    <FormSelectOption
key={option.selector} value={option.selector}
                                                                      label={`${option.selector.replace(/_/g, " ")} (${option.value})`}
                                                    />
                                                ))}
                                                <FormSelectOption value={CUSTOM} label={_("Custom value…")} />
                                            </FormSelect>
                                        </StackItem>
                                    )}
                                    {showInput && (
                                        <StackItem>
                                            <TextInput
                                                id={`value-${safeFilename(value.id)}`}
                                                aria-label={value.title}
                                                type={value.type === "number" ? "number" : "text"}
                                                value={text}
                                                isDisabled={readOnly}
                                                onChange={(_ev, next) => setValue(value.id, next)}
                                            />
                                        </StackItem>
                                    )}
                                </Stack>
                            ),
                        },
                        { title: <span className="oscap-mono">{value.default || "—"}</span> },
                    ],
                    expandedContent: (
                        <div className="oscap-expanded-details">
                            <Content component="p" className="oscap-prose">{value.description || _("No description")}</Content>
                            <Content component="small" className="oscap-mono">{value.id}</Content>
                        </div>
                    ),
                };
            })}
        />
    );

    return (
        <>
            <PageSection type="breadcrumb" hasBodyWrapper={false}>
                <Breadcrumb>
                    <BreadcrumbItem to="#/profiles" onClick={ev => { ev.preventDefault(); cockpit.location.go(["profiles"]) }}>
                        {_("Profiles")}
                    </BreadcrumbItem>
                    <BreadcrumbItem isActive>{title}</BreadcrumbItem>
                </Breadcrumb>
            </PageSection>
            <PageSection hasBodyWrapper={false} isFilled id="tailoring-editor">
                <Stack hasGutter>
                    <StackItem>
                        <Flex justifyContent={{ default: "justifyContentSpaceBetween" }} alignItems={{ default: "alignItemsFlexStart" }}>
                            <FlexItem grow={{ default: "grow" }}>
                                <Content component="h2">{title}</Content>
                                <Content component="p" className="oscap-muted">
                                    {cockpit.format(_("$0 of $1 rules enabled"), selectedCount, rules.length)}
                                    {modifications.length > 0 && (
                                        <>
                                            {" · "}
                                            {cockpit.format(_("$0 and $1 customized"),
                                                            cockpit.format(cockpit.ngettext("$0 rule", "$0 rules", changedRules), changedRules),
                                                            cockpit.format(cockpit.ngettext("$0 value", "$0 values", changedValues), changedValues))}
                                        </>
                                    )}
                                    {unsaved && <> {" · "}<strong>{_("Unsaved changes")}</strong></>}
                                </Content>
                            </FlexItem>
                            <FlexItem>
                                <div className="oscap-card-actions">
                                    <Button
id="tailoring-save" variant="primary" onClick={save} isLoading={busy}
                                            isDisabled={!unsaved || busy || readOnly}
                                    >
                                        {_("Save")}
                                    </Button>
                                    <Button variant="secondary" onClick={() => setCurrent(saved)} isDisabled={!unsaved || busy}>
                                        {_("Discard changes")}
                                    </Button>
                                    <ActionsMenu ariaLabel={_("Customization actions")} toggleButtonId="tailoring-actions" dropdownItems={kebab} />
                                    <input ref={fileInput} type="file" accept=".xml,application/xml" hidden onChange={importFile} />
                                </div>
                            </FlexItem>
                        </Flex>
                    </StackItem>
                    {notice && (
                        <StackItem>
                            <Alert
component="h2"
variant={notice.variant} isInline title={notice.title}
                                   actionClose={<AlertActionCloseButton onClose={() => setNotice(null)} />}
                            />
                        </StackItem>
                    )}
                    {error && (
                        <StackItem>
                            <ErrorAlert title={_("Operation failed")} error={error} onDismiss={() => setError(null)} />
                        </StackItem>
                    )}
                    <StackItem>
                        <Tabs
id="tailoring-tabs" activeKey={tab} onSelect={(_ev, key) => setTab(key as "rules" | "values")}
                              isSubtab aria-label={_("Profile sections")}
                        >
                            <Tab
eventKey="rules" ouiaId="tailoring-tab-rules" tabContentId="tailoring-panel"
                                 title={<TabTitleText>{cockpit.format(_("Rules ($0)"), rules.length)}</TabTitleText>}
                            />
                            <Tab
eventKey="values" ouiaId="tailoring-tab-values" tabContentId="tailoring-panel"
                                 title={<TabTitleText>{cockpit.format(_("Values ($0)"), values.length)}</TabTitleText>}
                            />
                        </Tabs>
                    </StackItem>
                    <StackItem>
                        <div id="tailoring-panel" role="tabpanel" aria-labelledby={`pf-tab-${tab}-tailoring-tabs`}>
                            {tab === "rules" ? rulesTable : valuesTable}
                        </div>
                    </StackItem>
                </Stack>
            </PageSection>
        </>
    );
};
