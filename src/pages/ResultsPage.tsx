/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Results: the history of scans kept on this system.
 */

import React, { useState } from "react";
import { Button } from "@patternfly/react-core/dist/esm/components/Button/index.js";
import { DropdownItem } from "@patternfly/react-core/dist/esm/components/Dropdown/index.js";
import { SearchInput } from "@patternfly/react-core/dist/esm/components/SearchInput/index.js";
import { Toolbar, ToolbarContent, ToolbarItem } from "@patternfly/react-core/dist/esm/components/Toolbar/index.js";
import { Stack, StackItem } from "@patternfly/react-core/dist/esm/layouts/Stack/index.js";
import { SortByDirection } from "@patternfly/react-table";
import cockpit from "cockpit";

import { EmptyStatePanel } from "cockpit-components-empty-state";
import { SimpleSelect } from "cockpit-components-simple-select";
import { ListingTable } from "cockpit-components-table";
import type { ListingTableRowProps } from "cockpit-components-table";
import { useDialogs } from "dialogs";
import * as timeformat from "timeformat";

import { RESULTS_DIR, deleteResult, generateFix, generateReport, getResult, listResults, readFile } from "../api";
import { useApp } from "../app";
import { useAsync } from "../app-hooks";
import { ActionsMenu } from "../components/ActionsMenu";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { CountLabels, ScanStatusLabel, ScoreLabel, TailoredLabel } from "../components/labels";
import { ErrorAlert, ErrorState, Loading } from "../components/states";
import {
    downloadFile,
    errorMessage,
    matchesSearch,
    parseTimestamp,
    resultsToCsv,
    safeFilename,
    withMember,
} from "../helpers";
import type { FixType, ResultSummary } from "../types";

const _ = cockpit.gettext;

export async function downloadReport(id: string): Promise<void> {
    const report = await generateReport(id);
    downloadFile(`compliance-report-${safeFilename(id)}.html`, report.html, "text/html");
}

export async function downloadArf(id: string): Promise<void> {
    const xml = await readFile(`${RESULTS_DIR}/${id}.arf.xml`);
    downloadFile(`compliance-results-${safeFilename(id)}.arf.xml`, xml, "application/xml");
}

/** Download every rule result of a scan as CSV. */
export async function downloadCsv(id: string): Promise<void> {
    const result = await getResult(id);
    downloadFile(`compliance-rules-${safeFilename(id)}.csv`, resultsToCsv(result), "text/csv");
}

/** Download the remediation for the failed rules of a scan as a Bash script or an Ansible playbook. */
export async function downloadFix(id: string, type: FixType): Promise<void> {
    const fix = await generateFix(id, type);
    if (type === "ansible")
        downloadFile(`compliance-remediation-${safeFilename(id)}.yml`, fix.script, "application/yaml");
    else
        downloadFile(`compliance-remediation-${safeFilename(id)}.sh`, fix.script, "text/x-shellscript");
}

export const ResultsPage = () => {
    const app = useApp();
    const Dialogs = useDialogs();
    const results = useAsync(listResults, [app.version]);
    const [search, setSearch] = useState("");
    const [error, setError] = useState<string | null>(null);
    const [selected, setSelected] = useState<Set<string>>(() => new Set());
    const [profileFilter, setProfileFilter] = useState("all");

    if (results.loading && !results.data)
        return <Loading />;
    if (results.error || !results.data)
        return <ErrorState title={_("Failed to load scan results")} error={results.error} onRetry={() => results.reload()} />;

    const all = results.data;

    if (all.length === 0) {
        return (
            <EmptyStatePanel
                title={_("No scan results yet")}
                paragraph={_("Every scan is kept here with its full report, so you can track how compliance changes over time.")}
                action={
                    <Button
variant="primary" onClick={() => app.runScan()}
                            isDisabled={app.superuser === false || app.scanning}
                    >
                        {_("Run scan")}
                    </Button>
                }
            />
        );
    }

    async function guarded(action: () => Promise<void>) {
        setError(null);
        try {
            await action();
        } catch (err) {
            setError(errorMessage(err));
        }
    }

    async function remove(summary: ResultSummary) {
        const date = parseTimestamp(summary.timestamp);
        const confirmed = await Dialogs.run(ConfirmDialog, {
            title: _("Delete scan result?"),
            body: cockpit.format(_("The scan of $0 from $1 and its report will be deleted permanently."),
                                 summary.profile_title || summary.profile_id,
                                 date ? timeformat.dateTime(date) : summary.timestamp),
            confirmText: _("Delete"),
            isDanger: true,
        });
        if (confirmed)
            await guarded(async () => { await deleteResult(summary.id); app.bump() });
    }

    // one entry per base profile, named after its most recent scan
    const profileOptions = Array.from(new Map(all.map(s => [s.base_profile_id, s.profile_title || s.base_profile_id])))
            .sort((a, b) => a[1].localeCompare(b[1]));
    const shown = all.filter(s => (profileFilter === "all" || s.base_profile_id === profileFilter) &&
        matchesSearch(search, s.profile_title, s.profile_id, s.id));
    const byId = new Map(shown.map(s => [s.id, s]));
    const readOnly = app.superuser === false;
    // only rows that are listed count: a search hides rows, and deleted ones are gone
    const selectedShown = shown.filter(s => selected.has(s.id));

    function selectRow(id: string, isSelected: boolean) {
        setSelected(prev => withMember(prev, id, isSelected));
    }

    async function removeSelected() {
        const ids = selectedShown.map(s => s.id);
        const confirmed = await Dialogs.run(ConfirmDialog, {
            title: cockpit.format(cockpit.ngettext("Delete $0 scan result?", "Delete $0 scan results?", ids.length), ids.length),
            body: _("The selected scans and their reports will be deleted permanently."),
            confirmText: _("Delete"),
            isDanger: true,
        });
        if (!confirmed)
            return;
        // keep going past a failure: what was deleted stays deleted, the rest stays selected
        const failures: string[] = [];
        for (const id of ids) {
            try {
                await deleteResult(id);
                setSelected(prev => withMember(prev, id, false));
            } catch (err) {
                failures.push(`${id}: ${errorMessage(err)}`);
            }
        }
        setError(failures.length > 0 ? failures.join("\n") : null);
        app.bump();
    }

    function openResult(id: string) {
        cockpit.location.go(["results", id]);
    }

    const sortMethod = (rows: ListingTableRowProps[], direction: SortByDirection, index: number) => {
        const key = (row: ListingTableRowProps) => byId.get(String(row.props?.key));
        const sorted = [...rows].sort((a, b) => {
            const sa = key(a);
            const sb = key(b);
            if (!sa || !sb)
                return 0;
            switch (index) {
            case 1:
                return (sa.profile_title || sa.profile_id).localeCompare(sb.profile_title || sb.profile_id);
            case 2:
                return sa.score - sb.score;
            case 3:
                return sa.counts.fail - sb.counts.fail;
            case 4:
                return sa.status.localeCompare(sb.status);
            default:
                return sa.timestamp.localeCompare(sb.timestamp) || sa.id.localeCompare(sb.id);
            }
        });
        return direction === SortByDirection.asc ? sorted : sorted.reverse();
    };

    return (
        <Stack hasGutter>
            <StackItem>
                <Toolbar id="results-toolbar" inset={{ default: "insetNone" }}>
                    <ToolbarContent>
                        <ToolbarItem>
                            <SearchInput
                                id="results-search"
                                placeholder={_("Search by profile")}
                                value={search}
                                onChange={(_ev, value) => setSearch(value)}
                                onClear={() => setSearch("")}
                            />
                        </ToolbarItem>
                        {profileOptions.length > 1 && (
                            <ToolbarItem>
                                <SimpleSelect
                                    toggleProps={{ id: "results-filter-profile" }}
                                    options={[
                                        { value: "all", content: _("All profiles") },
                                        ...profileOptions.map(([id, title]) => ({ value: id, content: title })),
                                    ]}
                                    selected={profileFilter}
                                    onSelect={value => setProfileFilter(value)}
                                />
                            </ToolbarItem>
                        )}
                        {selectedShown.length > 0 && (
                            <ToolbarItem>
                                <Button id="results-delete-selected" variant="danger" size="sm" onClick={removeSelected}>
                                    {cockpit.format(_("Delete $0 selected"), selectedShown.length)}
                                </Button>
                            </ToolbarItem>
                        )}
                        <ToolbarItem align={{ default: "alignEnd" }}>
                            <span className="oscap-toolbar-count">
                                {cockpit.format(cockpit.ngettext("$0 scan", "$0 scans", shown.length), shown.length)}
                            </span>
                        </ToolbarItem>
                    </ToolbarContent>
                </Toolbar>
            </StackItem>
            {error && (
                <StackItem>
                    <ErrorAlert title={_("Operation failed")} error={error} onDismiss={() => setError(null)} />
                </StackItem>
            )}
            <StackItem>
                <ListingTable
                    id="results-table"
                    aria-label={_("Scan results")}
                    variant="compact"
                    columns={[
                        { title: _("Date"), sortable: true, props: { modifier: "nowrap" } },
                        { title: _("Profile"), sortable: true, props: { width: 40 } },
                        { title: _("Score"), sortable: true, props: { modifier: "fitContent" } },
                        { title: _("Passed / Failed / Errors"), sortable: true, props: { modifier: "fitContent" } },
                        { title: _("Status"), sortable: true, props: { modifier: "fitContent" } },
                        { title: "", props: { screenReaderText: _("Actions"), modifier: "fitContent" } },
                    ]}
                    sortBy={{ index: 0, direction: SortByDirection.desc }}
                    sortMethod={sortMethod}
                    emptyCaption={_("No scans match the search")}
                    isEmptyStateInTable
                    onRowClick={(ev, row) => {
                        // a click on the row's checkbox selects; anywhere else opens the scan
                        if (ev?.target instanceof Element && ev.target.closest("input, .pf-v6-c-table__check"))
                            return;
                        openResult(String(row.props?.key));
                    }}
                    {...!readOnly && shown.length > 0 && {
                        onSelect: (_ev, isSelected, _index, rowData) => selectRow(String(rowData.props?.id), isSelected),
                        onHeaderSelect: (_ev, isSelected) => setSelected(isSelected ? new Set(shown.map(s => s.id)) : new Set()),
                    }}
                    rows={shown.map(summary => {
                        const date = parseTimestamp(summary.timestamp);
                        return {
                            props: {
                                key: summary.id,
                                // PatternFly's clickable row swallows Space/Enter, which the checkbox needs
                                onKeyDown: (ev: React.KeyboardEvent) => {
                                    if (ev.target instanceof HTMLInputElement)
                                        return;
                                    if (ev.key === "Enter" || ev.key === " ") {
                                        ev.preventDefault();
                                        openResult(summary.id);
                                    }
                                },
                            },
                            selected: selected.has(summary.id),
                            columns: [
                                {
                                    title: date ? timeformat.dateTime(date) : summary.timestamp,
                                    props: { className: "oscap-table-nowrap" },
                                },
                                {
                                    title: (
                                        <>
                                            {summary.profile_title || summary.profile_id}
                                            {summary.tailored && <> {" "}<TailoredLabel /></>}
                                        </>
                                    ),
                                },
                                { title: <ScoreLabel score={summary.score} /> },
                                { title: <CountLabels counts={summary.counts} /> },
                                { title: <ScanStatusLabel status={summary.status} /> },
                                {
                                    title: (
                                        <span onClick={ev => ev.stopPropagation()} onKeyDown={ev => ev.stopPropagation()}>
                                            <ActionsMenu
                                                toggleButtonId={`result-actions-${summary.id}`}
                                                ariaLabel={cockpit.format(_("Actions for the scan from $0"),
                                                                          date ? timeformat.dateTime(date) : summary.timestamp)}
                                                dropdownItems={[
                                                    <DropdownItem
key="view"
                                                                  onClick={() => cockpit.location.go(["results", summary.id])}
                                                    >
                                                        {_("View details")}
                                                    </DropdownItem>,
                                                    <DropdownItem
key="report" isDisabled={!summary.has_arf}
                                                                  onClick={() => guarded(() => downloadReport(summary.id))}
                                                    >
                                                        {_("Download HTML report")}
                                                    </DropdownItem>,
                                                    <DropdownItem
key="arf" isDisabled={!summary.has_arf}
                                                                  onClick={() => guarded(() => downloadArf(summary.id))}
                                                    >
                                                        {_("Download ARF results")}
                                                    </DropdownItem>,
                                                    <DropdownItem key="csv" onClick={() => guarded(() => downloadCsv(summary.id))}>
                                                        {_("Download rule results (CSV)")}
                                                    </DropdownItem>,
                                                    <DropdownItem
key="fix-bash" isDisabled={!summary.has_arf || summary.counts.fail === 0}
                                                                  onClick={() => guarded(() => downloadFix(summary.id, "bash"))}
                                                    >
                                                        {_("Download Bash remediation script")}
                                                    </DropdownItem>,
                                                    <DropdownItem
key="fix-ansible" isDisabled={!summary.has_arf || summary.counts.fail === 0}
                                                                  onClick={() => guarded(() => downloadFix(summary.id, "ansible"))}
                                                    >
                                                        {_("Download Ansible playbook")}
                                                    </DropdownItem>,
                                                    <DropdownItem
key="delete" isDanger isDisabled={readOnly}
                                                                  onClick={() => remove(summary)}
                                                    >
                                                        {_("Delete")}
                                                    </DropdownItem>,
                                                ]}
                                            />
                                        </span>
                                    ),
                                    props: { className: "pf-v6-c-table__action" },
                                },
                            ],
                        };
                    })}
                />
            </StackItem>
        </Stack>
    );
};
