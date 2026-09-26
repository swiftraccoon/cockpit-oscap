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
import { ListingTable } from "cockpit-components-table";
import type { ListingTableRowProps } from "cockpit-components-table";
import { useDialogs } from "dialogs";
import * as timeformat from "timeformat";

import { RESULTS_DIR, deleteResult, generateFix, generateReport, listResults, readFile } from "../api";
import { useApp } from "../app";
import { useAsync } from "../app-hooks";
import { ActionsMenu } from "../components/ActionsMenu";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { CountLabels, ScanStatusLabel, ScoreLabel, TailoredLabel } from "../components/labels";
import { ErrorAlert, ErrorState, Loading } from "../components/states";
import { downloadFile, errorMessage, matchesSearch, parseTimestamp, safeFilename } from "../helpers";
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

    const shown = all.filter(s => matchesSearch(search, s.profile_title, s.profile_id, s.id));
    const byId = new Map(shown.map(s => [s.id, s]));

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
                    onRowClick={(_ev, row) => cockpit.location.go(["results", String(row.props?.key)])}
                    rows={shown.map(summary => {
                        const date = parseTimestamp(summary.timestamp);
                        return {
                            props: { key: summary.id },
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
key="delete" isDanger isDisabled={app.superuser === false}
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
