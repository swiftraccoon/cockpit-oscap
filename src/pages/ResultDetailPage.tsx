/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * A single scan: summary, every evaluated rule with details on demand, and
 * the entry point to guided remediation.
 */

import React, { useMemo, useState } from "react";
import { Breadcrumb, BreadcrumbItem } from "@patternfly/react-core/dist/esm/components/Breadcrumb/index.js";
import { Button } from "@patternfly/react-core/dist/esm/components/Button/index.js";
import { Card, CardBody } from "@patternfly/react-core/dist/esm/components/Card/index.js";
import { Content } from "@patternfly/react-core/dist/esm/components/Content/index.js";
import { DropdownItem } from "@patternfly/react-core/dist/esm/components/Dropdown/index.js";
import { Label } from "@patternfly/react-core/dist/esm/components/Label/index.js";
import { PageSection } from "@patternfly/react-core/dist/esm/components/Page/index.js";
import { SearchInput } from "@patternfly/react-core/dist/esm/components/SearchInput/index.js";
import { Toolbar, ToolbarContent, ToolbarItem } from "@patternfly/react-core/dist/esm/components/Toolbar/index.js";
import { Flex, FlexItem } from "@patternfly/react-core/dist/esm/layouts/Flex/index.js";
import { Stack, StackItem } from "@patternfly/react-core/dist/esm/layouts/Stack/index.js";
import { SortByDirection } from "@patternfly/react-table";
import cockpit from "cockpit";

import { KebabDropdown } from "cockpit-components-dropdown";
import { ListingTable } from "cockpit-components-table";
import type { ListingTableRowProps, RowRecord } from "cockpit-components-table";
import { SimpleSelect } from "cockpit-components-simple-select";
import { useDialogs } from "dialogs";
import * as timeformat from "timeformat";

import { deleteResult, getResult, listResults } from "../api";
import { useApp } from "../app";
import { useAsync } from "../app-hooks";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { RemediationDialog } from "../components/RemediationDialog";
import { RuleDetails } from "../components/RuleDetails";
import {
    ChangeLabel,
    CountLabels,
    ResultLabel,
    ScanStatusLabel,
    ScoreValue,
    SeverityLabel,
    Stat,
    TailoredLabel,
} from "../components/labels";
import { ErrorAlert, ErrorState, Loading } from "../components/states";
import {
    SEVERITIES,
    compareSeverity,
    errorMessage,
    matchesSearch,
    normalizeResult,
    normalizeSeverity,
    parseTimestamp,
    resultLabel,
    ruleChange,
    scoredTotal,
    severityLabel,
} from "../helpers";
import type { ResultSummary, RuleResultItem, ScanResult } from "../types";
import { downloadArf, downloadFix, downloadReport } from "./ResultsPage";

const _ = cockpit.gettext;

type StatusFilter = "all" | "fail" | "pass" | "error" | "other" | "changed";
const STATUS_FILTERS: StatusFilter[] = ["all", "fail", "pass", "error", "other"];

const RESULT_ORDER: Record<string, number> = { fail: 0, error: 1, pass: 2, fixed: 3, notchecked: 4, informational: 5, notapplicable: 6 };

function resultOrder(result: string): number {
    return RESULT_ORDER[normalizeResult(result)] ?? 9;
}

function matchesStatus(filter: StatusFilter, result: string): boolean {
    switch (filter) {
    case "all":
        return true;
    case "other":
        return !["pass", "fail", "error"].includes(normalizeResult(result));
    default:
        return normalizeResult(result) === filter;
    }
}

/** The most recent completed scan of the same profile that ran before `result`, if any. */
async function findPrevious(result: ScanResult): Promise<ScanResult | null> {
    const at = parseTimestamp(result.timestamp)?.getTime() ?? 0;
    let summaries: ResultSummary[];
    try {
        summaries = await listResults();
    } catch {
        return null;
    }
    // newest first, so the first older match is the immediately preceding scan
    const before = summaries.find(s => s.id !== result.id && s.profile_id === result.profile_id &&
        s.status === "complete" && (parseTimestamp(s.timestamp)?.getTime() ?? 0) < at);
    if (!before)
        return null;
    try {
        return await getResult(before.id);
    } catch {
        return null;
    }
}

export const ResultDetailPage = ({ resultId }: { resultId: string }) => {
    const app = useApp();
    const Dialogs = useDialogs();
    const data = useAsync(async () => {
        const result = await getResult(resultId);
        return { result, previous: await findPrevious(result) };
    }, [resultId, app.version]);
    const [search, setSearch] = useState("");
    const [status, setStatus] = useState<StatusFilter>("all");
    const [severity, setSeverity] = useState("all");
    const [group, setGroup] = useState("all");
    const [error, setError] = useState<string | null>(null);
    const [expandedRules, setExpandedRules] = useState<RowRecord>({});

    const result = data.data?.result ?? null;
    const previous = data.data?.previous ?? null;
    const groups = useMemo(() => {
        const names = new Set<string>();
        result?.results.forEach(r => names.add(r.group || ""));
        return Array.from(names).sort((a, b) => a.localeCompare(b));
    }, [result]);
    const previousResults = useMemo(
        () => new Map((previous?.results ?? []).map(r => [r.rule_id, r.result])), [previous]);

    if (data.loading && !result)
        return <PageSection hasBodyWrapper={false} isFilled><Loading /></PageSection>;
    if (data.error || !result) {
        return (
            <PageSection hasBodyWrapper={false} isFilled>
                <ErrorState title={_("Failed to load scan result")} error={data.error} onRetry={() => data.reload()} />
                <Button variant="link" onClick={() => cockpit.location.go(["results"])}>{_("Back to results")}</Button>
            </PageSection>
        );
    }

    const loaded: ScanResult = result;
    const scannedAt = parseTimestamp(loaded.timestamp);
    const previousAt = previous ? parseTimestamp(previous.timestamp) : null;
    const changeOf = (rule: RuleResultItem) => ruleChange(previousResults.get(rule.rule_id), rule.result);
    const changes = { fixed: 0, regressed: 0, changed: 0 };
    if (previous) {
        for (const rule of loaded.results) {
            const change = changeOf(rule);
            if (change)
                changes[change] += 1;
        }
    }
    const changedTotal = changes.fixed + changes.regressed + changes.changed;
    const readOnly = app.superuser === false;
    const canRemediate = loaded.counts.fail > 0 && Boolean(loaded.arf_path) && !readOnly && !app.scanning;

    async function guarded(action: () => Promise<void>) {
        setError(null);
        try {
            await action();
        } catch (err) {
            setError(errorMessage(err));
        }
    }

    async function remove() {
        const confirmed = await Dialogs.run(ConfirmDialog, {
            title: _("Delete scan result?"),
            body: _("This scan result and its report will be deleted permanently."),
            confirmText: _("Delete"),
            isDanger: true,
        });
        if (confirmed) {
            await guarded(async () => {
                await deleteResult(loaded.id);
                app.bump();
                cockpit.location.go(["results"]);
            });
        }
    }

    function remediateRules() {
        if (Dialogs.isActive())
            return;
        Dialogs.show(<RemediationDialog result={loaded} onRescanned={() => app.bump()} />);
    }

    const shown = result.results.filter(rule =>
        (status === "changed" ? changeOf(rule) !== null : matchesStatus(status, rule.result)) &&
        (severity === "all" || normalizeSeverity(rule.severity) === severity) &&
        (group === "all" || (rule.group || "") === group) &&
        matchesSearch(search, rule.title, rule.rule_id, rule.group));
    const byId = new Map(shown.map(r => [r.rule_id, r]));

    const statusCount = (filter: StatusFilter) =>
        (filter === "changed" ? changedTotal : result.results.filter(r => matchesStatus(filter, r.result)).length);
    const statusOptionLabel = (filter: StatusFilter) => {
        switch (filter) {
        case "all":
            return _("All results");
        case "other":
            return _("Other");
        case "changed":
            return _("Changed since previous scan");
        default:
            return resultLabel(filter);
        }
    };

    const sortMethod = (rows: ListingTableRowProps[], direction: SortByDirection, index: number) => {
        const key = (row: ListingTableRowProps): RuleResultItem | undefined => byId.get(String(row.props?.key));
        const sorted = [...rows].sort((a, b) => {
            const ra = key(a);
            const rb = key(b);
            if (!ra || !rb)
                return 0;
            switch (index) {
            case 1:
                return ra.title.localeCompare(rb.title);
            case 2:
                return compareSeverity(ra.severity, rb.severity);
            case 3:
                return ra.group.localeCompare(rb.group);
            default:
                return resultOrder(ra.result) - resultOrder(rb.result) || compareSeverity(ra.severity, rb.severity);
            }
        });
        return direction === SortByDirection.asc ? sorted : sorted.reverse();
    };

    const title = result.profile_title || result.profile_id;

    return (
        <>
            <PageSection type="breadcrumb" hasBodyWrapper={false}>
                <Breadcrumb>
                    <BreadcrumbItem to="#/results" onClick={ev => { ev.preventDefault(); cockpit.location.go(["results"]) }}>
                        {_("Results")}
                    </BreadcrumbItem>
                    <BreadcrumbItem isActive>
                        {scannedAt ? cockpit.format("$0 · $1", title, timeformat.dateTime(scannedAt)) : title}
                    </BreadcrumbItem>
                </Breadcrumb>
            </PageSection>
            <PageSection hasBodyWrapper={false} isFilled id="result-detail">
                <Stack hasGutter>
                    <StackItem>
                        <Card className="ct-card oscap-summary-card" id="result-summary">
                            <CardBody>
                                <ScoreValue score={result.score} />
                                <Stat label={_("Profile")}>
                                    {title}{result.tailored && <> {" "}<TailoredLabel /></>}
                                </Stat>
                                <Stat label={_("Scanned")}>
                                    {scannedAt ? timeformat.dateTime(scannedAt) : loaded.timestamp}
                                    {scannedAt && (
                                        <span className="oscap-muted oscap-stat-detail">
                                            {" · "}{timeformat.distanceToNow(scannedAt)}
                                        </span>
                                    )}
                                </Stat>
                                <Stat label={_("Rules evaluated")}>
                                    {scoredTotal(result.counts)}
                                    <span className="oscap-muted">
                                        {" "}{cockpit.format(_("of $0"), result.results.length)}
                                    </span>
                                </Stat>
                                <Stat label={_("Results")}><CountLabels counts={result.counts} /></Stat>
                                <Stat label={_("Status")}><ScanStatusLabel status={result.status} /></Stat>
                                {previous && (
                                    <Stat label={_("Since previous scan")}>
                                        <span className="oscap-inline-list" id="result-changes">
                                            {changes.fixed > 0 && (
                                                <Label status="success" isCompact>
                                                    {cockpit.format(_("$0 now passing"), changes.fixed)}
                                                </Label>
                                            )}
                                            {changes.regressed > 0 && (
                                                <Label status="danger" isCompact>
                                                    {cockpit.format(cockpit.ngettext("$0 new failure", "$0 new failures",
                                                                                     changes.regressed), changes.regressed)}
                                                </Label>
                                            )}
                                            {changes.changed > 0 && (
                                                <Label color="purple" isCompact>
                                                    {cockpit.format(_("$0 changed"), changes.changed)}
                                                </Label>
                                            )}
                                            {changedTotal === 0
                                                ? <span className="oscap-muted">{_("No changes")}</span>
                                                : (
                                                    <Button
variant="link" isInline className="oscap-stat-detail"
                                                            onClick={() => setStatus("changed")}
                                                    >
                                                        {_("Show")}
                                                    </Button>
                                                )}
                                        </span>
                                        <span className="oscap-muted oscap-stat-detail">
                                            {cockpit.format(_("Compared with $0"),
                                                            previousAt ? timeformat.dateTime(previousAt) : previous.timestamp)}
                                        </span>
                                    </Stat>
                                )}
                                <Flex
flex={{ default: "flex_1" }} justifyContent={{ default: "justifyContentFlexEnd" }}
                                      alignItems={{ default: "alignItemsCenter" }} spaceItems={{ default: "spaceItemsSm" }}
                                >
                                    <FlexItem>
                                        <Button
id="result-remediate" variant="primary" onClick={remediateRules}
                                                isDisabled={!canRemediate}
                                        >
                                            {_("Remediate failed rules")}
                                        </Button>
                                    </FlexItem>
                                    <FlexItem>
                                        <KebabDropdown
                                            toggleButtonId="result-actions"
                                            dropdownItems={[
                                                <DropdownItem
key="rescan" isDisabled={readOnly || app.scanning}
                                                              onClick={() => app.runScan(result.base_profile_id)}
                                                >
                                                    {_("Scan again with this profile")}
                                                </DropdownItem>,
                                                <DropdownItem
key="report" isDisabled={!result.arf_path}
                                                              onClick={() => guarded(() => downloadReport(result.id))}
                                                >
                                                    {_("Download HTML report")}
                                                </DropdownItem>,
                                                <DropdownItem
key="arf" isDisabled={!result.arf_path}
                                                              onClick={() => guarded(() => downloadArf(result.id))}
                                                >
                                                    {_("Download ARF results")}
                                                </DropdownItem>,
                                                <DropdownItem
key="fix-bash" isDisabled={!result.arf_path || result.counts.fail === 0}
                                                              onClick={() => guarded(() => downloadFix(result.id, "bash"))}
                                                >
                                                    {_("Download Bash remediation script")}
                                                </DropdownItem>,
                                                <DropdownItem
key="fix-ansible" isDisabled={!result.arf_path || result.counts.fail === 0}
                                                              onClick={() => guarded(() => downloadFix(result.id, "ansible"))}
                                                >
                                                    {_("Download Ansible playbook")}
                                                </DropdownItem>,
                                                <DropdownItem key="delete" isDanger isDisabled={readOnly} onClick={remove}>
                                                    {_("Delete")}
                                                </DropdownItem>,
                                            ]}
                                        />
                                    </FlexItem>
                                </Flex>
                            </CardBody>
                        </Card>
                    </StackItem>
                    {result.status === "interrupted" && (
                        <StackItem>
                            <Content component="p" className="oscap-muted">
                                {_("This scan was interrupted; the results may be incomplete.")}
                            </Content>
                        </StackItem>
                    )}
                    {error && (
                        <StackItem>
                            <ErrorAlert title={_("Operation failed")} error={error} onDismiss={() => setError(null)} />
                        </StackItem>
                    )}
                    <StackItem>
                        <Toolbar id="result-toolbar" inset={{ default: "insetNone" }}>
                            <ToolbarContent>
                                <ToolbarItem>
                                    <SearchInput
                                        id="result-search"
                                        placeholder={_("Search rules")}
                                        value={search}
                                        onChange={(_ev, value) => setSearch(value)}
                                        onClear={() => setSearch("")}
                                    />
                                </ToolbarItem>
                                <ToolbarItem>
                                    <SimpleSelect
                                        toggleProps={{ id: "result-filter-status" }}
                                        options={[...STATUS_FILTERS, ...previous ? ["changed" as const] : []].map(filter => ({
                                            value: filter,
                                            content: `${statusOptionLabel(filter)} (${statusCount(filter)})`,
                                        }))}
                                        selected={status}
                                        onSelect={value => setStatus(value)}
                                    />
                                </ToolbarItem>
                                <ToolbarItem>
                                    <SimpleSelect
                                        toggleProps={{ id: "result-filter-severity" }}
                                        options={[
                                            { value: "all", content: _("All severities") },
                                            ...SEVERITIES.map(s => ({ value: s, content: severityLabel(s) })),
                                        ]}
                                        selected={severity}
                                        onSelect={value => setSeverity(value)}
                                    />
                                </ToolbarItem>
                                {groups.length > 1 && (
                                    <ToolbarItem>
                                        <SimpleSelect
                                            toggleProps={{ id: "result-filter-group" }}
                                            options={[
                                                { value: "all", content: _("All categories") },
                                                ...groups.map(name => ({ value: name || "__none__", content: name || _("Uncategorized") })),
                                            ]}
                                            selected={group === "" ? "__none__" : group}
                                            onSelect={value => setGroup(value === "__none__" ? "" : value)}
                                        />
                                    </ToolbarItem>
                                )}
                                <ToolbarItem align={{ default: "alignEnd" }}>
                                    <span className="oscap-toolbar-count">
                                        {cockpit.format(_("$0 of $1 rules"), shown.length, result.results.length)}
                                    </span>
                                </ToolbarItem>
                            </ToolbarContent>
                        </Toolbar>
                    </StackItem>
                    <StackItem>
                        <ListingTable
                            id="result-rules"
                            aria-label={_("Rule results")}
                            variant="compact"
                            columns={[
                                { title: _("Result"), sortable: true, props: { modifier: "fitContent" } },
                                { title: _("Rule"), sortable: true, props: { width: 50 } },
                                { title: _("Severity"), sortable: true, props: { modifier: "fitContent" } },
                                { title: _("Category"), sortable: true },
                            ]}
                            sortBy={{ index: 0, direction: SortByDirection.asc }}
                            sortMethod={sortMethod}
                            emptyCaption={_("No rules match the current filters")}
                            isEmptyStateInTable
                            onExpand={setExpandedRules}
                            rows={shown.map(rule => {
                                const change = changeOf(rule);
                                return {
                                    props: { key: rule.rule_id, id: `rule-${rule.rule_id}` },
                                    columns: [
                                        { title: <ResultLabel result={rule.result} />, props: { className: "oscap-table-nowrap" } },
                                        {
                                            title: (
                                                <>
                                                    {rule.title || rule.rule_id}
                                                    {change && (
                                                        <>
                                                            {" "}
                                                            <ChangeLabel change={change} before={previousResults.get(rule.rule_id)} />
                                                        </>
                                                    )}
                                                </>
                                            ),
                                        },
                                        { title: <SeverityLabel severity={rule.severity} /> },
                                        { title: rule.group || _("Uncategorized") },
                                    ],
                                    expandedContent: (
                                        <RuleDetails
                                            ruleId={rule.rule_id} message={rule.message}
                                            active={Boolean(expandedRules[rule.rule_id])}
                                        />
                                    ),
                                };
                            })}
                        />
                    </StackItem>
                </Stack>
            </PageSection>
        </>
    );
};
