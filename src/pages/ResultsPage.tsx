import React, { useEffect, useState } from "react";
import { Alert } from "@patternfly/react-core/dist/esm/components/Alert/index.js";
import { Button } from "@patternfly/react-core/dist/esm/components/Button/index.js";
import { Card, CardBody } from "@patternfly/react-core/dist/esm/components/Card/index.js";
import { Content, ContentVariants } from "@patternfly/react-core/dist/esm/components/Content/index.js";
import {
    EmptyState,
    EmptyStateActions,
    EmptyStateBody,
    EmptyStateFooter,
} from "@patternfly/react-core/dist/esm/components/EmptyState/index.js";
import { Label } from "@patternfly/react-core/dist/esm/components/Label/index.js";
import { PageSection } from "@patternfly/react-core/dist/esm/components/Page/index.js";
import { Spinner } from "@patternfly/react-core/dist/esm/components/Spinner/index.js";
import { Flex, FlexItem } from "@patternfly/react-core/dist/esm/layouts/Flex/index.js";
import { Table, Thead, Tbody, Tr, Th, Td } from "@patternfly/react-table/dist/esm/components/Table/index.js";
import cockpit from "cockpit";

import type { ScanResult } from "../types";

const _ = cockpit.gettext;

const RESULTS_DIR = "/var/lib/cockpit-oscap/results";

/** Metadata extracted from each scan result JSON, plus its filename. */
interface ScanSummary {
    filename: string;
    timestamp: string;
    profileId: string;
    score: number;
    passCount: number;
    failCount: number;
    errorCount: number;
    status: string;
    totalRules: number;
}

/** Parse a ScanResult into a ScanSummary. */
function summarize(filename: string, data: ScanResult): ScanSummary {
    const passCount = data.results.filter(r => r.result === "pass").length;
    const failCount = data.results.filter(r => r.result === "fail").length;
    const errorCount = data.results.filter(r => r.result === "error").length;

    return {
        filename,
        timestamp: data.timestamp,
        profileId: data.profile_id,
        score: data.score,
        passCount,
        failCount,
        errorCount,
        status: data.status || "complete",
        totalRules: data.results.length,
    };
}

/** Format a timestamp to a localized date/time string.
 *  Handles the bridge's compact format: "2026-04-08T025531" → "2026-04-08T02:55:31"
 */
function formatTimestamp(ts: string): string {
    // Insert colons into compact HHMMSS portion if needed
    const normalized = ts.replace(
        /T(\d{2})(\d{2})(\d{2})$/,
        "T$1:$2:$3"
    );
    const date = new Date(normalized);
    if (isNaN(date.getTime())) return ts;
    return date.toLocaleString();
}

/** Status label color mapping. */
function statusColor(status: string): "green" | "orange" | "red" | "grey" {
    switch (status.toLowerCase()) {
    case "complete":
    case "completed":
        return "green";
    case "interrupted":
        return "orange";
    case "error":
        return "red";
    default:
        return "grey";
    }
}

/** Column indices for sorting. */
const COL_DATE = 0;
const COL_PROFILE = 1;
const COL_SCORE = 2;
const COL_PASS = 3;
const COL_STATUS = 4;

export const ResultsPage: React.FunctionComponent = () => {
    const [loading, setLoading] = useState(true);
    const [error] = useState<string | null>(null);
    const [scans, setScans] = useState<ScanSummary[]>([]);
    const [sortIndex, setSortIndex] = useState<number>(COL_DATE);
    const [sortDirection, setSortDirection] = useState<"asc" | "desc">("desc");

    useEffect(() => {
        let cancelled = false;

        async function loadResults() {
            try {
                const listing = await cockpit.spawn(
                    ["ls", "-1", RESULTS_DIR],
                    { superuser: "try", err: "ignore" },
                );
                const jsonFiles = listing.trim().split("\n")
                        .filter(f => f.endsWith(".json"));

                if (jsonFiles.length === 0) {
                    if (!cancelled) {
                        setScans([]);
                        setLoading(false);
                    }
                    return;
                }

                const summaries: ScanSummary[] = [];
                for (const file of jsonFiles) {
                    try {
                        const content = await cockpit
                                .file(`${RESULTS_DIR}/${file}`, { superuser: "try" })
                                .read();
                        if (content !== null && content !== undefined) {
                            const data = JSON.parse(content) as ScanResult;
                            summaries.push(summarize(file, data));
                        }
                    } catch {
                        // Skip files that can't be read or parsed
                    }
                }

                if (!cancelled) {
                    setScans(summaries);
                }
            } catch {
                // Directory doesn't exist or is empty
                if (!cancelled) {
                    setScans([]);
                }
            } finally {
                if (!cancelled) setLoading(false);
            }
        }

        loadResults();
        return () => { cancelled = true };
    }, []);

    /* ------------------------------------------------------------------ */
    /* Sorting                                                             */
    /* ------------------------------------------------------------------ */

    function onSort(
        _event: React.MouseEvent,
        index: number,
        direction: "asc" | "desc",
    ) {
        setSortIndex(index);
        setSortDirection(direction);
    }

    function sortedScans(): ScanSummary[] {
        const sorted = [...scans];
        sorted.sort((a, b) => {
            let cmp = 0;
            switch (sortIndex) {
            case COL_DATE:
                cmp = a.timestamp.localeCompare(b.timestamp);
                break;
            case COL_PROFILE:
                cmp = a.profileId.localeCompare(b.profileId);
                break;
            case COL_SCORE:
                cmp = a.score - b.score;
                break;
            case COL_PASS:
                cmp = a.passCount - b.passCount;
                break;
            case COL_STATUS:
                cmp = a.status.localeCompare(b.status);
                break;
            default:
                cmp = 0;
            }
            return sortDirection === "asc" ? cmp : -cmp;
        });
        return sorted;
    }

    /** Navigate to the detail page for a scan result. */
    function onRowClick(filename: string) {
        // Strip .json extension
        const resultId = filename.replace(/\.json$/, "");
        cockpit.location.go(["results", resultId]);
    }

    /* ------------------------------------------------------------------ */
    /* Render                                                              */
    /* ------------------------------------------------------------------ */

    if (loading) {
        return (
            <PageSection>
                <Flex justifyContent={{ default: "justifyContentCenter" }}>
                    <FlexItem>
                        <Spinner size="xl" aria-label={_("Loading")} />
                    </FlexItem>
                </Flex>
            </PageSection>
        );
    }

    if (error) {
        return (
            <PageSection>
                <Alert variant="danger" title={_("Failed to load scan results")}>
                    {error}
                </Alert>
            </PageSection>
        );
    }

    if (scans.length === 0) {
        return (
            <PageSection>
                <EmptyState
                    titleText={_("No scan results yet")}
                    headingLevel="h2"
                >
                    <EmptyStateBody>
                        {_("Run a compliance scan to see historical results here.")}
                    </EmptyStateBody>
                    <EmptyStateFooter>
                        <EmptyStateActions>
                            <Button
                                variant="primary"
                                onClick={() => cockpit.location.go(["scan"])}
                            >
                                {_("Run Scan")}
                            </Button>
                        </EmptyStateActions>
                    </EmptyStateFooter>
                </EmptyState>
            </PageSection>
        );
    }

    const sortBy = { index: sortIndex, direction: sortDirection };
    const sorted = sortedScans();

    return (
        <PageSection>
            <Content
                component={ContentVariants.h1}
                style={{ marginBottom: "var(--pf-t--global--spacer--md)" }}
            >
                {_("Scan Results")}
            </Content>

            <Card>
                <CardBody>
                    <Table aria-label={_("Scan results history")} variant="compact">
                        <Thead>
                            <Tr>
                                <Th
                                    sort={{
                                        sortBy,
                                        onSort,
                                        columnIndex: COL_DATE,
                                    }}
                                >
                                    {_("Date / Time")}
                                </Th>
                                <Th
                                    sort={{
                                        sortBy,
                                        onSort,
                                        columnIndex: COL_PROFILE,
                                    }}
                                >
                                    {_("Profile")}
                                </Th>
                                <Th
                                    sort={{
                                        sortBy,
                                        onSort,
                                        columnIndex: COL_SCORE,
                                    }}
                                >
                                    {_("Score")}
                                </Th>
                                <Th
                                    sort={{
                                        sortBy,
                                        onSort,
                                        columnIndex: COL_PASS,
                                    }}
                                >
                                    {_("Pass / Fail / Error")}
                                </Th>
                                <Th
                                    sort={{
                                        sortBy,
                                        onSort,
                                        columnIndex: COL_STATUS,
                                    }}
                                >
                                    {_("Status")}
                                </Th>
                            </Tr>
                        </Thead>
                        <Tbody>
                            {sorted.map(scan => (
                                <Tr
                                    key={scan.filename}
                                    isClickable
                                    onRowClick={() => onRowClick(scan.filename)}
                                >
                                    <Td dataLabel={_("Date / Time")}>
                                        {formatTimestamp(scan.timestamp)}
                                    </Td>
                                    <Td dataLabel={_("Profile")}>
                                        {scan.profileId}
                                    </Td>
                                    <Td dataLabel={_("Score")}>
                                        {cockpit.format("$0%", scan.score.toFixed(1))}
                                    </Td>
                                    <Td dataLabel={_("Pass / Fail / Error")}>
                                        <Flex
                                            spaceItems={{ default: "spaceItemsSm" }}
                                            flexWrap={{ default: "nowrap" }}
                                        >
                                            <FlexItem>
                                                <Label color="green" isCompact>
                                                    {scan.passCount}
                                                </Label>
                                            </FlexItem>
                                            <FlexItem>
                                                <Label color="red" isCompact>
                                                    {scan.failCount}
                                                </Label>
                                            </FlexItem>
                                            <FlexItem>
                                                <Label color="orange" isCompact>
                                                    {scan.errorCount}
                                                </Label>
                                            </FlexItem>
                                        </Flex>
                                    </Td>
                                    <Td dataLabel={_("Status")}>
                                        <Label color={statusColor(scan.status)} isCompact>
                                            {scan.status}
                                        </Label>
                                    </Td>
                                </Tr>
                            ))}
                        </Tbody>
                    </Table>
                </CardBody>
            </Card>

            <Content
                component={ContentVariants.small}
                style={{
                    marginTop: "var(--pf-t--global--spacer--sm)",
                    textAlign: "center",
                }}
            >
                {cockpit.format(_("$0 scan result(s)"), scans.length)}
            </Content>
        </PageSection>
    );
};
