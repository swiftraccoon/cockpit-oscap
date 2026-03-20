import React, { useEffect, useState } from "react";
import { Alert } from "@patternfly/react-core/dist/esm/components/Alert/index.js";
import { Button } from "@patternfly/react-core/dist/esm/components/Button/index.js";
import { Card, CardBody, CardTitle } from "@patternfly/react-core/dist/esm/components/Card/index.js";
import { Content, ContentVariants } from "@patternfly/react-core/dist/esm/components/Content/index.js";
import {
    DescriptionList,
    DescriptionListDescription,
    DescriptionListGroup,
    DescriptionListTerm,
} from "@patternfly/react-core/dist/esm/components/DescriptionList/index.js";
import {
    EmptyState,
    EmptyStateActions,
    EmptyStateBody,
    EmptyStateFooter,
} from "@patternfly/react-core/dist/esm/components/EmptyState/index.js";
import { Label } from "@patternfly/react-core/dist/esm/components/Label/index.js";
import { PageSection } from "@patternfly/react-core/dist/esm/components/Page/index.js";
import { Spinner } from "@patternfly/react-core/dist/esm/components/Spinner/index.js";
import { Grid, GridItem } from "@patternfly/react-core/dist/esm/layouts/Grid/index.js";
import { Flex, FlexItem } from "@patternfly/react-core/dist/esm/layouts/Flex/index.js";
import cockpit from "cockpit";

import { detectBackend, loadConfig } from "../api";
import { ScoreCard } from "../components/ScoreCard.jsx";
import { RiskBadge } from "../components/RiskBadge.jsx";
import type { BackendInfo, Config, RuleResultItem, ScanResult, RiskLevel } from "../types";

const _ = cockpit.gettext;

const RESULTS_DIR = "/var/lib/cockpit-oscap/results";

/** Maximum number of failed rules to show in the summary table. */
const MAX_FAILED_RULES = 10;

/** Format a timestamp as a human-readable relative string. */
function relativeTime(timestamp: string): string {
    const then = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - then.getTime();
    const diffMin = Math.floor(diffMs / 60000);

    if (diffMin < 1) return _("just now");
    if (diffMin < 60) return cockpit.format(_("$0 min ago"), diffMin);
    const diffHours = Math.floor(diffMin / 60);
    if (diffHours < 24) return cockpit.format(_("$0h ago"), diffHours);
    const diffDays = Math.floor(diffHours / 24);
    return cockpit.format(_("$0d ago"), diffDays);
}

/** Map severity strings from SCAP results to RiskLevel. */
function severityToRisk(severity: string): RiskLevel {
    switch (severity.toLowerCase()) {
    case "high":
        return "high";
    case "medium":
        return "medium";
    case "low":
        return "low";
    default:
        return "medium";
    }
}

/** Load the newest JSON scan result from the results directory. */
async function loadLatestScan(): Promise<ScanResult | null> {
    try {
        const listing = await cockpit.spawn(
            ["ls", "-1t", RESULTS_DIR],
            { superuser: "try", err: "ignore" }
        );
        const files = listing.trim().split("\n")
                .filter(f => f.endsWith(".json"));
        if (files.length === 0) return null;

        const newest = files[0];
        const content = await cockpit
                .file(`${RESULTS_DIR}/${newest}`, { superuser: "try" })
                .read();
        if (content === null || content === undefined) return null;
        return JSON.parse(content) as ScanResult;
    } catch {
        return null;
    }
}

export const OverviewPage: React.FunctionComponent = () => {
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [backend, setBackend] = useState<BackendInfo | null>(null);
    const [config, setConfig] = useState<Config | null>(null);
    const [latestScan, setLatestScan] = useState<ScanResult | null>(null);

    useEffect(() => {
        let cancelled = false;

        async function init() {
            try {
                const [backendInfo, configData, scanData] = await Promise.all([
                    detectBackend(),
                    loadConfig(),
                    loadLatestScan(),
                ]);
                if (cancelled) return;

                setBackend(backendInfo);
                setConfig(configData);
                setLatestScan(scanData);
            } catch (err) {
                if (cancelled) return;
                setError(String(err));
            } finally {
                if (!cancelled) setLoading(false);
            }
        }

        init();
        return () => { cancelled = true };
    }, []);

    /* Loading state */
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

    /* Error state */
    if (error) {
        return (
            <PageSection>
                <Alert variant="danger" title={_("Failed to load compliance data")}>
                    {error}
                </Alert>
            </PageSection>
        );
    }

    /* Missing scap-security-guide */
    if (backend && !backend.content.present) {
        return (
            <PageSection>
                <Alert variant="warning" title={_("SCAP content not found")}>
                    {_("Install scap-security-guide to enable compliance scanning.")}
                    <br />
                    <code>sudo dnf install scap-security-guide</code>
                </Alert>
            </PageSection>
        );
    }

    /* No scan results yet */
    if (!latestScan) {
        return (
            <PageSection>
                <EmptyState
                    titleText={_("No scans yet")}
                    headingLevel="h2"
                >
                    <EmptyStateBody>
                        {_("Run your first compliance scan to see results here.")}
                    </EmptyStateBody>
                    <EmptyStateFooter>
                        <EmptyStateActions>
                            <Button
                                variant="primary"
                                onClick={() => cockpit.location.go(["scan"])}
                            >
                                {_("Run scan")}
                            </Button>
                        </EmptyStateActions>
                    </EmptyStateFooter>
                </EmptyState>
            </PageSection>
        );
    }

    /* Compute summary stats */
    const passCount = latestScan.results.filter(r => r.result === "pass").length;
    const failCount = latestScan.results.filter(r => r.result === "fail").length;
    const errorCount = latestScan.results.filter(r => r.result === "error").length;
    const score = latestScan.score;

    const profileName = config?.active_profile ?? latestScan.profile_id ?? _("Unknown");
    const hasTailoring = config !== null && "tailoring_path" in config && Boolean(config.tailoring_path);

    const failedRules: RuleResultItem[] = latestScan.results.filter(
        r => r.result === "fail" || r.result === "error"
    );
    const displayedRules = failedRules.slice(0, MAX_FAILED_RULES);

    /* Backend info line */
    const backendParts: string[] = [];
    if (backend) {
        backendParts.push(cockpit.format(_("Backend: OpenSCAP $0"), backend.oscap.version));
        backendParts.push(cockpit.format(_("Content: $0"), backend.content.datastream_path.split("/").pop() ?? "ssg"));
    }

    return (
        <PageSection>
            {/* Score cards row */}
            <Grid hasGutter>
                <GridItem sm={12} md={4}>
                    <ScoreCard
                        label={_("Active Profile")}
                        value={profileName}
                        subtext={hasTailoring ? _("Tailored") : undefined}
                    />
                </GridItem>
                <GridItem sm={12} md={4}>
                    <ScoreCard
                        label={_("Last Scan")}
                        value={new Date(latestScan.timestamp).toLocaleString()}
                        subtext={relativeTime(latestScan.timestamp)}
                    />
                </GridItem>
                <GridItem sm={12} md={4}>
                    <ScoreCard
                        label={_("Compliance Score")}
                        value={cockpit.format("$0%", score.toFixed(1))}
                        subtext={cockpit.format(
                            _("$0 pass, $1 fail, $2 error"),
                            passCount, failCount, errorCount
                        )}
                    />
                </GridItem>
            </Grid>

            {/* Failed rules summary */}
            {failedRules.length > 0 && (
                <Card style={{ marginTop: "var(--pf-t--global--spacer--md)" }}>
                    <CardTitle>{_("Failed Rules")}</CardTitle>
                    <CardBody>
                        <DescriptionList isHorizontal isCompact>
                            {displayedRules.map(rule => (
                                <DescriptionListGroup key={rule.rule_id}>
                                    <DescriptionListTerm>
                                        <Flex
                                            spaceItems={{ default: "spaceItemsSm" }}
                                            alignItems={{ default: "alignItemsCenter" }}
                                        >
                                            <FlexItem>
                                                <Label
                                                    color={rule.result === "error" ? "red" : "orangered"}
                                                    isCompact
                                                >
                                                    {rule.result.toUpperCase()}
                                                </Label>
                                            </FlexItem>
                                            <FlexItem>{rule.title}</FlexItem>
                                        </Flex>
                                    </DescriptionListTerm>
                                    <DescriptionListDescription>
                                        <RiskBadge level={severityToRisk(rule.severity)} />
                                    </DescriptionListDescription>
                                </DescriptionListGroup>
                            ))}
                        </DescriptionList>
                        {failedRules.length > MAX_FAILED_RULES && (
                            <Content
                                component={ContentVariants.p}
                                style={{ marginTop: "var(--pf-t--global--spacer--sm)" }}
                            >
                                <Button
                                    variant="link"
                                    isInline
                                    onClick={() => cockpit.location.go(["results"])}
                                >
                                    {cockpit.format(
                                        _("View all $0 failed rules"),
                                        failedRules.length
                                    )}
                                </Button>
                            </Content>
                        )}
                    </CardBody>
                </Card>
            )}

            {/* Scan Now button */}
            <Flex
                justifyContent={{ default: "justifyContentCenter" }}
                style={{ marginTop: "var(--pf-t--global--spacer--md)" }}
            >
                <FlexItem>
                    <Button
                        variant="primary"
                        onClick={() => cockpit.location.go(["scan"])}
                    >
                        {_("Scan Now")}
                    </Button>
                </FlexItem>
            </Flex>

            {/* Backend info footer */}
            {backendParts.length > 0 && (
                <Content
                    component={ContentVariants.small}
                    style={{
                        marginTop: "var(--pf-t--global--spacer--md)",
                        textAlign: "center",
                    }}
                >
                    {backendParts.join(" \u00B7 ")}
                </Content>
            )}
        </PageSection>
    );
};
