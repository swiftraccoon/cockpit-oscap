/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Overview: the latest score, the active profile, the scan schedule and the
 * rules that need attention.
 */

import React from "react";
import { Button } from "@patternfly/react-core/dist/esm/components/Button/index.js";
import { Card, CardBody, CardFooter, CardTitle } from "@patternfly/react-core/dist/esm/components/Card/index.js";
import { Content } from "@patternfly/react-core/dist/esm/components/Content/index.js";
import {
    DescriptionList,
    DescriptionListDescription,
    DescriptionListGroup,
    DescriptionListTerm,
} from "@patternfly/react-core/dist/esm/components/DescriptionList/index.js";
import { Label } from "@patternfly/react-core/dist/esm/components/Label/index.js";
import { Grid, GridItem } from "@patternfly/react-core/dist/esm/layouts/Grid/index.js";
import { Stack, StackItem } from "@patternfly/react-core/dist/esm/layouts/Stack/index.js";
import CheckCircleIcon from "@patternfly/react-icons/dist/esm/icons/check-circle-icon";
import ShieldAltIcon from "@patternfly/react-icons/dist/esm/icons/shield-alt-icon";
import cockpit from "cockpit";

import { EmptyStatePanel } from "cockpit-components-empty-state";
import { ListingTable } from "cockpit-components-table";
import * as timeformat from "timeformat";

import { getConfig, getResult, listProfiles, listResults, manageTimer } from "../api";
import { useApp } from "../app";
import { useAsync } from "../app-hooks";
import { ScoreTrend } from "../components/ScoreTrend";
import type { TrendPoint } from "../components/ScoreTrend";
import {
    CountLabels,
    ScanStatusLabel,
    ScoreLabel,
    ScoreValue,
    SeverityCounts,
    SeverityLabel,
    TailoredLabel,
    When,
} from "../components/labels";
import { ErrorState, Loading } from "../components/states";
import { compareSeverity, parseTimestamp, scoredTotal } from "../helpers";
import type { RuleResultItem, TimerStatus } from "../types";

const _ = cockpit.gettext;

const TOP_FAILED = 8;
const RECENT_SCANS = 5;
const TREND_POINTS = 12;

const Delta = ({ current, previous }: { current: number; previous: number }) => {
    const delta = Math.round((current - previous) * 10) / 10;
    if (delta === 0)
        return <span className="oscap-muted">{_("No change since the previous scan")}</span>;
    const className = delta > 0 ? "oscap-delta-up" : "oscap-delta-down";
    const text = delta > 0
        ? cockpit.format(_("Up $0 points since the previous scan"), delta)
        : cockpit.format(_("Down $0 points since the previous scan"), Math.abs(delta));
    return <span className={className}>{text}</span>;
};

function scheduleSummary(timer: TimerStatus | null): React.ReactNode {
    if (!timer || !timer.installed)
        return <Label color="grey" isCompact>{_("Not available")}</Label>;
    if (timer.status === "active")
        return <Label status="success" isCompact>{_("Enabled")}</Label>;
    return <Label color="grey" isCompact>{_("Disabled")}</Label>;
}

export const OverviewPage = () => {
    const app = useApp();
    const data = useAsync(async () => {
        const [results, config, profiles, timer] = await Promise.all([
            listResults(),
            getConfig(),
            listProfiles(),
            manageTimer("status").catch(() => null),
        ]);
        const latest = results.length > 0 ? await getResult(results[0].id) : null;
        return { results, config, profiles, timer, latest };
    }, [app.version]);

    if (data.loading && !data.data)
        return <Loading />;
    if (data.error || !data.data)
        return <ErrorState title={_("Failed to load compliance status")} error={data.error} onRetry={() => data.reload()} />;

    const { results, config, profiles, timer, latest } = data.data;
    const activeProfile = profiles.find(p => p.id === config.active_profile);

    if (!latest) {
        return (
            <EmptyStatePanel
                icon={ShieldAltIcon}
                title={_("No compliance scans yet")}
                paragraph={
                    <span className="oscap-empty-hint">
                        {_("Run a scan to evaluate this system against a security profile such as CIS, STIG or PCI DSS. Results, guided remediation and scheduled scans all start here.")}
                    </span>
                }
                action={
                    <Button
id="overview-run-scan" variant="primary" onClick={() => app.runScan()}
                            isDisabled={app.superuser === false || app.scanning}
                    >
                        {_("Run scan")}
                    </Button>
                }
                secondary={
                    <Button variant="link" onClick={() => cockpit.location.go(["profiles"])}>
                        {_("Browse profiles")}
                    </Button>
                }
            />
        );
    }

    const previous = results.find(r => r.id !== latest.id && r.status === "complete" &&
        r.base_profile_id === latest.base_profile_id && r.datastream === latest.datastream);
    const scannedAt = parseTimestamp(latest.timestamp);
    const failed: RuleResultItem[] = latest.results
            .filter(r => r.result === "fail" || r.result === "error")
            .sort((a, b) => (a.result === b.result ? compareSeverity(a.severity, b.severity) : a.result === "fail" ? -1 : 1));
    const recent = results.slice(0, RECENT_SCANS);
    const trend: TrendPoint[] = results
            .filter(r => r.base_profile_id === latest.base_profile_id && r.datastream === latest.datastream &&
                r.status === "complete")
            .slice(0, TREND_POINTS)
            .reverse()
            .map(r => ({ id: r.id, timestamp: r.timestamp, score: r.score }));

    return (
        <Stack hasGutter>
            <StackItem>
                <Grid hasGutter>
                    <GridItem md={4}>
                        <Card className="ct-card" id="overview-latest" isFullHeight>
                            <CardTitle>{_("Latest scan")}</CardTitle>
                            <CardBody>
                                <Stack hasGutter>
                                    <StackItem><ScoreValue score={latest.score} /></StackItem>
                                    <StackItem>
                                        <span className="oscap-inline-list">
                                            <CountLabels counts={latest.counts} />
                                            <ScanStatusLabel status={latest.status} />
                                        </span>
                                    </StackItem>
                                    {previous && (
                                        <StackItem><Delta current={latest.score} previous={previous.score} /></StackItem>
                                    )}
                                    {trend.length > 1 && (
                                        <StackItem>
                                            <ScoreTrend
                                                points={trend}
                                                onSelect={point => cockpit.location.go(["results", point.id])}
                                            />
                                        </StackItem>
                                    )}
                                    <StackItem>
                                        <DescriptionList isCompact>
                                            <DescriptionListGroup>
                                                <DescriptionListTerm>{_("Profile")}</DescriptionListTerm>
                                                <DescriptionListDescription>
                                                    {latest.profile_title || latest.profile_id}
                                                    {latest.tailored && <> {" "}<TailoredLabel /></>}
                                                </DescriptionListDescription>
                                            </DescriptionListGroup>
                                            <DescriptionListGroup>
                                                <DescriptionListTerm>{_("Scanned")}</DescriptionListTerm>
                                                <DescriptionListDescription>
                                                    {scannedAt ? <When iso={latest.timestamp} fallback="" /> : latest.timestamp}
                                                </DescriptionListDescription>
                                            </DescriptionListGroup>
                                        </DescriptionList>
                                    </StackItem>
                                </Stack>
                            </CardBody>
                            <CardFooter>
                                <Button variant="link" isInline onClick={() => cockpit.location.go(["results", latest.id])}>
                                    {_("View results")}
                                </Button>
                            </CardFooter>
                        </Card>
                    </GridItem>
                    <GridItem md={4}>
                        <Card className="ct-card" id="overview-profile" isFullHeight>
                            <CardTitle>{_("Active profile")}</CardTitle>
                            <CardBody>
                                {activeProfile
                                    ? (
                                        <Stack hasGutter>
                                            <StackItem>
                                                <div className="oscap-inline-list">
                                                    <strong>{activeProfile.title}</strong>
                                                    {activeProfile.tailored_profile_id && <TailoredLabel />}
                                                </div>
                                            </StackItem>
                                            <StackItem>
                                                <Content component="small">
                                                    {cockpit.format(cockpit.ngettext("$0 rule", "$0 rules", activeProfile.rule_count),
                                                                    activeProfile.rule_count)}
                                                    {" · "}
                                                    {_("Used by scheduled scans")}
                                                </Content>
                                            </StackItem>
                                        </Stack>
                                    )
                                    : (
                                        <Content component="p" className="oscap-muted">
                                            {_("No profile selected. Choose the security profile scheduled scans should use.")}
                                        </Content>
                                    )}
                            </CardBody>
                            <CardFooter className="oscap-card-actions">
                                <Button variant="link" isInline onClick={() => cockpit.location.go(["profiles"])}>
                                    {activeProfile ? _("Change") : _("Choose profile")}
                                </Button>
                                {activeProfile && (
                                    <Button
variant="link" isInline
                                            onClick={() => cockpit.location.go(["profiles", activeProfile.id])}
                                    >
                                        {_("Customize")}
                                    </Button>
                                )}
                            </CardFooter>
                        </Card>
                    </GridItem>
                    <GridItem md={4}>
                        <Card className="ct-card" id="overview-schedule" isFullHeight>
                            <CardTitle>{_("Scheduled scans")}</CardTitle>
                            <CardBody>
                                <DescriptionList isCompact>
                                    <DescriptionListGroup>
                                        <DescriptionListTerm>{_("Status")}</DescriptionListTerm>
                                        <DescriptionListDescription>{scheduleSummary(timer)}</DescriptionListDescription>
                                    </DescriptionListGroup>
                                    {timer?.status === "active" && (
                                        <DescriptionListGroup>
                                            <DescriptionListTerm>{_("Next run")}</DescriptionListTerm>
                                            <DescriptionListDescription>
                                                <When iso={timer.next_run} fallback={_("Not scheduled")} />
                                            </DescriptionListDescription>
                                        </DescriptionListGroup>
                                    )}
                                    {timer?.last_run && (
                                        <DescriptionListGroup>
                                            <DescriptionListTerm>{_("Last run")}</DescriptionListTerm>
                                            <DescriptionListDescription>
                                                <When iso={timer.last_run} fallback={_("Never")} />
                                            </DescriptionListDescription>
                                        </DescriptionListGroup>
                                    )}
                                </DescriptionList>
                            </CardBody>
                            <CardFooter>
                                <Button variant="link" isInline onClick={() => cockpit.location.go(["schedule"])}>
                                    {_("Configure")}
                                </Button>
                            </CardFooter>
                        </Card>
                    </GridItem>
                </Grid>
            </StackItem>
            <StackItem>
                <Grid hasGutter>
                    <GridItem md={8}>
                        <Card className="ct-card" id="overview-failed" isFullHeight>
                            <CardTitle>
                                {failed.length > 0
                                    ? cockpit.format(cockpit.ngettext("$0 rule needs attention", "$0 rules need attention", failed.length),
                                                     failed.length)
                                    : _("Rules needing attention")}
                            </CardTitle>
                            <CardBody>
                                {failed.length === 0
                                    ? (
                                        <EmptyStatePanel
                                            icon={CheckCircleIcon}
                                            title={_("All evaluated rules passed")}
                                            paragraph={cockpit.format(
                                                cockpit.ngettext("$0 rule was evaluated.", "$0 rules were evaluated.",
                                                                 scoredTotal(latest.counts)),
                                                scoredTotal(latest.counts))}
                                        />
                                    )
                                    : (
                                        <Stack hasGutter>
                                            <StackItem id="overview-severities"><SeverityCounts rules={failed} /></StackItem>
                                            <StackItem>
                                                <ListingTable
                                                    aria-label={_("Failed rules")}
                                                    variant="compact"
                                                    columns={[_("Severity"), _("Rule"), _("Category")]}
                                                    onRowClick={() => cockpit.location.go(["results", latest.id])}
                                                    rows={failed.slice(0, TOP_FAILED).map(rule => ({
                                                        props: { key: rule.rule_id },
                                                        columns: [
                                                            <SeverityLabel key="severity" severity={rule.severity} />,
                                                            rule.title || rule.rule_id,
                                                            rule.group || _("Uncategorized"),
                                                        ],
                                                    }))}
                                                />
                                            </StackItem>
                                        </Stack>
                                    )}
                            </CardBody>
                            {failed.length > 0 && (
                                <CardFooter>
                                    <Button variant="link" isInline onClick={() => cockpit.location.go(["results", latest.id])}>
                                        {failed.length > TOP_FAILED
                                            ? cockpit.format(_("View all $0 rules"), failed.length)
                                            : _("View results and remediate")}
                                    </Button>
                                </CardFooter>
                            )}
                        </Card>
                    </GridItem>
                    <GridItem md={4}>
                        <Card className="ct-card" id="overview-recent" isFullHeight>
                            <CardTitle>{_("Recent scans")}</CardTitle>
                            <CardBody>
                                <ListingTable
                                    aria-label={_("Recent scans")}
                                    variant="compact"
                                    showHeader={false}
                                    columns={[_("Scan"), { title: _("Score"), props: { modifier: "fitContent" } }]}
                                    onRowClick={(_ev, row) => cockpit.location.go(["results", String(row.props?.key)])}
                                    rows={recent.map(summary => {
                                        const date = parseTimestamp(summary.timestamp);
                                        return {
                                            props: { key: summary.id },
                                            columns: [
                                                {
                                                    title: (
                                                        <div className="oscap-stack-tight">
                                                            <span className="oscap-table-nowrap">
                                                                {date ? timeformat.dateTimeNoYear(date) : summary.timestamp}
                                                            </span>
                                                            <span className="oscap-muted oscap-small">
                                                                {summary.profile_title || summary.profile_id}
                                                            </span>
                                                        </div>
                                                    ),
                                                },
                                                { title: <ScoreLabel score={summary.score} /> },
                                            ],
                                        };
                                    })}
                                />
                            </CardBody>
                            <CardFooter>
                                <Button variant="link" isInline onClick={() => cockpit.location.go(["results"])}>
                                    {_("All results")}
                                </Button>
                            </CardFooter>
                        </Card>
                    </GridItem>
                </Grid>
            </StackItem>
            <StackItem>
                <Content component="small" className="oscap-muted">
                    {cockpit.format(_("OpenSCAP $0 · $1"), app.backend.oscap?.version ?? "",
                                    app.backend.content.datastream_path.split("/").pop() ?? "")}
                    {app.backend.content.os.pretty_name && ` · ${app.backend.content.os.pretty_name}`}
                </Content>
            </StackItem>
        </Stack>
    );
};
