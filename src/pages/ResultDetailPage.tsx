import React, { useEffect, useState } from "react";
import { Alert } from "@patternfly/react-core/dist/esm/components/Alert/index.js";
import { Button } from "@patternfly/react-core/dist/esm/components/Button/index.js";
import { Card, CardBody, CardTitle } from "@patternfly/react-core/dist/esm/components/Card/index.js";
import { Checkbox } from "@patternfly/react-core/dist/esm/components/Checkbox/index.js";
import { Content, ContentVariants } from "@patternfly/react-core/dist/esm/components/Content/index.js";
import {
    EmptyState,
    EmptyStateBody,
} from "@patternfly/react-core/dist/esm/components/EmptyState/index.js";
import { Label } from "@patternfly/react-core/dist/esm/components/Label/index.js";
import { MenuToggle } from "@patternfly/react-core/dist/esm/components/MenuToggle/index.js";
import { PageSection } from "@patternfly/react-core/dist/esm/components/Page/index.js";
import { Progress } from "@patternfly/react-core/dist/esm/components/Progress/index.js";
import { Select, SelectList, SelectOption } from "@patternfly/react-core/dist/esm/components/Select/index.js";
import { Spinner } from "@patternfly/react-core/dist/esm/components/Spinner/index.js";
import { TextInput } from "@patternfly/react-core/dist/esm/components/TextInput/index.js";
import {
    Toolbar,
    ToolbarContent,
    ToolbarItem,
} from "@patternfly/react-core/dist/esm/components/Toolbar/index.js";
import { Flex, FlexItem } from "@patternfly/react-core/dist/esm/layouts/Flex/index.js";
import { Table, Thead, Tbody, Tr, Th, Td, ExpandableRowContent } from "@patternfly/react-table/dist/esm/components/Table/index.js";
import CheckCircleIcon from "@patternfly/react-icons/dist/esm/icons/check-circle-icon";
import TimesCircleIcon from "@patternfly/react-icons/dist/esm/icons/times-circle-icon";
import ExclamationTriangleIcon from "@patternfly/react-icons/dist/esm/icons/exclamation-triangle-icon";
import cockpit from "cockpit";

import { applyFix, generateFix, scan } from "../api";
import { RiskBadge } from "../components/RiskBadge.jsx";
import type {
    ApplyResult,
    FixInfo,
    FixRuleInfo,
    RiskLevel,
    RuleResultItem,
    ScanResult,
} from "../types";

const _ = cockpit.gettext;

const RESULTS_DIR = "/var/lib/cockpit-oscap/results";

// ---------------------------------------------------------------------------
// Category derivation (shared with TailoringEditor pattern)
// ---------------------------------------------------------------------------

const CATEGORY_MAP: [RegExp, string][] = [
    [/\brule_sysctl_/, "Kernel Settings"],
    [/\brule_audit_/, "Audit & Logging"],
    [/\brule_service_/, "Services & Daemons"],
    [/\brule_file_/, "File Permissions"],
    [/\brule_permissions_/, "File Permissions"],
    [/\brule_accounts_/, "Accounts & Authentication"],
    [/\brule_package_/, "Software & Packages"],
    [/\brule_selinux_/, "SELinux"],
    [/\brule_firewall_/, "Firewall"],
    [/\brule_network_/, "Network"],
    [/\brule_mount_/, "Filesystem & Mounts"],
    [/\brule_partition_/, "Filesystem & Mounts"],
    [/\brule_grub_/, "Bootloader"],
    [/\brule_banner_/, "Login Banners"],
    [/\brule_chronyd_/, "Time Synchronization"],
    [/\brule_crypto_/, "Cryptographic Policies"],
    [/\brule_sudo_/, "Privilege Escalation"],
    [/\brule_sshd_/, "SSH Configuration"],
    [/\brule_ssh_/, "SSH Configuration"],
    [/\brule_aide_/, "Integrity Checking"],
    [/\brule_rsyslog_/, "Logging"],
    [/\brule_journald_/, "Logging"],
    [/\brule_coredump_/, "Core Dumps"],
];

function deriveSubsystem(ruleId: string): string {
    for (const [pattern, category] of CATEGORY_MAP) {
        if (pattern.test(ruleId)) return category;
    }
    return "Other";
}

// ---------------------------------------------------------------------------
// High-risk warning text for specific patterns
// ---------------------------------------------------------------------------

const HIGH_RISK_WARNINGS: [RegExp, string][] = [
    [/sudoers/, "May lock out users not in wheel group"],
    [/pam\.d/, "May disrupt login or authentication mechanisms"],
    [/firewalld|firewall-cmd/, "May block network connectivity"],
    [/selinux|semanage/, "May change SELinux enforcement and break services"],
    [/authselect/, "May change system authentication configuration"],
    [/sshd_config/, "May change SSH access and lock out remote users"],
];

function getHighRiskWarning(fixSnippet: string): string | null {
    for (const [pattern, warning] of HIGH_RISK_WARNINGS) {
        if (pattern.test(fixSnippet)) return warning;
    }
    return null;
}

// ---------------------------------------------------------------------------
// Status display helpers
// ---------------------------------------------------------------------------

function statusIcon(result: string): React.ReactNode {
    switch (result) {
    case "pass":
    case "fixed":
        return <CheckCircleIcon color="var(--pf-t--global--color--status--success--default)" />;
    case "fail":
        return <TimesCircleIcon color="var(--pf-t--global--color--status--danger--default)" />;
    case "error":
        return <ExclamationTriangleIcon color="var(--pf-t--global--color--status--warning--default)" />;
    default:
        return <Label color="grey" isCompact>{result}</Label>;
    }
}

function severityColor(severity: string): "red" | "orange" | "blue" | "grey" {
    switch (severity.toLowerCase()) {
    case "high":
        return "red";
    case "medium":
        return "orange";
    case "low":
        return "blue";
    default:
        return "grey";
    }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type ViewMode = "rules" | "remediate";
type StatusFilter = "all" | "pass" | "fail" | "error" | "other";
type SeverityFilter = "all" | "high" | "medium" | "low" | "unknown";

type ApplyState =
    | "idle"
    | "generating"
    | "ready"
    | "applying"
    | "rescanning"
    | "done"
    | "error";

interface ResultDetailPageProps {
    resultId: string;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export const ResultDetailPage = ({ resultId }: ResultDetailPageProps) => {
    // Core data
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [scanResult, setScanResult] = useState<ScanResult | null>(null);

    // Rules view state
    const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());
    const [searchText, setSearchText] = useState("");
    const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
    const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
    const [statusFilterOpen, setStatusFilterOpen] = useState(false);
    const [severityFilterOpen, setSeverityFilterOpen] = useState(false);

    // View mode: rules table vs remediation flow
    const [viewMode, setViewMode] = useState<ViewMode>("rules");

    // Remediation state
    const [fixInfo, setFixInfo] = useState<FixInfo | null>(null);
    const [selectedRuleIds, setSelectedRuleIds] = useState<Set<string>>(new Set());
    const [applyState, setApplyState] = useState<ApplyState>("idle");
    const [applyResult, setApplyResult] = useState<ApplyResult | null>(null);
    const [rescanResult, setRescanResult] = useState<ScanResult | null>(null);
    const [remediationError, setRemediationError] = useState<string | null>(null);
    const [expandedRemRows, setExpandedRemRows] = useState<Set<string>>(new Set());

    // -----------------------------------------------------------------------
    // Load scan result on mount
    // -----------------------------------------------------------------------

    useEffect(() => {
        let cancelled = false;

        async function loadResult() {
            try {
                const content = await cockpit
                        .file(`${RESULTS_DIR}/${resultId}.json`, { superuser: "try" })
                        .read();
                if (content === null || content === undefined) {
                    if (!cancelled) setError(_("Scan result file not found."));
                    return;
                }
                const data = JSON.parse(content) as ScanResult;
                if (!cancelled) setScanResult(data);
            } catch (err) {
                if (!cancelled) setError(cockpit.format(_("Failed to load scan result: $0"), String(err)));
            } finally {
                if (!cancelled) setLoading(false);
            }
        }

        loadResult();
        return () => { cancelled = true };
    }, [resultId]);

    // -----------------------------------------------------------------------
    // Rules table: filtering
    // -----------------------------------------------------------------------

    function filteredRules(): RuleResultItem[] {
        if (!scanResult) return [];

        return scanResult.results.filter(r => {
            // Text search
            if (searchText) {
                const needle = searchText.toLowerCase();
                const haystack = `${r.title} ${r.rule_id} ${r.severity}`.toLowerCase();
                if (!haystack.includes(needle)) return false;
            }

            // Status filter
            if (statusFilter !== "all") {
                if (statusFilter === "other") {
                    if (["pass", "fail", "error"].includes(r.result)) return false;
                } else {
                    if (r.result !== statusFilter) return false;
                }
            }

            // Severity filter
            if (severityFilter !== "all") {
                if (severityFilter === "unknown") {
                    if (["high", "medium", "low"].includes(r.severity.toLowerCase())) return false;
                } else {
                    if (r.severity.toLowerCase() !== severityFilter) return false;
                }
            }

            return true;
        });
    }

    // -----------------------------------------------------------------------
    // Expand rows
    // -----------------------------------------------------------------------

    function toggleExpand(ruleId: string) {
        setExpandedRows(prev => {
            const next = new Set(prev);
            if (next.has(ruleId)) {
                next.delete(ruleId);
            } else {
                next.add(ruleId);
            }
            return next;
        });
    }

    function toggleRemExpand(ruleId: string) {
        setExpandedRemRows(prev => {
            const next = new Set(prev);
            if (next.has(ruleId)) {
                next.delete(ruleId);
            } else {
                next.add(ruleId);
            }
            return next;
        });
    }

    // -----------------------------------------------------------------------
    // Remediation flow
    // -----------------------------------------------------------------------

    /** Enter remediation mode: generate fix info. */
    async function onStartRemediation() {
        if (!scanResult) return;

        setViewMode("remediate");
        setApplyState("generating");
        setRemediationError(null);
        setApplyResult(null);
        setRescanResult(null);

        try {
            const fix = await generateFix(scanResult.profile_id);
            setFixInfo(fix);

            // Pre-select low and medium risk rules, leave high unchecked
            const selected = new Set<string>();
            for (const rule of fix.rules) {
                // Only include rules that actually failed
                const scanRule = scanResult.results.find(r => r.rule_id === rule.id);
                if (scanRule && scanRule.result === "fail") {
                    if (rule.risk_level !== "high" && rule.risk_level !== "critical") {
                        selected.add(rule.id);
                    }
                }
            }
            setSelectedRuleIds(selected);
            setApplyState("ready");
        } catch (err) {
            setRemediationError(cockpit.format(_("Failed to generate fix: $0"), String(err)));
            setApplyState("error");
        }
    }

    /** Get the failed rules with available fixes. */
    function remediableRules(): (FixRuleInfo & { title: string; severity: string })[] {
        if (!scanResult || !fixInfo) return [];

        return fixInfo.rules
                .map(fix => {
                    const scanRule = scanResult.results.find(r => r.rule_id === fix.id);
                    return {
                        ...fix,
                        title: scanRule?.title ?? fix.id,
                        severity: scanRule?.severity ?? "unknown",
                        result: scanRule?.result ?? "unknown",
                    };
                })
                .filter(r => r.result === "fail");
    }

    function toggleRuleSelection(ruleId: string) {
        setSelectedRuleIds(prev => {
            const next = new Set(prev);
            if (next.has(ruleId)) {
                next.delete(ruleId);
            } else {
                next.add(ruleId);
            }
            return next;
        });
    }

    /** Build a bash script from selected rule fix snippets. */
    function buildSelectedScript(): string {
        if (!fixInfo) return "";

        const lines = ["#!/bin/bash", "# Remediation script generated by cockpit-oscap", "set -e", ""];
        for (const rule of fixInfo.rules) {
            if (selectedRuleIds.has(rule.id)) {
                lines.push(`# --- ${rule.id} ---`);
                lines.push(rule.fix_snippet);
                lines.push("");
            }
        }
        return lines.join("\n");
    }

    /** Export the selected fix as a downloadable bash script. */
    function onExportScript() {
        const script = buildSelectedScript();
        if (!script) return;

        const blob = new Blob([script], { type: "text/x-shellscript" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `remediation-${resultId}.sh`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    /** Apply the selected fixes, then re-scan. */
    async function onApplySelected() {
        if (!scanResult) return;

        const script = buildSelectedScript();
        if (!script) return;

        setApplyState("applying");
        setRemediationError(null);

        try {
            // Write script to a temp file on the system
            const scriptPath = `/var/lib/cockpit-oscap/results/remediation-${Date.now()}.sh`;
            await cockpit
                    .file(scriptPath, { superuser: "try" })
                    .replace(script);

            // Make it executable
            await cockpit.spawn(["chmod", "+x", scriptPath], { superuser: "try" });

            // Apply
            const result = await applyFix(scriptPath);
            setApplyResult(result);

            if (!result.success) {
                setRemediationError(cockpit.format(
                    _("Fix script completed with errors: $0"),
                    result.errors.slice(0, 500),
                ));
                setApplyState("error");
                return;
            }

            // Re-scan to see what changed
            setApplyState("rescanning");
            try {
                const rescan = await scan(scanResult.profile_id);
                setRescanResult(rescan);
                setApplyState("done");
            } catch (err) {
                setRemediationError(cockpit.format(
                    _("Fix applied but re-scan failed: $0"),
                    String(err),
                ));
                setApplyState("error");
            }
        } catch (err) {
            setRemediationError(cockpit.format(_("Failed to apply fix: $0"), String(err)));
            setApplyState("error");
        }
    }

    /** Compute which rules were fixed vs still failing after re-scan. */
    function postApplyComparison(): { fixed: string[]; stillFailing: string[] } {
        if (!rescanResult || !scanResult) return { fixed: [], stillFailing: [] };

        const fixed: string[] = [];
        const stillFailing: string[] = [];

        for (const ruleId of selectedRuleIds) {
            const newResult = rescanResult.results.find(r => r.rule_id === ruleId);
            if (newResult && newResult.result === "pass") {
                fixed.push(ruleId);
            } else {
                stillFailing.push(ruleId);
            }
        }

        return { fixed, stillFailing };
    }

    function handleBack() {
        cockpit.location.go(["results"]);
    }

    function handleBackToRules() {
        setViewMode("rules");
        setApplyState("idle");
    }

    // -----------------------------------------------------------------------
    // Filter labels
    // -----------------------------------------------------------------------

    const statusLabels: Record<StatusFilter, string> = {
        all: _("All statuses"),
        pass: _("Pass"),
        fail: _("Fail"),
        error: _("Error"),
        other: _("Other"),
    };

    const severityLabels: Record<SeverityFilter, string> = {
        all: _("All severities"),
        high: _("High"),
        medium: _("Medium"),
        low: _("Low"),
        unknown: _("Unknown"),
    };

    // -----------------------------------------------------------------------
    // Render: loading / error states
    // -----------------------------------------------------------------------

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

    if (error || !scanResult) {
        return (
            <PageSection>
                <Alert variant="danger" title={_("Failed to load scan result")}>
                    {error ?? _("Unknown error")}
                </Alert>
                <Button
                    variant="link"
                    onClick={handleBack}
                    style={{ marginTop: "var(--pf-t--global--spacer--sm)" }}
                >
                    {_("Back to Results")}
                </Button>
            </PageSection>
        );
    }

    // -----------------------------------------------------------------------
    // Summary stats
    // -----------------------------------------------------------------------

    const passCount = scanResult.results.filter(r => r.result === "pass").length;
    const failCount = scanResult.results.filter(r => r.result === "fail").length;
    const errorCount = scanResult.results.filter(r => r.result === "error").length;

    // -----------------------------------------------------------------------
    // Render: remediation "done" view (post-apply comparison)
    // -----------------------------------------------------------------------

    if (viewMode === "remediate" && applyState === "done" && rescanResult) {
        const { fixed, stillFailing } = postApplyComparison();

        /** Look up a rule title by ID. */
        const ruleTitle = (ruleId: string): string => {
            const r = scanResult?.results.find(x => x.rule_id === ruleId);
            return r ? r.title : ruleId;
        };

        return (
            <PageSection>
                <Flex
                    justifyContent={{ default: "justifyContentSpaceBetween" }}
                    alignItems={{ default: "alignItemsCenter" }}
                    style={{ marginBottom: "var(--pf-t--global--spacer--md)" }}
                >
                    <FlexItem>
                        <Content component={ContentVariants.h1}>
                            {_("Remediation Results")}
                        </Content>
                    </FlexItem>
                    <FlexItem>
                        <Button variant="secondary" onClick={handleBack}>
                            {_("Back to Results")}
                        </Button>
                    </FlexItem>
                </Flex>

                <Alert
                    variant="success"
                    isInline
                    title={cockpit.format(
                        _("Remediation complete: new score $0% (was $1%)"),
                        rescanResult.score.toFixed(1),
                        scanResult.score.toFixed(1),
                    )}
                    style={{ marginBottom: "var(--pf-t--global--spacer--md)" }}
                />

                {fixed.length > 0 && (
                    <Card style={{ marginBottom: "var(--pf-t--global--spacer--sm)" }}>
                        <CardTitle>
                            <Flex spaceItems={{ default: "spaceItemsSm" }} alignItems={{ default: "alignItemsCenter" }}>
                                <FlexItem>
                                    <CheckCircleIcon color="var(--pf-t--global--color--status--success--default)" />
                                </FlexItem>
                                <FlexItem>
                                    {cockpit.format(_("$0 rule(s) fixed"), fixed.length)}
                                </FlexItem>
                            </Flex>
                        </CardTitle>
                        <CardBody>
                            <Table aria-label={_("Fixed rules")} variant="compact">
                                <Tbody>
                                    {fixed.map(id => (
                                        <Tr key={id}>
                                            <Td>
                                                <CheckCircleIcon color="var(--pf-t--global--color--status--success--default)" />
                                            </Td>
                                            <Td>{ruleTitle(id)}</Td>
                                        </Tr>
                                    ))}
                                </Tbody>
                            </Table>
                        </CardBody>
                    </Card>
                )}

                {stillFailing.length > 0 && (
                    <Card style={{ marginBottom: "var(--pf-t--global--spacer--sm)" }}>
                        <CardTitle>
                            <Flex spaceItems={{ default: "spaceItemsSm" }} alignItems={{ default: "alignItemsCenter" }}>
                                <FlexItem>
                                    <TimesCircleIcon color="var(--pf-t--global--color--status--danger--default)" />
                                </FlexItem>
                                <FlexItem>
                                    {cockpit.format(_("$0 rule(s) still failing"), stillFailing.length)}
                                </FlexItem>
                            </Flex>
                        </CardTitle>
                        <CardBody>
                            <Table aria-label={_("Still failing rules")} variant="compact">
                                <Tbody>
                                    {stillFailing.map(id => (
                                        <Tr key={id}>
                                            <Td>
                                                <TimesCircleIcon color="var(--pf-t--global--color--status--danger--default)" />
                                            </Td>
                                            <Td>{ruleTitle(id)}</Td>
                                        </Tr>
                                    ))}
                                </Tbody>
                            </Table>
                        </CardBody>
                    </Card>
                )}
            </PageSection>
        );
    }

    // -----------------------------------------------------------------------
    // Render: remediation flow
    // -----------------------------------------------------------------------

    if (viewMode === "remediate") {
        const remedRules = remediableRules();
        const selectedCount = selectedRuleIds.size;

        return (
            <PageSection>
                {/* Header */}
                <Flex
                    justifyContent={{ default: "justifyContentSpaceBetween" }}
                    alignItems={{ default: "alignItemsCenter" }}
                    style={{ marginBottom: "var(--pf-t--global--spacer--md)" }}
                >
                    <FlexItem>
                        <Flex alignItems={{ default: "alignItemsCenter" }} spaceItems={{ default: "spaceItemsSm" }}>
                            <FlexItem>
                                <Button variant="link" isInline onClick={handleBackToRules}>
                                    {_("Back to Rules")}
                                </Button>
                            </FlexItem>
                            <FlexItem>
                                <Content component={ContentVariants.h1}>
                                    {_("Remediate Failed Rules")}
                                </Content>
                            </FlexItem>
                        </Flex>
                    </FlexItem>
                    <FlexItem>
                        <Flex spaceItems={{ default: "spaceItemsSm" }}>
                            <FlexItem>
                                <Button
                                    variant="secondary"
                                    onClick={onExportScript}
                                    isDisabled={selectedCount === 0 || applyState === "generating"}
                                >
                                    {_("Export Script")}
                                </Button>
                            </FlexItem>
                            <FlexItem>
                                <Button
                                    variant="primary"
                                    onClick={onApplySelected}
                                    isDisabled={selectedCount === 0 || applyState !== "ready"}
                                    isLoading={applyState === "applying" || applyState === "rescanning"}
                                >
                                    {applyState === "rescanning"
                                        ? _("Re-scanning...")
                                        : cockpit.format(_("Apply Selected ($0)"), selectedCount)}
                                </Button>
                            </FlexItem>
                        </Flex>
                    </FlexItem>
                </Flex>

                {/* Progress / error alerts */}
                {applyState === "generating" && (
                    <Flex
                        justifyContent={{ default: "justifyContentCenter" }}
                        style={{ marginBottom: "var(--pf-t--global--spacer--md)" }}
                    >
                        <FlexItem>
                            <Spinner size="lg" aria-label={_("Generating fixes")} />
                        </FlexItem>
                        <FlexItem>
                            <Content component={ContentVariants.p}>
                                {_("Generating fix scripts...")}
                            </Content>
                        </FlexItem>
                    </Flex>
                )}

                {applyState === "applying" && (
                    <div style={{ marginBottom: "var(--pf-t--global--spacer--md)" }}>
                        <Alert variant="info" isInline title={_("Applying remediation scripts...")}>
                            {_("This may take several minutes. Do not close this page.")}
                        </Alert>
                        <Progress
                            aria-label={_("Apply progress")}
                            measureLocation="none"
                            style={{ marginTop: "var(--pf-t--global--spacer--sm)" }}
                        />
                    </div>
                )}

                {applyState === "rescanning" && (
                    <Alert
                        variant="info"
                        isInline
                        title={_("Re-scanning to verify fixes...")}
                        style={{ marginBottom: "var(--pf-t--global--spacer--md)" }}
                    />
                )}

                {remediationError && (
                    <Alert
                        variant="danger"
                        isInline
                        title={_("Remediation error")}
                        style={{ marginBottom: "var(--pf-t--global--spacer--md)" }}
                    >
                        {remediationError}
                    </Alert>
                )}

                {applyResult && !applyResult.success && applyResult.output && (
                    <Alert
                        variant="warning"
                        isInline
                        title={_("Script output")}
                        style={{ marginBottom: "var(--pf-t--global--spacer--md)" }}
                    >
                        <pre style={{ whiteSpace: "pre-wrap", fontSize: "0.85em", maxHeight: "200px", overflow: "auto" }}>
                            {applyResult.output}
                        </pre>
                    </Alert>
                )}

                {/* Remediation table */}
                {applyState === "ready" && (
                    remedRules.length === 0
                        ? (
                            <EmptyState titleText={_("No remediable rules")} headingLevel="h3">
                                <EmptyStateBody>
                                    {_("No failed rules have available fix scripts.")}
                                </EmptyStateBody>
                            </EmptyState>
                        )
                        : (
                            <Card>
                                <CardBody>
                                    <Content
                                            component={ContentVariants.small}
                                            style={{ marginBottom: "var(--pf-t--global--spacer--sm)" }}
                                    >
                                        {_("High-risk rules are unchecked by default. Review carefully before applying.")}
                                    </Content>

                                    <Table aria-label={_("Remediable rules")} variant="compact">
                                        <Thead>
                                            <Tr>
                                                <Th screenReaderText={_("Select")} />
                                                <Th>{_("Rule")}</Th>
                                                <Th>{_("Fix Preview")}</Th>
                                                <Th>{_("Risk")}</Th>
                                                <Th>{_("Subsystem")}</Th>
                                                <Th screenReaderText={_("Expand")} />
                                            </Tr>
                                        </Thead>
                                        <Tbody>
                                            {remedRules.map((rule, rowIndex) => {
                                                const isHighRisk = rule.risk_level === "high" || rule.risk_level === "critical";
                                                const isSelected = selectedRuleIds.has(rule.id);
                                                const isExpanded = expandedRemRows.has(rule.id);
                                                const warning = isHighRisk ? getHighRiskWarning(rule.fix_snippet) : null;

                                                return (
                                                    <React.Fragment key={rule.id}>
                                                        <Tr
                                                                style={isHighRisk
                                                                    ? { backgroundColor: "var(--pf-t--global--color--status--warning--100, #fdf7e7)" }
                                                                    : undefined}
                                                        >
                                                            <Td dataLabel={_("Select")}>
                                                                <Checkbox
                                                                        id={`rem-check-${rule.id}`}
                                                                        isChecked={isSelected}
                                                                        onChange={() => toggleRuleSelection(rule.id)}
                                                                        aria-label={cockpit.format(_("Select rule $0"), rule.title)}
                                                                />
                                                            </Td>
                                                            <Td dataLabel={_("Rule")}>
                                                                {rule.title}
                                                                {warning && (
                                                                    <div style={{ marginTop: "4px" }}>
                                                                        <Label color="orange" isCompact icon={<ExclamationTriangleIcon />}>
                                                                            {_(warning)}
                                                                        </Label>
                                                                    </div>
                                                                )}
                                                            </Td>
                                                            <Td dataLabel={_("Fix Preview")}>
                                                                <code style={{ fontSize: "0.8em" }}>
                                                                    {rule.fix_snippet.split("\n")[0].slice(0, 60)}
                                                                    {rule.fix_snippet.length > 60 ? "..." : ""}
                                                                </code>
                                                            </Td>
                                                            <Td dataLabel={_("Risk")}>
                                                                <RiskBadge level={rule.risk_level as RiskLevel} />
                                                            </Td>
                                                            <Td dataLabel={_("Subsystem")}>
                                                                {deriveSubsystem(rule.id)}
                                                            </Td>
                                                            <Td
                                                                    expand={{
                                                                        rowIndex,
                                                                        isExpanded,
                                                                        onToggle: () => toggleRemExpand(rule.id),
                                                                        expandId: `rem-expand-${rule.id}`,
                                                                    }}
                                                            />
                                                        </Tr>
                                                        {isExpanded && (
                                                            <Tr isExpanded>
                                                                <Td colSpan={6}>
                                                                    <ExpandableRowContent>
                                                                        <Content component={ContentVariants.p}>
                                                                            <strong>{_("Full fix script:")}</strong>
                                                                        </Content>
                                                                        <pre style={{
                                                                            whiteSpace: "pre-wrap",
                                                                            fontSize: "0.85em",
                                                                            maxHeight: "300px",
                                                                            overflow: "auto",
                                                                            backgroundColor: "var(--pf-t--global--background--color--secondary--default, #f0f0f0)",
                                                                            padding: "var(--pf-t--global--spacer--sm)",
                                                                            borderRadius: "4px",
                                                                        }}
                                                                        >
                                                                            {rule.fix_snippet}
                                                                        </pre>
                                                                    </ExpandableRowContent>
                                                                </Td>
                                                            </Tr>
                                                        )}
                                                    </React.Fragment>
                                                );
                                            })}
                                        </Tbody>
                                    </Table>
                                </CardBody>
                            </Card>
                        )
                )}
            </PageSection>
        );
    }

    // -----------------------------------------------------------------------
    // Render: rules table (main view)
    // -----------------------------------------------------------------------

    const filtered = filteredRules();

    return (
        <PageSection>
            {/* Header */}
            <Flex
                justifyContent={{ default: "justifyContentSpaceBetween" }}
                alignItems={{ default: "alignItemsCenter" }}
                style={{ marginBottom: "var(--pf-t--global--spacer--md)" }}
            >
                <FlexItem>
                    <Flex alignItems={{ default: "alignItemsCenter" }} spaceItems={{ default: "spaceItemsSm" }}>
                        <FlexItem>
                            <Button variant="link" isInline onClick={handleBack}>
                                {_("Back to Results")}
                            </Button>
                        </FlexItem>
                        <FlexItem>
                            <Content component={ContentVariants.h1}>
                                {_("Scan Detail")}
                            </Content>
                        </FlexItem>
                    </Flex>
                </FlexItem>
                <FlexItem>
                    {failCount > 0 && (
                        <Button
                            variant="primary"
                            onClick={onStartRemediation}
                        >
                            {_("Remediate Selected")}
                        </Button>
                    )}
                </FlexItem>
            </Flex>

            {/* Summary bar */}
            <Card style={{ marginBottom: "var(--pf-t--global--spacer--md)" }}>
                <CardBody>
                    <Flex
                        spaceItems={{ default: "spaceItemsLg" }}
                        alignItems={{ default: "alignItemsCenter" }}
                        flexWrap={{ default: "wrap" }}
                    >
                        <FlexItem>
                            <Content component={ContentVariants.small}>{_("Profile")}</Content>
                            <Content component={ContentVariants.p}>
                                <strong>{scanResult.profile_id}</strong>
                            </Content>
                        </FlexItem>
                        <FlexItem>
                            <Content component={ContentVariants.small}>{_("Scanned")}</Content>
                            <Content component={ContentVariants.p}>
                                <strong>{new Date(scanResult.timestamp).toLocaleString()}</strong>
                            </Content>
                        </FlexItem>
                        <FlexItem>
                            <Content component={ContentVariants.small}>{_("Score")}</Content>
                            <Content component={ContentVariants.p}>
                                <strong>{cockpit.format("$0%", scanResult.score.toFixed(1))}</strong>
                            </Content>
                        </FlexItem>
                        <FlexItem>
                            <Flex spaceItems={{ default: "spaceItemsSm" }}>
                                <FlexItem>
                                    <Label color="green" isCompact>
                                        {cockpit.format(_("$0 pass"), passCount)}
                                    </Label>
                                </FlexItem>
                                <FlexItem>
                                    <Label color="red" isCompact>
                                        {cockpit.format(_("$0 fail"), failCount)}
                                    </Label>
                                </FlexItem>
                                <FlexItem>
                                    <Label color="orange" isCompact>
                                        {cockpit.format(_("$0 error"), errorCount)}
                                    </Label>
                                </FlexItem>
                            </Flex>
                        </FlexItem>
                    </Flex>
                </CardBody>
            </Card>

            {/* Filter toolbar */}
            <Toolbar>
                <ToolbarContent>
                    <ToolbarItem>
                        <TextInput
                            type="search"
                            aria-label={_("Search rules")}
                            placeholder={_("Search rules...")}
                            value={searchText}
                            onChange={(_event, value) => setSearchText(value)}
                        />
                    </ToolbarItem>
                    <ToolbarItem>
                        <Select
                            isOpen={statusFilterOpen}
                            selected={statusFilter}
                            onSelect={(_event, value) => {
                                setStatusFilter(value as StatusFilter);
                                setStatusFilterOpen(false);
                            }}
                            onOpenChange={setStatusFilterOpen}
                            toggle={(toggleRef) => (
                                <MenuToggle
                                    ref={toggleRef}
                                    onClick={() => setStatusFilterOpen(prev => !prev)}
                                    isExpanded={statusFilterOpen}
                                >
                                    {statusLabels[statusFilter]}
                                </MenuToggle>
                            )}
                        >
                            <SelectList>
                                <SelectOption value="all">{statusLabels.all}</SelectOption>
                                <SelectOption value="pass">{statusLabels.pass}</SelectOption>
                                <SelectOption value="fail">{statusLabels.fail}</SelectOption>
                                <SelectOption value="error">{statusLabels.error}</SelectOption>
                                <SelectOption value="other">{statusLabels.other}</SelectOption>
                            </SelectList>
                        </Select>
                    </ToolbarItem>
                    <ToolbarItem>
                        <Select
                            isOpen={severityFilterOpen}
                            selected={severityFilter}
                            onSelect={(_event, value) => {
                                setSeverityFilter(value as SeverityFilter);
                                setSeverityFilterOpen(false);
                            }}
                            onOpenChange={setSeverityFilterOpen}
                            toggle={(toggleRef) => (
                                <MenuToggle
                                    ref={toggleRef}
                                    onClick={() => setSeverityFilterOpen(prev => !prev)}
                                    isExpanded={severityFilterOpen}
                                >
                                    {severityLabels[severityFilter]}
                                </MenuToggle>
                            )}
                        >
                            <SelectList>
                                <SelectOption value="all">{severityLabels.all}</SelectOption>
                                <SelectOption value="high">{severityLabels.high}</SelectOption>
                                <SelectOption value="medium">{severityLabels.medium}</SelectOption>
                                <SelectOption value="low">{severityLabels.low}</SelectOption>
                                <SelectOption value="unknown">{severityLabels.unknown}</SelectOption>
                            </SelectList>
                        </Select>
                    </ToolbarItem>
                    <ToolbarItem>
                        <Content component={ContentVariants.small}>
                            {cockpit.format(_("$0 of $1 rules"), filtered.length, scanResult.results.length)}
                        </Content>
                    </ToolbarItem>
                </ToolbarContent>
            </Toolbar>

            {/* Rules table */}
            {filtered.length === 0
                ? (
                    <Card>
                        <CardBody>
                            <Content component={ContentVariants.p}>
                                {_("No rules match the current filters.")}
                            </Content>
                        </CardBody>
                    </Card>
                )
                : (
                    <Card>
                        <CardBody>
                            <Table aria-label={_("Rule evaluation results")} variant="compact">
                                <Thead>
                                    <Tr>
                                        <Th>{_("Status")}</Th>
                                        <Th>{_("Rule Title")}</Th>
                                        <Th>{_("Severity")}</Th>
                                        <Th>{_("Subsystem")}</Th>
                                        <Th screenReaderText={_("Expand")} />
                                    </Tr>
                                </Thead>
                                <Tbody>
                                    {filtered.map((rule, rowIndex) => {
                                        const isExpanded = expandedRows.has(rule.rule_id);

                                        return (
                                            <React.Fragment key={rule.rule_id}>
                                                <Tr>
                                                    <Td dataLabel={_("Status")}>
                                                        {statusIcon(rule.result)}
                                                    </Td>
                                                    <Td dataLabel={_("Rule Title")}>
                                                        {rule.title}
                                                    </Td>
                                                    <Td dataLabel={_("Severity")}>
                                                        <Label color={severityColor(rule.severity)} isCompact>
                                                            {rule.severity}
                                                        </Label>
                                                    </Td>
                                                    <Td dataLabel={_("Subsystem")}>
                                                        {deriveSubsystem(rule.rule_id)}
                                                    </Td>
                                                    <Td
                                                        expand={{
                                                            rowIndex,
                                                            isExpanded,
                                                            onToggle: () => toggleExpand(rule.rule_id),
                                                            expandId: `expand-${rule.rule_id}`,
                                                        }}
                                                    />
                                                </Tr>
                                                {isExpanded && (
                                                    <Tr isExpanded>
                                                        <Td colSpan={5}>
                                                            <ExpandableRowContent>
                                                                <div style={{ paddingLeft: "var(--pf-t--global--spacer--md)" }}>
                                                                    <Content component={ContentVariants.p}>
                                                                        <strong>{_("Rule ID:")}</strong>{" "}
                                                                        <code style={{ fontSize: "0.85em", wordBreak: "break-all" }}>
                                                                            {rule.rule_id}
                                                                        </code>
                                                                    </Content>
                                                                    <Content component={ContentVariants.small}>
                                                                        {cockpit.format(
                                                                            _("Result: $0 | Severity: $1"),
                                                                            rule.result,
                                                                            rule.severity,
                                                                        )}
                                                                    </Content>
                                                                </div>
                                                            </ExpandableRowContent>
                                                        </Td>
                                                    </Tr>
                                                )}
                                            </React.Fragment>
                                        );
                                    })}
                                </Tbody>
                            </Table>
                        </CardBody>
                    </Card>
                )}
        </PageSection>
    );
};
