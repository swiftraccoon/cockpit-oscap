/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Small presentational components shared by all pages.
 */

import React from "react";
import { Label } from "@patternfly/react-core/dist/esm/components/Label/index.js";
import { Tooltip } from "@patternfly/react-core/dist/esm/components/Tooltip/index.js";
import MinusCircleIcon from "@patternfly/react-icons/dist/esm/icons/minus-circle-icon";
import PencilAltIcon from "@patternfly/react-icons/dist/esm/icons/pencil-alt-icon";
import cockpit from "cockpit";

import * as timeformat from "timeformat";

import {
    SEVERITIES,
    formatScore,
    normalizeResult,
    normalizeSeverity,
    parseTimestamp,
    resultLabel,
    scoreVariant,
    severityLabel,
} from "../helpers";
import type { RuleChange } from "../helpers";
import type { ResultCounts, Severity } from "../types";

const _ = cockpit.gettext;

type LabelColor = "blue" | "teal" | "green" | "orange" | "purple" | "red" | "orangered" | "grey" | "yellow";

/** An absolute timestamp with its relative distance, or a fallback when unset. */
export const When = ({ iso, fallback }: { iso: string; fallback: string }) => {
    const date = parseTimestamp(iso);
    if (!date)
        return <span>{fallback}</span>;
    return (
        <span>
            {timeformat.dateTime(date)}
            <span className="oscap-muted">{" · "}{timeformat.distanceToNow(date)}</span>
        </span>
    );
};

/** How a rule's result moved since the previous scan. */
export const ChangeLabel = ({ change, before }: { change: RuleChange; before?: string | undefined }) => {
    const title = before ? cockpit.format(_("Previously: $0"), resultLabel(before)) : "";
    switch (change) {
    case "fixed":
        return <Label status="success" variant="outline" isCompact title={title}>{_("Now passing")}</Label>;
    case "regressed":
        return <Label status="danger" variant="outline" isCompact title={title}>{_("New failure")}</Label>;
    default:
        return <Label color="purple" variant="outline" isCompact title={title}>{_("Changed")}</Label>;
    }
};

/** Result of evaluating a single rule (pass, fail, error, ...). */
export const ResultLabel = ({ result, isCompact = true }: { result: string; isCompact?: boolean }) => {
    const text = resultLabel(result);
    switch (normalizeResult(result)) {
    case "pass":
    case "fixed":
        return <Label status="success" isCompact={isCompact}>{text}</Label>;
    case "fail":
        return <Label status="danger" isCompact={isCompact}>{text}</Label>;
    case "error":
        return <Label status="warning" isCompact={isCompact}>{text}</Label>;
    case "informational":
        return <Label status="info" isCompact={isCompact}>{text}</Label>;
    default:
        return <Label color="grey" icon={<MinusCircleIcon />} isCompact={isCompact}>{text}</Label>;
    }
};

const SEVERITY_COLORS: Record<Severity, LabelColor> = {
    high: "red",
    medium: "orange",
    low: "blue",
    unknown: "grey",
};

export const SeverityLabel = ({ severity, isCompact = true }: { severity: string; isCompact?: boolean }) => (
    <Label color={SEVERITY_COLORS[normalizeSeverity(severity)]} isCompact={isCompact} variant="outline">
        {severityLabel(severity)}
    </Label>
);

const RISK_COLORS: Record<string, LabelColor> = { low: "green", medium: "orange", high: "red" };

function riskText(level: string): string {
    switch (level) {
    case "high":
        return _("High risk");
    case "medium":
        return _("Medium risk");
    case "low":
        return _("Low risk");
    default:
        return level;
    }
}

const SEVERITY_COUNT_FORMATS: Record<Severity, string> = {
    high: _("$0 high"),
    medium: _("$0 medium"),
    low: _("$0 low"),
    unknown: _("$0 unknown"),
};

/** How many of the given rules fall in each severity, highest first (empty severities are omitted). */
export const SeverityCounts = ({ rules }: { rules: { severity: string }[] }) => {
    const counts = new Map<Severity, number>();
    for (const rule of rules) {
        const severity = normalizeSeverity(rule.severity);
        counts.set(severity, (counts.get(severity) ?? 0) + 1);
    }
    return (
        <span className="oscap-inline-list">
            {SEVERITIES.filter(severity => counts.has(severity)).map(severity => (
                <Label key={severity} color={SEVERITY_COLORS[severity]} variant="outline" isCompact>
                    {cockpit.format(SEVERITY_COUNT_FORMATS[severity], counts.get(severity))}
                </Label>
            ))}
        </span>
    );
};

/** Risk of applying an automated fix, with the reason as a tooltip. */
export const RiskLabel = ({ level, reason }: { level: string; reason?: string }) => {
    const label = <Label color={RISK_COLORS[level] ?? "grey"} isCompact>{riskText(level)}</Label>;
    return reason ? <Tooltip content={reason}>{label}</Tooltip> : label;
};

/** A compliance score, colored by threshold. */
export const ScoreValue = ({ score, size = "lg" }: { score: number; size?: "lg" | "md" }) => (
    <span className={`oscap-score oscap-score-${size} oscap-score-${scoreVariant(score)}`}>
        {formatScore(score)}
    </span>
);

const SCORE_LABEL_COLORS: Record<string, LabelColor> = { success: "green", warning: "orange", danger: "red" };

export const ScoreLabel = ({ score }: { score: number }) => (
    <Label color={SCORE_LABEL_COLORS[scoreVariant(score)]} isCompact>{formatScore(score)}</Label>
);

export const ScanStatusLabel = ({ status }: { status: string }) => {
    switch (status) {
    case "complete":
        return <Label status="success" isCompact>{_("Complete")}</Label>;
    case "interrupted":
        return <Label status="warning" isCompact>{_("Interrupted")}</Label>;
    case "failed":
        return <Label status="danger" isCompact>{_("Failed")}</Label>;
    default:
        return <Label color="grey" isCompact>{status}</Label>;
    }
};

export const TailoredLabel = () => (
    <Tooltip content={_("This profile has saved customizations (a tailoring file)")}>
        <Label color="purple" icon={<PencilAltIcon />} isCompact>{_("Customized")}</Label>
    </Tooltip>
);

/** Pass / fail / error counts as a row of labels. */
export const CountLabels = ({ counts }: { counts: ResultCounts }) => (
    <span className="oscap-inline-list">
        <Tooltip content={cockpit.format(cockpit.ngettext("$0 rule passed", "$0 rules passed", counts.pass), counts.pass)}>
            <Label status="success" isCompact>{counts.pass}</Label>
        </Tooltip>
        <Tooltip content={cockpit.format(cockpit.ngettext("$0 rule failed", "$0 rules failed", counts.fail), counts.fail)}>
            <Label status="danger" isCompact>{counts.fail}</Label>
        </Tooltip>
        <Tooltip content={cockpit.format(cockpit.ngettext("$0 rule had an error", "$0 rules had errors", counts.error),
                                         counts.error)}
        >
            <Label status="warning" isCompact>{counts.error}</Label>
        </Tooltip>
    </span>
);

/** A "label: value" stat block used in summary cards. */
export const Stat = ({ label, children }: { label: string; children: React.ReactNode }) => (
    <div className="oscap-stat">
        <span className="oscap-stat-label">{label}</span>
        <span className="oscap-stat-value">{children}</span>
    </div>
);
