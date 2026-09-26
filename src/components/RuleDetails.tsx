/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Expanded details for a rule: description, rationale, references and
 * identifiers, loaded on demand from the datastream and cached.
 */

import React, { useState } from "react";
import { Alert } from "@patternfly/react-core/dist/esm/components/Alert/index.js";
import { Button } from "@patternfly/react-core/dist/esm/components/Button/index.js";
import { ClipboardCopy } from "@patternfly/react-core/dist/esm/components/ClipboardCopy/index.js";
import {
    DescriptionList,
    DescriptionListDescription,
    DescriptionListGroup,
    DescriptionListTerm,
} from "@patternfly/react-core/dist/esm/components/DescriptionList/index.js";
import { ExpandableSection } from "@patternfly/react-core/dist/esm/components/ExpandableSection/index.js";
import { Label } from "@patternfly/react-core/dist/esm/components/Label/index.js";
import { Spinner } from "@patternfly/react-core/dist/esm/components/Spinner/index.js";
import { Tooltip } from "@patternfly/react-core/dist/esm/components/Tooltip/index.js";
import cockpit from "cockpit";

import * as timeformat from "timeformat";

import { ruleHistory, ruleInfo } from "../api";
import { useAsync } from "../app-hooks";
import { countHistory, normalizeResult, parseTimestamp, referenceSource, resultLabel } from "../helpers";
import type { Reference, RuleDetail, RuleHistoryPoint } from "../types";

const _ = cockpit.gettext;

const cache = new Map<string, Promise<RuleDetail>>();

function loadRule(ruleId: string, datastream: string | undefined): Promise<RuleDetail> {
    const key = `${datastream ?? ""}\n${ruleId}`;
    let pending = cache.get(key);
    if (!pending) {
        pending = ruleInfo(ruleId, datastream);
        cache.set(key, pending);
        pending.catch(() => cache.delete(key));
    }
    return pending;
}

/** Known fix systems, in the order they are listed (the ones this plugin can apply or export first). */
const FIX_SYSTEM_NAMES: Record<string, string> = {
    "urn:xccdf:fix:script:sh": "Bash",
    "urn:xccdf:fix:script:ansible": "Ansible",
    "urn:xccdf:fix:script:puppet": "Puppet",
    "urn:xccdf:fix:script:kubernetes": "Kubernetes",
    "urn:redhat:anaconda:pre": "Anaconda",
    "urn:xccdf:fix:script:ignition": "Ignition",
    "urn:redhat:osbuild:blueprint": "Image builder blueprint",
    "urn:xccdf:fix:script:blueprint": "Image builder blueprint",
};
const FIX_SYSTEM_ORDER = Object.keys(FIX_SYSTEM_NAMES);

function fixSystemNames(systems: string[]): string {
    const rank = (system: string) => {
        const index = FIX_SYSTEM_ORDER.indexOf(system);
        return index === -1 ? FIX_SYSTEM_ORDER.length : index;
    };
    return Array.from(new Set([...systems].sort((a, b) => rank(a) - rank(b)).map(s => FIX_SYSTEM_NAMES[s] ?? s))).join(", ");
}

function groupReferences(references: Reference[]): [string, string[]][] {
    const groups = new Map<string, string[]>();
    for (const ref of references) {
        const source = referenceSource(ref.href);
        const list = groups.get(source) ?? [];
        if (!list.includes(ref.text))
            list.push(ref.text);
        groups.set(source, list);
    }
    return Array.from(groups.entries());
}

const References = ({ references }: { references: Reference[] }) => {
    const [expanded, setExpanded] = useState(false);
    const groups = groupReferences(references);
    const toggle = expanded
        ? _("Hide references")
        : cockpit.format(cockpit.ngettext("Show $0 reference", "Show $0 references", references.length),
                         references.length);
    return (
        <ExpandableSection
toggleText={toggle} isExpanded={expanded} onToggle={(_ev, value) => setExpanded(value)}
                           isIndented
        >
            <DescriptionList isCompact isHorizontal>
                {groups.map(([source, items]) => (
                    <DescriptionListGroup key={source}>
                        <DescriptionListTerm>{source}</DescriptionListTerm>
                        <DescriptionListDescription>{items.join(", ")}</DescriptionListDescription>
                    </DescriptionListGroup>
                ))}
            </DescriptionList>
        </ExpandableSection>
    );
};

/** How the rule fared in the profile's recent scans: one square per scan, oldest first, each a link. */
const RuleHistory = ({ ruleId, points, currentId }: { ruleId: string; points: RuleHistoryPoint[]; currentId: string }) => {
    const counts = countHistory(points);
    const ordered = [...points].reverse();
    return (
        <div className="oscap-history">
            <span className="oscap-history-strip" role="list" aria-label={_("Result per scan, oldest first")}>
                {ordered.map(point => {
                    const at = parseTimestamp(point.timestamp);
                    const label = cockpit.format("$0 · $1", at ? timeformat.dateTime(at) : point.timestamp, resultLabel(point.result));
                    const kind = normalizeResult(point.result);
                    return (
                        <Tooltip key={point.id} content={label}>
                            <a
                                role="listitem"
                                href={cockpit.location.encode(["results", point.id], { rule: ruleId })}
                                aria-label={label}
                                aria-current={point.id === currentId ? "true" : undefined}
                                className={`oscap-history-dot oscap-history-${kind}${point.id === currentId ? " oscap-history-current" : ""}`}
                            />
                        </Tooltip>
                    );
                })}
            </span>
            <span className="oscap-muted">
                {cockpit.format(_("Last $0 scans: $1 failed, $2 passed"),
                                points.length, counts.failed, counts.passed)}
                {counts.other > 0 && cockpit.format(_(", $0 other"), counts.other)}
            </span>
        </div>
    );
};

export const RuleDetails = ({
    ruleId, datastream, message, description, onRemediate, onExclude, excluded = false, history,
}: {
    ruleId: string;
    /** The SCAP content the rule belongs to (the one a result was scanned with); the configured one when unset. */
    datastream?: string | undefined;
    /** A message recorded by the scanner for this rule (typically for errors). */
    message?: string;
    /** Already-known description, shown while the full details load. */
    description?: string;
    /** Offered next to the remediation info when the rule ships an automated fix. */
    onRemediate?: () => void;
    /** Offered when the rule can be excluded from its profile's customization (with a justification). */
    onExclude?: () => void;
    /** The profile's customization already disables the rule (later scans skip it). */
    excluded?: boolean;
    /** Show how the rule fared in the profile's recent scans (on a result page). */
    history?: { baseProfileId: string; currentId: string };
}) => {
    // Callers mount this only for expanded rows, so the fetch happens on first expansion.
    const { data, error, loading } = useAsync(() => loadRule(ruleId, datastream), [ruleId, datastream]);
    const past = useAsync(
        () => (history ? ruleHistory(ruleId, history.baseProfileId) : Promise.resolve(null)),
        [ruleId, history?.baseProfileId]);

    return (
        <div className="oscap-expanded-details">
            {message && <Alert component="h2" variant="warning" isInline isPlain title={_("Scanner message")}>{message}</Alert>}
            {error && (
                <Alert component="h2" variant="danger" isInline isPlain title={_("Rule details are unavailable")}>{error}</Alert>
            )}
            {data?.content_substituted && (
                <Alert
                    component="h2" variant="info" isInline isPlain
                    title={_("Described from the currently installed content; the content this scan used is no longer installed.")}
                />
            )}
            <DescriptionList isCompact isHorizontal horizontalTermWidthModifier={{ default: "14ch" }}>
                <DescriptionListGroup>
                    <DescriptionListTerm>{_("Description")}</DescriptionListTerm>
                    <DescriptionListDescription>
                        <div className="oscap-prose">{data?.description || description || (loading ? "" : _("No description"))}</div>
                        {loading && !description && <Spinner size="md" aria-label={_("Loading rule details")} />}
                    </DescriptionListDescription>
                </DescriptionListGroup>
                {data?.rationale && (
                    <DescriptionListGroup>
                        <DescriptionListTerm>{_("Rationale")}</DescriptionListTerm>
                        <DescriptionListDescription><div className="oscap-prose">{data.rationale}</div></DescriptionListDescription>
                    </DescriptionListGroup>
                )}
                {data && data.warnings.length > 0 && (
                    <DescriptionListGroup>
                        <DescriptionListTerm>{_("Warnings")}</DescriptionListTerm>
                        <DescriptionListDescription>
                            {data.warnings.map((warning, index) => (
                                <div key={index} className="oscap-prose">{warning}</div>
                            ))}
                        </DescriptionListDescription>
                    </DescriptionListGroup>
                )}
                {data && data.group_path.length > 0 && (
                    <DescriptionListGroup>
                        <DescriptionListTerm>{_("Category")}</DescriptionListTerm>
                        <DescriptionListDescription>{data.group_path.join(" › ")}</DescriptionListDescription>
                    </DescriptionListGroup>
                )}
                {data && data.idents.length > 0 && (
                    <DescriptionListGroup>
                        <DescriptionListTerm>{_("Identifiers")}</DescriptionListTerm>
                        <DescriptionListDescription>
                            <span className="oscap-inline-list">
                                {data.idents.map(ident => (
                                    <Label key={ident.text} isCompact variant="outline">{ident.text}</Label>
                                ))}
                            </span>
                        </DescriptionListDescription>
                    </DescriptionListGroup>
                )}
                {data && (
                    <DescriptionListGroup>
                        <DescriptionListTerm>{_("Remediation")}</DescriptionListTerm>
                        <DescriptionListDescription>
                            <span className="oscap-inline-list">
                                {data.fix_systems.length > 0 ? fixSystemNames(data.fix_systems) : _("No automated remediation available")}
                                {data.has_fix && onRemediate && (
                                    <Button
id={`remediate-${ruleId}`} variant="secondary" size="sm"
                                            onClick={onRemediate}
                                    >
                                        {_("Remediate this rule")}
                                    </Button>
                                )}
                            </span>
                        </DescriptionListDescription>
                    </DescriptionListGroup>
                )}
                {history && past.data && past.data.length > 1 && (
                    <DescriptionListGroup>
                        <DescriptionListTerm>{_("History")}</DescriptionListTerm>
                        <DescriptionListDescription>
                            <RuleHistory ruleId={ruleId} points={past.data} currentId={history.currentId} />
                        </DescriptionListDescription>
                    </DescriptionListGroup>
                )}
                {(excluded || onExclude) && (
                    <DescriptionListGroup>
                        <DescriptionListTerm>{_("Customization")}</DescriptionListTerm>
                        <DescriptionListDescription>
                            {excluded
                                ? <span id={`excluded-${ruleId}`}>{_("Excluded from the profile; later scans skip this rule.")}</span>
                                : (
                                    <Button id={`exclude-${ruleId}`} variant="link" isInline onClick={onExclude}>
                                        {_("Exclude from profile…")}
                                    </Button>
                                )}
                        </DescriptionListDescription>
                    </DescriptionListGroup>
                )}
                {data && data.references.length > 0 && (
                    <DescriptionListGroup>
                        <DescriptionListTerm>{_("References")}</DescriptionListTerm>
                        <DescriptionListDescription><References references={data.references} /></DescriptionListDescription>
                    </DescriptionListGroup>
                )}
                <DescriptionListGroup>
                    <DescriptionListTerm>{_("Rule ID")}</DescriptionListTerm>
                    <DescriptionListDescription>
                        <ClipboardCopy
isReadOnly variant="inline-compact" hoverTip={_("Copy")} clickTip={_("Copied")}
                                       className="oscap-mono"
                        >
                            {ruleId}
                        </ClipboardCopy>
                    </DescriptionListDescription>
                </DescriptionListGroup>
            </DescriptionList>
        </div>
    );
};
