/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Expanded details for a rule: description, rationale, references and
 * identifiers, loaded on demand from the datastream and cached.
 */

import React, { useState } from "react";
import { Alert } from "@patternfly/react-core/dist/esm/components/Alert/index.js";
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
import cockpit from "cockpit";

import { ruleInfo } from "../api";
import { useAsync } from "../app-hooks";
import { referenceSource } from "../helpers";
import type { Reference, RuleDetail } from "../types";

const _ = cockpit.gettext;

const cache = new Map<string, Promise<RuleDetail>>();

function loadRule(ruleId: string): Promise<RuleDetail> {
    let pending = cache.get(ruleId);
    if (!pending) {
        pending = ruleInfo(ruleId);
        cache.set(ruleId, pending);
        pending.catch(() => cache.delete(ruleId));
    }
    return pending;
}

const FIX_SYSTEM_NAMES: Record<string, string> = {
    "urn:xccdf:fix:script:sh": "Bash",
    "urn:xccdf:fix:script:ansible": "Ansible",
    "urn:xccdf:fix:script:puppet": "Puppet",
    "urn:xccdf:fix:script:kubernetes": "Kubernetes",
    "urn:redhat:anaconda:pre": "Anaconda",
    "urn:xccdf:fix:script:ignition": "Ignition",
    "urn:xccdf:fix:script:blueprint": "Image builder blueprint",
};

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

export const RuleDetails = ({ ruleId, message, description }: {
    ruleId: string;
    /** A message recorded by the scanner for this rule (typically for errors). */
    message?: string;
    /** Already-known description, shown while the full details load. */
    description?: string;
}) => {
    const { data, error, loading } = useAsync(() => loadRule(ruleId), [ruleId]);

    return (
        <div className="oscap-expanded-details">
            {message && <Alert variant="warning" isInline isPlain title={_("Scanner message")}>{message}</Alert>}
            {error && (
                <Alert variant="danger" isInline isPlain title={_("Rule details are unavailable")}>{error}</Alert>
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
                            {data.fix_systems.length > 0
                                ? data.fix_systems.map(system => FIX_SYSTEM_NAMES[system] ?? system).join(", ")
                                : _("No automated remediation available")}
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
