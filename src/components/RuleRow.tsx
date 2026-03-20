import React, { useState } from "react";
import { ExpandableSection } from "@patternfly/react-core/dist/esm/components/ExpandableSection/index.js";
import { Label } from "@patternfly/react-core/dist/esm/components/Label/index.js";
import { Switch } from "@patternfly/react-core/dist/esm/components/Switch/index.js";
import { Flex, FlexItem } from "@patternfly/react-core/dist/esm/layouts/Flex/index.js";
import cockpit from "cockpit";

import type { RuleInfo } from "../types";

const _ = cockpit.gettext;

/** Map severity strings to PatternFly Label colors. */
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

interface RuleRowProps {
    rule: RuleInfo;
    modified: boolean;
    onToggle: (ruleId: string, enabled: boolean) => void;
}

export const RuleRow: React.FunctionComponent<RuleRowProps> = ({ rule, modified, onToggle }) => {
    const [expanded, setExpanded] = useState(false);

    const toggleContent = (
        <Flex
            alignItems={{ default: "alignItemsCenter" }}
            spaceItems={{ default: "spaceItemsSm" }}
            flexWrap={{ default: "nowrap" }}
            style={{ width: "100%" }}
        >
            <FlexItem
                onClick={(e: React.MouseEvent) => e.stopPropagation()}
                style={{ flexShrink: 0 }}
            >
                <Switch
                    id={`rule-switch-${rule.id}`}
                    aria-label={cockpit.format(_("Toggle rule $0"), rule.title)}
                    isChecked={rule.selected}
                    onChange={(_event, checked) => onToggle(rule.id, checked)}
                />
            </FlexItem>
            <FlexItem grow={{ default: "grow" }}>
                {rule.title}
            </FlexItem>
            <FlexItem style={{ flexShrink: 0 }}>
                <Label color={severityColor(rule.severity)} isCompact>
                    {rule.severity}
                </Label>
            </FlexItem>
            {modified && (
                <FlexItem style={{ flexShrink: 0 }}>
                    <Label color="purple" isCompact>{_("modified")}</Label>
                </FlexItem>
            )}
        </Flex>
    );

    return (
        <div
            style={{
                padding: "var(--pf-t--global--spacer--xs) 0",
                ...(modified
                    ? { backgroundColor: "var(--pf-t--global--color--nonstatus--purple--100, #f2e6ff)" }
                    : {}),
            }}
        >
            <ExpandableSection
                toggleContent={toggleContent}
                isExpanded={expanded}
                onToggle={(_event, isExpanded) => setExpanded(isExpanded)}
                isIndented
            >
                <div style={{ paddingLeft: "var(--pf-t--global--spacer--lg)" }}>
                    {rule.description || _("No description available.")}
                    <br />
                    <code style={{ fontSize: "0.85em", wordBreak: "break-all" }}>{rule.id}</code>
                </div>
            </ExpandableSection>
        </div>
    );
};
