import React from "react";
import { Label } from "@patternfly/react-core/dist/esm/components/Label/index.js";
import type { RiskLevel } from "../types";

const RISK_COLORS: Record<RiskLevel, "green" | "orange" | "red"> = {
    low: "green",
    medium: "orange",
    high: "red",
    critical: "red",
};

interface RiskBadgeProps {
    level: RiskLevel;
}

export const RiskBadge: React.FunctionComponent<RiskBadgeProps> = ({ level }) => {
    return (
        <Label color={RISK_COLORS[level]} isCompact>
            {level}
        </Label>
    );
};
