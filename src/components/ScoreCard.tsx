import React from "react";
import { Card, CardBody, CardTitle } from "@patternfly/react-core/dist/esm/components/Card/index.js";
import { Content, ContentVariants } from "@patternfly/react-core/dist/esm/components/Content/index.js";

interface ScoreCardProps {
    label: string;
    value: string;
    subtext?: string | undefined;
}

export const ScoreCard: React.FunctionComponent<ScoreCardProps> = ({ label, value, subtext }) => {
    return (
        <Card isCompact>
            <CardTitle>{label}</CardTitle>
            <CardBody>
                <Content component={ContentVariants.p}>
                    <strong>{value}</strong>
                </Content>
                {subtext && (
                    <Content component={ContentVariants.small}>{subtext}</Content>
                )}
            </CardBody>
        </Card>
    );
};
