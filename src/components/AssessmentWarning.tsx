/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

import React from "react";
import { Alert } from "@patternfly/react-core/dist/esm/components/Alert/index.js";

import { assessmentLabel, assessmentMessage, hasAssessment } from "../helpers";
import type { ResultCounts } from "../types";

/** Completing the scanner process does not guarantee that its content evaluated this host. */
export const AssessmentWarning = ({ counts }: { counts: ResultCounts }) => hasAssessment(counts)
    ? null
    : (
        <Alert component="h2" variant="warning" isInline title={assessmentLabel(counts)}>
            {assessmentMessage(counts)}
        </Alert>
    );
