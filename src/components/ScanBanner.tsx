/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * A banner shown on every page while a scan runs (interactive or scheduled),
 * driven by the scan-state.json file the bridge keeps up to date.
 */

import React from "react";
import { Alert } from "@patternfly/react-core/dist/esm/components/Alert/index.js";
import { PageSection } from "@patternfly/react-core/dist/esm/components/Page/index.js";
import { Progress } from "@patternfly/react-core/dist/esm/components/Progress/index.js";
import { Spinner } from "@patternfly/react-core/dist/esm/components/Spinner/index.js";
import cockpit from "cockpit";

import { useDialogs } from "dialogs";

import { useScanState } from "../app-hooks";
import { ScanEta } from "./ScanEta";

const _ = cockpit.gettext;

export const ScanBanner = () => {
    const state = useScanState();
    const Dialogs = useDialogs();

    // While a dialog is open the scan (or remediation re-scan) shows its own progress.
    if (!state?.running || Dialogs.isActive())
        return null;

    const total = state.total ?? 0;
    const current = state.current ?? 0;
    const title = state.source === "scheduled"
        ? cockpit.format(_("Scheduled compliance scan in progress: $0"), state.profile_title ?? state.profile_id ?? "")
        : cockpit.format(_("Compliance scan in progress: $0"), state.profile_title ?? state.profile_id ?? "");

    return (
        <PageSection hasBodyWrapper={false} className="oscap-banner-section">
            <Alert component="h2" id="scan-banner" variant="info" isInline title={title} customIcon={<Spinner size="md" />}>
                <Progress
                    value={state.progress ?? 0}
                    size="sm"
                    measureLocation="outside"
                    title={total > 0 ? cockpit.format(_("Rule $0 of $1"), current, total) : _("Starting…")}
                />
                <ScanEta scanKey={state.started ?? ""} progress={state.progress ?? 0} />
            </Alert>
        </PageSection>
    );
};
