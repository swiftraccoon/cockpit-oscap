/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Loading, error and "not installed" states.
 */

import React from "react";
import { Alert, AlertActionCloseButton, AlertActionLink } from "@patternfly/react-core/dist/esm/components/Alert/index.js";
import { Button } from "@patternfly/react-core/dist/esm/components/Button/index.js";
import { ClipboardCopy } from "@patternfly/react-core/dist/esm/components/ClipboardCopy/index.js";
import { Content } from "@patternfly/react-core/dist/esm/components/Content/index.js";
import { PageSection } from "@patternfly/react-core/dist/esm/components/Page/index.js";
import { Stack, StackItem } from "@patternfly/react-core/dist/esm/layouts/Stack/index.js";
import ExclamationCircleIcon from "@patternfly/react-icons/dist/esm/icons/exclamation-circle-icon";
import ShieldAltIcon from "@patternfly/react-icons/dist/esm/icons/shield-alt-icon";
import cockpit from "cockpit";

import { EmptyStatePanel } from "cockpit-components-empty-state";
import { get_manifest_config_matchlist } from "utils";

import type { BackendInfo } from "../types";

const _ = cockpit.gettext;

export const Loading = ({ title }: { title?: string }) => (
    <EmptyStatePanel loading title={title ?? _("Loading…")} />
);

export const ErrorAlert = ({ title, error, onRetry, onDismiss }: {
    title: string;
    error: string | null;
    onRetry?: () => void;
    onDismiss?: () => void;
}) => (
    <Alert
        variant="danger"
        isInline
        title={title}
        {...onDismiss && { actionClose: <AlertActionCloseButton onClose={onDismiss} /> }}
        {...onRetry && { actionLinks: <AlertActionLink onClick={onRetry}>{_("Try again")}</AlertActionLink> }}
    >
        {error && <p className="oscap-prose">{error}</p>}
    </Alert>
);

/** Full-page error, used when a page cannot load at all. */
export const ErrorState = ({ title, error, onRetry }: { title: string; error: string | null; onRetry?: () => void }) => (
    <EmptyStatePanel
        icon={ExclamationCircleIcon}
        title={title}
        paragraph={error}
        {...onRetry && { action: _("Try again"), onAction: onRetry, actionVariant: "secondary" }}
    />
);

/** The distribution's install command for OpenSCAP and SCAP Security Guide, from manifest.json. */
export function installCommand(osId: string): string | null {
    const hint = get_manifest_config_matchlist("oscap", "install-hints", null, [osId]);
    return typeof hint === "string" ? hint : null;
}

/** Shown when oscap or the SCAP Security Guide content is missing. */
export const SetupNeeded = ({ backend, onRetry }: { backend: BackendInfo; onRetry: () => void }) => {
    const command = installCommand(backend.content.os.id);
    const oscapMissing = backend.oscap === null;
    const title = oscapMissing ? _("OpenSCAP is not installed") : _("No SCAP content found");
    const paragraph = oscapMissing
        ? _("Install the OpenSCAP scanner and the SCAP Security Guide to evaluate this system against security profiles.")
        : cockpit.format(
            _("OpenSCAP $0 is installed, but no SCAP Security Guide datastream was found in $1. Install the SCAP Security Guide content for this system to start scanning."),
            backend.oscap?.version ?? "", "/usr/share/xml/scap/ssg/content");

    return (
        <PageSection hasBodyWrapper={false} isFilled>
            <EmptyStatePanel
                icon={ShieldAltIcon}
                title={title}
                paragraph={
                    <Stack hasGutter className="oscap-empty-hint">
                        <StackItem>{paragraph}</StackItem>
                        {command && (
                            <StackItem>
                                <ClipboardCopy isReadOnly hoverTip={_("Copy")} clickTip={_("Copied")}>
                                    {command}
                                </ClipboardCopy>
                            </StackItem>
                        )}
                        {!command && (
                            <StackItem>
                                <Content component="small">
                                    {_("The packages are usually named openscap-scanner and scap-security-guide.")}
                                </Content>
                            </StackItem>
                        )}
                    </Stack>
                }
                action={<Button variant="secondary" onClick={onRetry}>{_("Check again")}</Button>}
            />
        </PageSection>
    );
};

export const LimitedAccessAlert = () => (
    <Alert variant="warning" isInline isPlain title={_("Limited access")}>
        {_("Running scans, applying remediation and changing settings require administrative access.")}
    </Alert>
);
