/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * The "Run compliance scan" dialog: choose a profile, watch live progress,
 * then jump to the results.
 */

import React, { useEffect, useRef, useState } from "react";
import { Alert } from "@patternfly/react-core/dist/esm/components/Alert/index.js";
import { Button } from "@patternfly/react-core/dist/esm/components/Button/index.js";
import { Checkbox } from "@patternfly/react-core/dist/esm/components/Checkbox/index.js";
import { Content } from "@patternfly/react-core/dist/esm/components/Content/index.js";
import { Form, FormGroup } from "@patternfly/react-core/dist/esm/components/Form/index.js";
import { Modal, ModalBody, ModalFooter, ModalHeader } from "@patternfly/react-core/dist/esm/components/Modal/index.js";
import { Progress } from "@patternfly/react-core/dist/esm/components/Progress/index.js";
import { Stack, StackItem } from "@patternfly/react-core/dist/esm/layouts/Stack/index.js";
import cockpit from "cockpit";

import { FormHelper } from "cockpit-components-form-helper";
import { SimpleSelect } from "cockpit-components-simple-select";
import { useDialogs } from "dialogs";

import { getConfig, listProfiles, scan } from "../api";
import type { StreamHandle } from "../api";
import { useAsync } from "../app-hooks";
import { errorMessage, ruleShortName } from "../helpers";
import type { ProfileInfo, ScanProgress, ScanResult } from "../types";
import { CountLabels, ScoreValue } from "./labels";
import { ErrorAlert, Loading } from "./states";

const _ = cockpit.gettext;

type Phase = "setup" | "running" | "done" | "error";

export const ScanDialog = ({ initialProfileId, onFinished }: {
    initialProfileId?: string;
    onFinished?: (result: ScanResult) => void;
}) => {
    const Dialogs = useDialogs();
    const setup = useAsync(async () => {
        const [profiles, config] = await Promise.all([listProfiles(), getConfig()]);
        return { profiles, config };
    }, []);

    const [phase, setPhase] = useState<Phase>("setup");
    const [profileId, setProfileId] = useState(initialProfileId ?? "");
    const [useTailoring, setUseTailoring] = useState(true);
    const [progress, setProgress] = useState<ScanProgress | null>(null);
    const [result, setResult] = useState<ScanResult | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [cancelled, setCancelled] = useState(false);
    const handle = useRef<StreamHandle<ScanResult> | null>(null);

    // Default to the active profile once the profile list is known
    useEffect(() => {
        if (!setup.data || profileId)
            return;
        const active = setup.data.config.active_profile;
        const first = setup.data.profiles[0]?.id ?? "";
        setProfileId(active && setup.data.profiles.some(p => p.id === active) ? active : first);
    }, [setup.data, profileId]);

    const profiles: ProfileInfo[] = setup.data?.profiles ?? [];
    const profile = profiles.find(p => p.id === profileId);

    function start() {
        setPhase("running");
        setProgress(null);
        setError(null);
        setCancelled(false);
        handle.current = scan({ profileId, noTailoring: !useTailoring }, setProgress);
        handle.current.promise
                .then(scanResult => {
                    setResult(scanResult);
                    setPhase("done");
                    onFinished?.(scanResult);
                })
                .catch((err: unknown) => {
                    setCancelled(err instanceof Error && "cancelled" in err && Boolean(err.cancelled));
                    setError(errorMessage(err));
                    setPhase("error");
                })
                .finally(() => { handle.current = null });
    }

    function cancel() {
        handle.current?.cancel();
    }

    function close() {
        if (phase === "running")
            return;
        Dialogs.close();
    }

    function viewResults() {
        if (result)
            cockpit.location.go(["results", result.id]);
        Dialogs.close();
    }

    let body: React.ReactNode;
    let footer: React.ReactNode;

    if (phase === "setup") {
        body = setup.loading
            ? <Loading />
            : setup.error
                ? <ErrorAlert title={_("Failed to load profiles")} error={setup.error} onRetry={() => setup.reload()} />
                : (
                    <Form isHorizontal onSubmit={ev => { ev.preventDefault(); start() }}>
                        <FormGroup label={_("Profile")} fieldId="scan-profile" isRequired>
                            <SimpleSelect
                                toggleProps={{ id: "scan-profile", isFullWidth: true }}
                                options={profiles.map(p => ({
                                    value: p.id,
                                    content: p.title,
                                    description: cockpit.format(cockpit.ngettext("$0 rule", "$0 rules", p.rule_count),
                                                                p.rule_count),
                                }))}
                                selected={profileId}
                                onSelect={value => setProfileId(value)}
                                placeholder={_("Select a profile")}
                            />
                            <FormHelper helperText={profile?.description} />
                        </FormGroup>
                        {profile?.tailored_profile_id && (
                            <FormGroup fieldId="scan-tailoring">
                                <Checkbox
                                    id="scan-tailoring"
                                    label={_("Apply saved customizations")}
                                    description={_("Use the tailoring file created in the profile editor instead of the profile defaults.")}
                                    isChecked={useTailoring}
                                    onChange={(_ev, checked) => setUseTailoring(checked)}
                                />
                            </FormGroup>
                        )}
                    </Form>
                );
        footer = (
            <>
                <Button id="scan-start" variant="primary" onClick={start} isDisabled={!profileId || setup.loading}>
                    {_("Start scan")}
                </Button>
                <Button variant="link" onClick={close}>{_("Cancel")}</Button>
            </>
        );
    } else if (phase === "running") {
        const title = progress
            ? cockpit.format(_("Evaluating rule $0 of $1"), progress.current, progress.total)
            : _("Starting scan…");
        body = (
            <Stack hasGutter>
                <StackItem>
                    <Progress
                        id="scan-progress"
                        value={progress?.progress ?? 0}
                        title={title}
                        measureLocation="outside"
                    />
                </StackItem>
                {progress?.rule_id && (
                    <StackItem>
                        <Content component="small" className="oscap-mono">{ruleShortName(progress.rule_id)}</Content>
                    </StackItem>
                )}
                <StackItem>
                    <Content component="small">
                        {_("Scanning can take several minutes. Leaving the Compliance page cancels the scan.")}
                    </Content>
                </StackItem>
            </Stack>
        );
        footer = <Button variant="secondary" onClick={cancel}>{_("Cancel scan")}</Button>;
    } else if (phase === "done" && result) {
        body = (
            <Stack hasGutter>
                <StackItem>
                    <Alert component="h2" variant="success" isInline title={_("Scan complete")}>
                        {result.profile_title}
                    </Alert>
                </StackItem>
                <StackItem>
                    <div className="oscap-inline-list" style={{ gap: "var(--pf-t--global--spacer--lg)" }}>
                        <ScoreValue score={result.score} />
                        <CountLabels counts={result.counts} />
                    </div>
                </StackItem>
            </Stack>
        );
        footer = (
            <>
                <Button id="scan-view-results" variant="primary" onClick={viewResults}>{_("View results")}</Button>
                <Button variant="link" onClick={close}>{_("Close")}</Button>
            </>
        );
    } else {
        body = cancelled
            ? <Alert component="h2" variant="info" isInline title={_("The scan was cancelled")} />
            : <ErrorAlert title={_("Scan failed")} error={error} />;
        footer = (
            <>
                <Button variant="primary" onClick={() => setPhase("setup")}>{_("Back")}</Button>
                <Button variant="link" onClick={close}>{_("Close")}</Button>
            </>
        );
    }

    return (
        <Modal
            id="scan-dialog"
            isOpen
            variant="medium"
            position="top"
            {...phase !== "running" && { onClose: close }}
        >
            <ModalHeader
                title={_("Run compliance scan")}
                description={phase === "setup"
                    ? _("Evaluate this system against a security profile. Scanning reads system state and does not change anything.")
                    : undefined}
            />
            <ModalBody>{body}</ModalBody>
            <ModalFooter>{footer}</ModalFooter>
        </Modal>
    );
};
