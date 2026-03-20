import React, { useEffect, useRef, useState } from "react";
import { Alert } from "@patternfly/react-core/dist/esm/components/Alert/index.js";
import { Button } from "@patternfly/react-core/dist/esm/components/Button/index.js";
import { Card, CardBody, CardTitle } from "@patternfly/react-core/dist/esm/components/Card/index.js";
import { Content, ContentVariants } from "@patternfly/react-core/dist/esm/components/Content/index.js";
import {
    EmptyState,
    EmptyStateBody,
} from "@patternfly/react-core/dist/esm/components/EmptyState/index.js";
import { MenuToggle } from "@patternfly/react-core/dist/esm/components/MenuToggle/index.js";
import { PageSection } from "@patternfly/react-core/dist/esm/components/Page/index.js";
import { Progress } from "@patternfly/react-core/dist/esm/components/Progress/index.js";
import { Select, SelectList, SelectOption } from "@patternfly/react-core/dist/esm/components/Select/index.js";
import { Spinner } from "@patternfly/react-core/dist/esm/components/Spinner/index.js";
import { Flex, FlexItem } from "@patternfly/react-core/dist/esm/layouts/Flex/index.js";
import cockpit from "cockpit";

import { listProfiles, loadConfig, manageTimer, scan } from "../api";
import type { Config, ProfileInfo, ScanResult } from "../types";

const _ = cockpit.gettext;

/** Possible states for the scan page lifecycle. */
type ScanState =
    | "loading"       // fetching profiles + config + timer status
    | "ready"         // idle, waiting for user action
    | "scanning"      // scan in progress
    | "success"       // scan completed successfully
    | "error"         // scan or init failed
    | "in-progress";  // scheduled scan already running

export const ScanPage: React.FunctionComponent = () => {
    const [scanState, setScanState] = useState<ScanState>("loading");
    const [profiles, setProfiles] = useState<ProfileInfo[]>([]);
    const [selectedProfile, setSelectedProfile] = useState<string>("");
    const [selectOpen, setSelectOpen] = useState(false);
    const [initError, setInitError] = useState<string | null>(null);
    const [scanError, setScanError] = useState<string | null>(null);
    const [scanResult, setScanResult] = useState<ScanResult | null>(null);

    const toggleRef = useRef<HTMLButtonElement>(null);

    /* ------------------------------------------------------------------ */
    /* Initialisation: load profiles, config, and check for running scan  */
    /* ------------------------------------------------------------------ */
    useEffect(() => {
        let cancelled = false;

        async function init() {
            try {
                const [profileList, configData, timerStatus] = await Promise.all([
                    listProfiles(),
                    loadConfig(),
                    manageTimer("status"),
                ]);
                if (cancelled) return;

                setProfiles(profileList);

                // Default to the active profile from config, or the first profile
                const activeId = pickDefault(configData, profileList);
                setSelectedProfile(activeId);

                // If the scan service is currently active, show in-progress state
                if (timerStatus.status === "activating" || timerStatus.status === "running") {
                    setScanState("in-progress");
                } else {
                    setScanState("ready");
                }
            } catch (err) {
                if (cancelled) return;
                setInitError(String(err));
                setScanState("error");
            }
        }

        init();
        return () => { cancelled = true };
    }, []);

    /* ------------------------------------------------------------------ */
    /* Helpers                                                             */
    /* ------------------------------------------------------------------ */

    /** Pick the best default profile id. */
    function pickDefault(config: Config, profileList: ProfileInfo[]): string {
        if (config.active_profile) {
            const match = profileList.find(p => p.id === config.active_profile);
            if (match) return match.id;
        }
        return profileList.length > 0 ? profileList[0].id : "";
    }

    /** Find the title for a profile id. */
    function profileTitle(id: string): string {
        const match = profiles.find(p => p.id === id);
        return match ? match.title : id;
    }

    /* ------------------------------------------------------------------ */
    /* Event handlers                                                     */
    /* ------------------------------------------------------------------ */

    function onSelectToggle() {
        setSelectOpen(prev => !prev);
    }

    function onSelectProfile(
        _event: React.MouseEvent<Element, MouseEvent> | undefined,
        value: string | number | undefined,
    ) {
        if (value !== undefined) {
            setSelectedProfile(String(value));
        }
        setSelectOpen(false);
    }

    async function onScanClick() {
        setScanState("scanning");
        setScanError(null);
        setScanResult(null);

        try {
            const result = await scan(selectedProfile);
            setScanResult(result);
            setScanState("success");
        } catch (err) {
            setScanError(String(err));
            setScanState("error");
        }
    }

    function onViewResults() {
        cockpit.location.go(["results"]);
    }

    /** Re-check timer status and transition to ready if scan finished. */
    async function onRefreshStatus() {
        try {
            const timerStatus = await manageTimer("status");
            if (timerStatus.status === "activating" || timerStatus.status === "running") {
                // Still running — stay on in-progress view
                setScanState("in-progress");
            } else {
                setScanState("ready");
            }
        } catch {
            // If we can't check status, just let them proceed
            setScanState("ready");
        }
    }

    /* ------------------------------------------------------------------ */
    /* Loading state                                                      */
    /* ------------------------------------------------------------------ */
    if (scanState === "loading") {
        return (
            <PageSection>
                <Flex justifyContent={{ default: "justifyContentCenter" }}>
                    <FlexItem>
                        <Spinner size="xl" aria-label={_("Loading")} />
                    </FlexItem>
                </Flex>
            </PageSection>
        );
    }

    /* ------------------------------------------------------------------ */
    /* Init error — could not load profiles or config                     */
    /* ------------------------------------------------------------------ */
    if (scanState === "error" && initError) {
        return (
            <PageSection>
                <Alert variant="danger" title={_("Failed to load scan configuration")}>
                    {initError}
                </Alert>
            </PageSection>
        );
    }

    /* ------------------------------------------------------------------ */
    /* No profiles available                                              */
    /* ------------------------------------------------------------------ */
    if (profiles.length === 0 && scanState !== "error") {
        return (
            <PageSection>
                <EmptyState
                    titleText={_("No profiles available")}
                    headingLevel="h2"
                >
                    <EmptyStateBody>
                        {_("Install scap-security-guide to make SCAP profiles available for scanning.")}
                    </EmptyStateBody>
                </EmptyState>
            </PageSection>
        );
    }

    /* ------------------------------------------------------------------ */
    /* Build the profile selector (shared across ready/success states)    */
    /* ------------------------------------------------------------------ */
    const profileSelector = (
        <Select
            id="profile-select"
            isOpen={selectOpen}
            selected={selectedProfile}
            onSelect={onSelectProfile}
            onOpenChange={isOpen => setSelectOpen(isOpen)}
            toggle={toggleNode => (
                <MenuToggle
                    ref={toggleRef}
                    onClick={onSelectToggle}
                    isExpanded={selectOpen}
                    isDisabled={scanState === "scanning"}
                    isFullWidth
                    {...toggleNode}
                >
                    {profileTitle(selectedProfile)}
                </MenuToggle>
            )}
            popperProps={{ width: "trigger" }}
        >
            <SelectList>
                {profiles.map(profile => (
                    <SelectOption
                        key={profile.id}
                        value={profile.id}
                        isSelected={profile.id === selectedProfile}
                        description={cockpit.format(_("$0 rules"), profile.rule_count)}
                    >
                        {profile.title}
                    </SelectOption>
                ))}
            </SelectList>
        </Select>
    );

    /* ------------------------------------------------------------------ */
    /* Render                                                             */
    /* ------------------------------------------------------------------ */
    return (
        <PageSection>
            <Card>
                <CardTitle>{_("Compliance Scan")}</CardTitle>
                <CardBody>
                    {/* Profile selector */}
                    <Content
                        component={ContentVariants.p}
                        style={{ marginBottom: "var(--pf-t--global--spacer--sm)" }}
                    >
                        {_("Profile")}
                    </Content>
                    <div style={{ maxWidth: "480px", marginBottom: "var(--pf-t--global--spacer--md)" }}>
                        {profileSelector}
                    </div>

                    {/* Scheduled scan already in progress */}
                    {scanState === "in-progress" && (
                        <Alert
                            variant="info"
                            isInline
                            title={_("Scan already in progress")}
                            style={{ marginBottom: "var(--pf-t--global--spacer--md)" }}
                        >
                            {_("A scheduled compliance scan is currently running. Wait for it to finish or check back later.")}
                            <br />
                            <Button
                                variant="link"
                                isInline
                                onClick={onRefreshStatus}
                                style={{ marginTop: "var(--pf-t--global--spacer--sm)" }}
                            >
                                {_("Refresh status")}
                            </Button>
                        </Alert>
                    )}

                    {/* Scanning — progress feedback */}
                    {scanState === "scanning" && (
                        <div style={{ marginBottom: "var(--pf-t--global--spacer--md)" }}>
                            <Flex
                                alignItems={{ default: "alignItemsCenter" }}
                                spaceItems={{ default: "spaceItemsSm" }}
                                style={{ marginBottom: "var(--pf-t--global--spacer--sm)" }}
                            >
                                <FlexItem>
                                    <Spinner size="md" aria-label={_("Scanning")} />
                                </FlexItem>
                                <FlexItem>
                                    <Content component={ContentVariants.p}>
                                        {_("Scanning... This may take several minutes.")}
                                    </Content>
                                </FlexItem>
                            </Flex>
                            <Progress
                                aria-label={_("Scan progress")}
                                measureLocation="none"
                            />
                        </div>
                    )}

                    {/* Scan error */}
                    {scanState === "error" && scanError && (
                        <Alert
                            variant="danger"
                            isInline
                            title={_("Scan failed")}
                            style={{ marginBottom: "var(--pf-t--global--spacer--md)" }}
                        >
                            {scanError}
                        </Alert>
                    )}

                    {/* Scan success */}
                    {scanState === "success" && scanResult && (
                        <Alert
                            variant="success"
                            isInline
                            title={cockpit.format(_("Scan complete — $0% compliance"), scanResult.score.toFixed(1))}
                            style={{ marginBottom: "var(--pf-t--global--spacer--md)" }}
                        >
                            <Content component={ContentVariants.p}>
                                {cockpit.format(
                                    _("Profile: $0 | Rules evaluated: $1 | Score: $2%"),
                                    profileTitle(scanResult.profile_id),
                                    scanResult.results.length,
                                    scanResult.score.toFixed(1),
                                )}
                            </Content>
                            <Button
                                variant="link"
                                isInline
                                onClick={onViewResults}
                                style={{ marginTop: "var(--pf-t--global--spacer--sm)" }}
                            >
                                {_("View detailed results")}
                            </Button>
                        </Alert>
                    )}

                    {/* Action buttons */}
                    <Flex spaceItems={{ default: "spaceItemsSm" }}>
                        {(scanState === "ready" || scanState === "error" || scanState === "success") && (
                            <FlexItem>
                                <Button
                                    variant="primary"
                                    onClick={onScanClick}
                                    isDisabled={!selectedProfile}
                                >
                                    {scanState === "success" ? _("Scan Again") : _("Scan Now")}
                                </Button>
                            </FlexItem>
                        )}
                        {scanState === "success" && (
                            <FlexItem>
                                <Button
                                    variant="secondary"
                                    onClick={onViewResults}
                                >
                                    {_("View Results")}
                                </Button>
                            </FlexItem>
                        )}
                        {scanState === "in-progress" && (
                            <FlexItem>
                                <Button
                                    variant="primary"
                                    onClick={onRefreshStatus}
                                >
                                    {_("Check Again")}
                                </Button>
                            </FlexItem>
                        )}
                    </Flex>
                </CardBody>
            </Card>
        </PageSection>
    );
};
