import React, { useEffect, useState } from "react";
import { Alert } from "@patternfly/react-core/dist/esm/components/Alert/index.js";
import { Button } from "@patternfly/react-core/dist/esm/components/Button/index.js";
import { Card, CardBody, CardFooter, CardHeader, CardTitle } from "@patternfly/react-core/dist/esm/components/Card/index.js";
import { Content, ContentVariants } from "@patternfly/react-core/dist/esm/components/Content/index.js";
import {
    EmptyState,
    EmptyStateBody,
} from "@patternfly/react-core/dist/esm/components/EmptyState/index.js";
import { Label } from "@patternfly/react-core/dist/esm/components/Label/index.js";
import { PageSection } from "@patternfly/react-core/dist/esm/components/Page/index.js";
import { Spinner } from "@patternfly/react-core/dist/esm/components/Spinner/index.js";
import { Gallery, GalleryItem } from "@patternfly/react-core/dist/esm/layouts/Gallery/index.js";
import { Flex, FlexItem } from "@patternfly/react-core/dist/esm/layouts/Flex/index.js";
import cockpit from "cockpit";

import { detectBackend, listProfiles, loadConfig } from "../api";
import type { BackendInfo, Config, ProfileInfo } from "../types";

const _ = cockpit.gettext;

const CONFIG_PATH = "/var/lib/cockpit-oscap/config.json";

/** Check whether a profile id looks like a CIS benchmark (typically draft). */
function isCisProfile(profileId: string): boolean {
    return profileId.toLowerCase().includes("cis");
}

export const ProfilesPage: React.FunctionComponent = () => {
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [profiles, setProfiles] = useState<ProfileInfo[]>([]);
    const [config, setConfig] = useState<Config>({});
    const [backend, setBackend] = useState<BackendInfo | null>(null);
    const [activating, setActivating] = useState<string | null>(null);
    const [importAlert, setImportAlert] = useState(false);

    useEffect(() => {
        let cancelled = false;

        async function init() {
            try {
                const [profileList, configData, backendInfo] = await Promise.all([
                    listProfiles(),
                    loadConfig(),
                    detectBackend(),
                ]);
                if (cancelled) return;

                setProfiles(profileList);
                setConfig(configData);
                setBackend(backendInfo);
            } catch (err) {
                if (cancelled) return;
                setError(String(err));
            } finally {
                if (!cancelled) setLoading(false);
            }
        }

        init();
        return () => { cancelled = true };
    }, []);

    /** Set a profile as active by updating config.json. */
    async function activateProfile(profileId: string) {
        setActivating(profileId);
        try {
            await cockpit.file(CONFIG_PATH, { superuser: "try" })
                    .modify((content: string | null) => {
                        const cfg: Config = content ? JSON.parse(content) : {};
                        cfg.active_profile = profileId;
                        return JSON.stringify(cfg, null, 2);
                    });
            setConfig(prev => ({ ...prev, active_profile: profileId }));
        } catch (err) {
            setError(cockpit.format(_("Failed to activate profile: $0"), String(err)));
        } finally {
            setActivating(null);
        }
    }

    /* Loading state */
    if (loading) {
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

    /* Error state */
    if (error) {
        return (
            <PageSection>
                <Alert variant="danger" title={_("Failed to load profiles")}>
                    {error}
                </Alert>
            </PageSection>
        );
    }

    /* No profiles found */
    if (profiles.length === 0) {
        return (
            <PageSection>
                <EmptyState
                    titleText={_("No profiles available")}
                    headingLevel="h2"
                >
                    <EmptyStateBody>
                        {_("Install scap-security-guide to make SCAP profiles available.")}
                    </EmptyStateBody>
                </EmptyState>
            </PageSection>
        );
    }

    const activeProfileId = config.active_profile;

    return (
        <PageSection>
            {/* Header row */}
            <Flex
                justifyContent={{ default: "justifyContentSpaceBetween" }}
                alignItems={{ default: "alignItemsCenter" }}
                style={{ marginBottom: "var(--pf-t--global--spacer--md)" }}
            >
                <FlexItem>
                    <Content component={ContentVariants.h1}>
                        {_("Security Profiles")}
                    </Content>
                </FlexItem>
                <FlexItem>
                    <Button
                        variant="secondary"
                        onClick={() => setImportAlert(true)}
                    >
                        {_("Import Tailoring")}
                    </Button>
                </FlexItem>
            </Flex>

            {/* Import tailoring placeholder alert */}
            {importAlert && (
                <Alert
                    variant="info"
                    isInline
                    title={_("Import not yet available")}
                    actionClose={<Button variant="plain" onClick={() => setImportAlert(false)}>{_("Dismiss")}</Button>}
                    style={{ marginBottom: "var(--pf-t--global--spacer--md)" }}
                >
                    {_("Tailoring file import will be available in a future update.")}
                </Alert>
            )}

            {/* Content source info bar */}
            {backend && (
                <Content
                    component={ContentVariants.small}
                    style={{ marginBottom: "var(--pf-t--global--spacer--md)" }}
                >
                    {cockpit.format(
                        _("Datastream: $0 \u00B7 OpenSCAP $1"),
                        backend.content.datastream_path,
                        backend.oscap.version
                    )}
                </Content>
            )}

            {/* Profile card grid */}
            <Gallery hasGutter minWidths={{ default: "300px" }}>
                {profiles.map(profile => {
                    const isActive = profile.id === activeProfileId;
                    const isDraft = isCisProfile(profile.id);

                    return (
                        <GalleryItem key={profile.id}>
                            <Card
                                isSelectable={isActive}
                                isSelected={isActive}
                                isFullHeight
                                isCompact
                            >
                                <CardHeader>
                                    <CardTitle>
                                        <Flex
                                            spaceItems={{ default: "spaceItemsSm" }}
                                            alignItems={{ default: "alignItemsCenter" }}
                                        >
                                            <FlexItem>{profile.title}</FlexItem>
                                            {isActive && (
                                                <FlexItem>
                                                    <Label color="blue" isCompact>{_("ACTIVE")}</Label>
                                                </FlexItem>
                                            )}
                                            {isDraft && (
                                                <FlexItem>
                                                    <Label color="yellow" isCompact>{_("DRAFT")}</Label>
                                                </FlexItem>
                                            )}
                                        </Flex>
                                    </CardTitle>
                                </CardHeader>
                                <CardBody>
                                    <Content component={ContentVariants.p}>
                                        {profile.description}
                                    </Content>
                                    <Content
                                        component={ContentVariants.small}
                                        style={{ marginTop: "var(--pf-t--global--spacer--sm)" }}
                                    >
                                        {cockpit.format(_("$0 rules"), profile.rule_count)}
                                    </Content>
                                </CardBody>
                                <CardFooter>
                                    {isActive
                                        ? (
                                            <Flex spaceItems={{ default: "spaceItemsSm" }}>
                                                <FlexItem>
                                                    <Button
                                                        variant="primary"
                                                        size="sm"
                                                        onClick={() => cockpit.location.go(["profiles", profile.id])}
                                                    >
                                                        {_("Edit Tailoring")}
                                                    </Button>
                                                </FlexItem>
                                                <FlexItem>
                                                    <Button
                                                        variant="secondary"
                                                        size="sm"
                                                        onClick={() => cockpit.location.go(["profiles", profile.id])}
                                                    >
                                                        {_("Export Tailoring")}
                                                    </Button>
                                                </FlexItem>
                                            </Flex>
                                        )
                                        : (
                                            <Flex spaceItems={{ default: "spaceItemsSm" }}>
                                                <FlexItem>
                                                    <Button
                                                        variant="primary"
                                                        size="sm"
                                                        isLoading={activating === profile.id}
                                                        isDisabled={activating !== null}
                                                        onClick={() => activateProfile(profile.id)}
                                                    >
                                                        {_("Activate")}
                                                    </Button>
                                                </FlexItem>
                                                <FlexItem>
                                                    <Button
                                                        variant="secondary"
                                                        size="sm"
                                                        onClick={() => cockpit.location.go(["profiles", profile.id])}
                                                    >
                                                        {_("Customize")}
                                                    </Button>
                                                </FlexItem>
                                            </Flex>
                                        )}
                                </CardFooter>
                            </Card>
                        </GalleryItem>
                    );
                })}
            </Gallery>
        </PageSection>
    );
};
