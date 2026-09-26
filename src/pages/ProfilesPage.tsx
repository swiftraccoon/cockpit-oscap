/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Profiles: the security profiles available in the SCAP content, which one
 * scheduled scans use, and entry points to customize or scan with them.
 */

import React, { useState } from "react";
import { Button } from "@patternfly/react-core/dist/esm/components/Button/index.js";
import { Card, CardBody, CardFooter, CardTitle } from "@patternfly/react-core/dist/esm/components/Card/index.js";
import { Content } from "@patternfly/react-core/dist/esm/components/Content/index.js";
import { DropdownItem } from "@patternfly/react-core/dist/esm/components/Dropdown/index.js";
import { Label } from "@patternfly/react-core/dist/esm/components/Label/index.js";
import { Tooltip } from "@patternfly/react-core/dist/esm/components/Tooltip/index.js";
import { SearchInput } from "@patternfly/react-core/dist/esm/components/SearchInput/index.js";
import { Toolbar, ToolbarContent, ToolbarItem } from "@patternfly/react-core/dist/esm/components/Toolbar/index.js";
import { Gallery } from "@patternfly/react-core/dist/esm/layouts/Gallery/index.js";
import { Stack, StackItem } from "@patternfly/react-core/dist/esm/layouts/Stack/index.js";
import cockpit from "cockpit";

import { EmptyStatePanel } from "cockpit-components-empty-state";
import { SimpleSelect } from "cockpit-components-simple-select";
import { useDialogs } from "dialogs";
import * as timeformat from "timeformat";

import { deleteTailoring, getConfig, listProfiles, listResults, readFile, setConfig } from "../api";
import { useApp } from "../app";
import { useAsync } from "../app-hooks";
import { ActionsMenu } from "../components/ActionsMenu";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { ScoreLabel, TailoredLabel } from "../components/labels";
import { ErrorAlert, ErrorState, Loading } from "../components/states";
import { TruncatedText } from "../components/TruncatedText";
import { downloadFile, errorMessage, matchesSearch, parseTimestamp, profileShortName, safeFilename } from "../helpers";
import type { ProfileInfo, ResultSummary } from "../types";

const _ = cockpit.gettext;

export const ProfilesPage = () => {
    const app = useApp();
    const Dialogs = useDialogs();
    const data = useAsync(async () => {
        const [profiles, config, results] = await Promise.all([
            listProfiles(),
            getConfig(),
            listResults().catch((): ResultSummary[] => []),
        ]);
        // newest first, so the first summary per base profile is its latest scan
        const latest = new Map<string, ResultSummary>();
        for (const summary of results) {
            if (summary.status === "complete" && !latest.has(summary.base_profile_id))
                latest.set(summary.base_profile_id, summary);
        }
        return { profiles, config, latest };
    }, [app.version]);
    const [search, setSearch] = useState("");
    const [busy, setBusy] = useState<string | null>(null);
    const [error, setError] = useState<string | null>(null);

    if (data.loading && !data.data)
        return <Loading />;
    if (data.error || !data.data)
        return <ErrorState title={_("Failed to load profiles")} error={data.error} onRetry={() => data.reload()} />;

    const { profiles, config, latest } = data.data;
    const datastreams = app.backend.content.available;
    const readOnly = app.superuser === false;

    async function activate(profile: ProfileInfo) {
        setBusy(profile.id);
        setError(null);
        try {
            const updated = await setConfig({ active_profile: profile.id });
            data.setData(prev => prev && { ...prev, config: updated });
        } catch (err) {
            setError(errorMessage(err));
        } finally {
            setBusy(null);
        }
    }

    async function selectDatastream(path: string) {
        setError(null);
        try {
            await setConfig({ datastream: path });
            app.reloadBackend();
            app.bump();
        } catch (err) {
            setError(errorMessage(err));
        }
    }

    async function exportTailoring(profile: ProfileInfo) {
        if (!profile.tailoring_path)
            return;
        try {
            const xml = await readFile(profile.tailoring_path);
            downloadFile(`${safeFilename(profileShortName(profile.id))}-tailoring.xml`, xml, "application/xml");
        } catch (err) {
            setError(errorMessage(err));
        }
    }

    async function removeTailoring(profile: ProfileInfo) {
        const confirmed = await Dialogs.run(ConfirmDialog, {
            title: _("Remove customizations?"),
            body: cockpit.format(_("The saved customizations for $0 will be deleted. Scans will use the profile defaults."),
                                 profile.title),
            confirmText: _("Remove"),
            isDanger: true,
        });
        if (!confirmed)
            return;
        try {
            await deleteTailoring(profile.id);
            app.bump();
        } catch (err) {
            setError(errorMessage(err));
        }
    }

    const shown = profiles.filter(p => matchesSearch(search, p.title, p.id, p.description));

    return (
        <Stack hasGutter>
            <StackItem>
                <Toolbar id="profiles-toolbar" inset={{ default: "insetNone" }}>
                    <ToolbarContent>
                        <ToolbarItem>
                            <SearchInput
                                id="profiles-search"
                                placeholder={_("Search profiles")}
                                value={search}
                                onChange={(_ev, value) => setSearch(value)}
                                onClear={() => setSearch("")}
                            />
                        </ToolbarItem>
                        {datastreams.length > 1 && (
                            <ToolbarItem>
                                <SimpleSelect
                                    toggleProps={{ id: "profiles-datastream" }}
                                    options={datastreams.map(ds => ({ value: ds.path, content: ds.name }))}
                                    selected={app.backend.content.datastream_path}
                                    onSelect={value => selectDatastream(value)}
                                    isDisabled={readOnly}
                                />
                            </ToolbarItem>
                        )}
                        <ToolbarItem align={{ default: "alignEnd" }}>
                            <span className="oscap-toolbar-count">
                                {cockpit.format(cockpit.ngettext("$0 profile", "$0 profiles", shown.length), shown.length)}
                                {" · "}
                                {app.backend.content.datastream_path.split("/").pop()}
                            </span>
                        </ToolbarItem>
                    </ToolbarContent>
                </Toolbar>
            </StackItem>
            {error && (
                <StackItem>
                    <ErrorAlert title={_("Operation failed")} error={error} onDismiss={() => setError(null)} />
                </StackItem>
            )}
            {app.backend.content.source === "fallback" && (
                <StackItem>
                    <Content component="small" className="oscap-muted">
                        {_("No SCAP content matches this operating system exactly; showing the newest content installed.")}
                    </Content>
                </StackItem>
            )}
            <StackItem>
                {shown.length === 0
                    ? (
                        <EmptyStatePanel
                            title={profiles.length === 0 ? _("No profiles available") : _("No matching profiles")}
                            paragraph={profiles.length === 0
                                ? _("The selected SCAP content does not define any profiles.")
                                : _("Try a different search term.")}
                        />
                    )
                    : (
                        <Gallery hasGutter minWidths={{ default: "100%", md: "360px" }}>
                            {shown.map(profile => {
                                const isActive = profile.id === config.active_profile;
                                const short = profileShortName(profile.id);
                                const last = latest.get(profile.id);
                                const lastDate = last ? parseTimestamp(last.timestamp) : null;
                                const kebab = [
                                    <DropdownItem
key="scan" isDisabled={readOnly || app.scanning}
                                                  onClick={() => app.runScan(profile.id)}
                                    >
                                        {_("Run scan with this profile")}
                                    </DropdownItem>,
                                    <DropdownItem key="customize" onClick={() => cockpit.location.go(["profiles", profile.id])}>
                                        {_("Customize")}
                                    </DropdownItem>,
                                ];
                                if (profile.tailoring_path) {
                                    kebab.push(
                                        <DropdownItem key="export" onClick={() => exportTailoring(profile)}>
                                            {_("Export customizations")}
                                        </DropdownItem>,
                                        <DropdownItem
key="remove" isDanger isDisabled={readOnly}
                                                      onClick={() => removeTailoring(profile)}
                                        >
                                            {_("Remove customizations")}
                                        </DropdownItem>,
                                    );
                                }
                                return (
                                    <Card
key={profile.id} id={`profile-${safeFilename(short)}`}
                                          className="ct-card oscap-profile-card" isFullHeight
                                    >
                                        <CardTitle>
                                            <span>{profile.title}</span>
                                            {isActive && <Label status="info" isCompact>{_("Active")}</Label>}
                                            {profile.tailored_profile_id && <TailoredLabel />}
                                            {profile.tailoring_problem && (
                                                <Tooltip content={profile.tailoring_problem}>
                                                    <Label status="warning" isCompact>{_("Customization not applied")}</Label>
                                                </Tooltip>
                                            )}
                                        </CardTitle>
                                        <CardBody>
                                            <Stack hasGutter>
                                                <StackItem>
                                                    <TruncatedText
                                                        id={`profile-description-${safeFilename(short)}`}
                                                        text={profile.description || _("No description available.")}
                                                    />
                                                </StackItem>
                                                <StackItem>
                                                    <Content component="small">
                                                        {cockpit.format(cockpit.ngettext("$0 rule", "$0 rules", profile.rule_count),
                                                                        profile.rule_count)}
                                                        {" · "}
                                                        <span className="oscap-mono">{short}</span>
                                                    </Content>
                                                </StackItem>
                                                <StackItem>
                                                    <span className="oscap-inline-list oscap-small">
                                                        {last
                                                            ? (
                                                                <>
                                                                    <ScoreLabel score={last.score} />
                                                                    <Button
variant="link" isInline className="oscap-small"
                                                                            onClick={() => cockpit.location.go(["results", last.id])}
                                                                    >
                                                                        {lastDate
                                                                            ? cockpit.format(_("scanned $0"), timeformat.distanceToNow(lastDate))
                                                                            : _("last scan")}
                                                                    </Button>
                                                                </>
                                                            )
                                                            : <span className="oscap-muted">{_("Not scanned yet")}</span>}
                                                    </span>
                                                </StackItem>
                                            </Stack>
                                        </CardBody>
                                        <CardFooter className="oscap-card-actions">
                                            {isActive
                                                ? (
                                                    <Button variant="secondary" size="sm" isDisabled>
                                                        {_("Active profile")}
                                                    </Button>
                                                )
                                                : (
                                                    <Button
                                                        variant="primary"
                                                        size="sm"
                                                        isLoading={busy === profile.id}
                                                        isDisabled={busy !== null || readOnly}
                                                        onClick={() => activate(profile)}
                                                    >
                                                        {_("Set as active")}
                                                    </Button>
                                                )}
                                            <Button
variant="link" size="sm" isInline
                                                    onClick={() => cockpit.location.go(["profiles", profile.id])}
                                            >
                                                {_("Customize")}
                                            </Button>
                                            <span className="oscap-card-actions-end">
                                                <ActionsMenu
                                                    toggleButtonId={`profile-actions-${safeFilename(short)}`}
                                                    ariaLabel={cockpit.format(_("Actions for $0"), profile.title)}
                                                    dropdownItems={kebab}
                                                />
                                            </span>
                                        </CardFooter>
                                    </Card>
                                );
                            })}
                        </Gallery>
                    )}
            </StackItem>
        </Stack>
    );
};
