/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Application shell: backend detection, tabs, the global scan banner and
 * routing on cockpit.location (overview, profiles[/<id>], results[/<id>],
 * schedule).
 */

import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { Button } from "@patternfly/react-core/dist/esm/components/Button/index.js";
import { Page, PageSection } from "@patternfly/react-core/dist/esm/components/Page/index.js";
import { Tab, Tabs, TabTitleText } from "@patternfly/react-core/dist/esm/components/Tabs/index.js";
import PlayIcon from "@patternfly/react-icons/dist/esm/icons/play-icon";
import cockpit from "cockpit";

import { WithDialogs, useDialogs } from "dialogs";
import { usePageLocation } from "hooks";

import { detectBackend } from "./api";
import { useAsync, useScanState, useSuperuser } from "./app-hooks";
import { ScanBanner } from "./components/ScanBanner";
import { ScanDialog } from "./components/ScanDialog";
import { ErrorState, LimitedAccessAlert, Loading, SetupNeeded } from "./components/states";
import { OverviewPage } from "./pages/OverviewPage";
import { ProfilesPage } from "./pages/ProfilesPage";
import { ResultDetailPage } from "./pages/ResultDetailPage";
import { ResultsPage } from "./pages/ResultsPage";
import { SchedulePage } from "./pages/SchedulePage";
import { TailoringEditor } from "./pages/TailoringEditor";
import type { BackendInfo } from "./types";

const _ = cockpit.gettext;

export interface AppContextValue {
    backend: BackendInfo;
    reloadBackend: () => void;
    /** Incremented whenever results or configuration change; pages reload when it does. */
    version: number;
    bump: () => void;
    /** Whether the session has administrative access (null while unknown). */
    superuser: boolean | null;
    /** Whether a scan is currently running anywhere on the system. */
    scanning: boolean;
    runScan: (profileId?: string) => void;
}

const AppContext = createContext<AppContextValue | null>(null);

export function useApp(): AppContextValue {
    const context = useContext(AppContext);
    if (!context)
        throw new Error("useApp() must be used inside the application shell");
    return context;
}

type PageName = "overview" | "profiles" | "results" | "schedule";

const PAGES: PageName[] = ["overview", "profiles", "results", "schedule"];

const PAGE_COMPONENTS: Record<PageName, React.ComponentType> = {
    overview: OverviewPage,
    profiles: ProfilesPage,
    results: ResultsPage,
    schedule: SchedulePage,
};

function pageLabel(page: PageName): string {
    switch (page) {
    case "overview":
        return _("Overview");
    case "profiles":
        return _("Profiles");
    case "results":
        return _("Results");
    case "schedule":
        return _("Schedule");
    }
}

const AppShell = () => {
    const { path } = usePageLocation();
    const Dialogs = useDialogs();
    const backend = useAsync(detectBackend, []);
    const superuserAllowed = useSuperuser();
    const scanState = useScanState();
    const [version, setVersion] = useState(0);
    const bump = useCallback(() => setVersion(v => v + 1), []);

    const scanning = Boolean(scanState?.running);

    // Refresh everything when a scan (interactive or scheduled) finishes
    const wasScanning = useRef(false);
    useEffect(() => {
        if (wasScanning.current && !scanning)
            bump();
        wasScanning.current = scanning;
    }, [scanning, bump]);

    // The former "scan" page became a dialog; keep old links working
    useEffect(() => {
        if (path[0] === "scan")
            cockpit.location.replace(["overview"]);
    }, [path]);

    const runScan = useCallback((profileId?: string) => {
        if (Dialogs.isActive())
            return;
        Dialogs.show(<ScanDialog {...profileId && { initialProfileId: profileId }} onFinished={bump} />);
    }, [Dialogs, bump]);

    const info = backend.data;
    const context = useMemo<AppContextValue | null>(() => info
        ? {
            backend: info,
            reloadBackend: backend.reload,
            version,
            bump,
            superuser: superuserAllowed,
            scanning,
            runScan,
        }
        : null, [info, backend.reload, version, bump, superuserAllowed, scanning, runScan]);

    if (!context || !info) {
        return (
            <Page className="no-masthead-sidebar" isContentFilled>
                <PageSection hasBodyWrapper={false} isFilled>
                    {backend.loading
                        ? <Loading />
                        : <ErrorState title={_("Failed to detect OpenSCAP")} error={backend.error} onRetry={() => backend.reload()} />}
                </PageSection>
            </Page>
        );
    }

    if (!info.oscap || !info.content.present) {
        return (
            <Page className="no-masthead-sidebar" isContentFilled>
                <SetupNeeded backend={info} onRetry={() => backend.reload()} />
            </Page>
        );
    }

    const page: PageName = PAGES.includes(path[0] as PageName) ? path[0] as PageName : "overview";
    const detail = path[1];

    let content: React.ReactNode;
    if (page === "profiles" && detail) {
        content = <TailoringEditor profileId={detail} />;
    } else if (page === "results" && detail) {
        content = <ResultDetailPage resultId={detail} />;
    } else {
        const Component = PAGE_COMPONENTS[page];
        content = (
            <PageSection hasBodyWrapper={false} isFilled id={`page-${page}`}>
                <Component />
            </PageSection>
        );
    }

    return (
        <AppContext.Provider value={context}>
            <Page className="no-masthead-sidebar" isContentFilled>
                {!detail && (
                    <PageSection type="tabs" hasBodyWrapper={false}>
                        <div className="oscap-tabs-row">
                            <Tabs
                                id="oscap-tabs"
                                activeKey={page}
                                onSelect={(_ev, key) => cockpit.location.go([String(key)])}
                                aria-label={_("Compliance sections")}
                            >
                                {PAGES.map(name => (
                                    <Tab
key={name} eventKey={name} id={`tab-${name}`}
                                         title={<TabTitleText>{pageLabel(name)}</TabTitleText>}
                                    />
                                ))}
                            </Tabs>
                            <Button
                                id="run-scan"
                                variant="primary"
                                icon={<PlayIcon />}
                                onClick={() => runScan()}
                                isDisabled={superuserAllowed === false || scanning}
                            >
                                {_("Run scan")}
                            </Button>
                        </div>
                    </PageSection>
                )}
                {superuserAllowed === false && !detail && (
                    <PageSection hasBodyWrapper={false} className="oscap-banner-section">
                        <LimitedAccessAlert />
                    </PageSection>
                )}
                <ScanBanner />
                {content}
            </Page>
        </AppContext.Provider>
    );
};

export const Application = () => (
    <WithDialogs>
        <AppShell />
    </WithDialogs>
);
