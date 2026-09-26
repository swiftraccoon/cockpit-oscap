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
import { page_status } from "notifications";
import type { Status } from "notifications";
import { usePageLocation } from "hooks";

import { detectBackend, listResults } from "./api";
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
import { formatScore, scoreVariant } from "./helpers";
import type { BackendInfo, ResultSummary, ScanState } from "./types";

const _ = cockpit.gettext;

const RELOAD_COALESCE_MS = 150;

/** What Cockpit's navigation should flag next to "Compliance", or null when all is well. */
function complianceStatus(results: ResultSummary[], scanState: ScanState | null): Status | null {
    if (scanState && !scanState.running && scanState.status === "failed")
        return { type: "warning", title: _("The last compliance scan failed") };
    const latest = results.find(r => r.status === "complete");
    if (latest && scoreVariant(latest.score) === "danger")
        return { type: "warning", title: cockpit.format(_("Compliance score $0"), formatScore(latest.score)) };
    return null;
}

/** The page frame: Cockpit's shell has no heading of its own, so every state of the page gets one. */
const Shell = ({ children }: { children: React.ReactNode }) => (
    <Page className="no-masthead-sidebar" isContentFilled>
        <h1 className="pf-v6-screen-reader">{_("Compliance")}</h1>
        {children}
    </Page>
);

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
    // Reload everything. Calls within a short window collapse into one reload: a finished scan
    // is reported both by the dialog that ran it and by the scan-state file watch.
    const bumpTimer = useRef<number | null>(null);
    const bump = useCallback(() => {
        if (bumpTimer.current !== null)
            window.clearTimeout(bumpTimer.current);
        bumpTimer.current = window.setTimeout(() => {
            bumpTimer.current = null;
            setVersion(v => v + 1);
        }, RELOAD_COALESCE_MS);
    }, []);

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

    // Flag a failed scan or a poor score in Cockpit's navigation (the manifest preloads this page,
    // so the icon appears without visiting it). A finished scan bumps `version`, so keying on it
    // costs one bridge call per reload rather than one per scan-state write.
    const scanStateRef = useRef(scanState);
    scanStateRef.current = scanState;
    useEffect(() => {
        if (!info || !info.oscap || !info.content.present || scanStateRef.current?.running)
            return undefined;
        let cancelled = false;
        listResults()
                .then(results => { if (!cancelled) page_status.set_own(complianceStatus(results, scanStateRef.current)); })
                .catch(() => { if (!cancelled) page_status.set_own(null); });
        return () => { cancelled = true };
    }, [info, version]);
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
            <Shell>
                <PageSection hasBodyWrapper={false} isFilled>
                    {backend.loading
                        ? <Loading />
                        : <ErrorState title={_("Failed to detect OpenSCAP")} error={backend.error} onRetry={() => backend.reload()} />}
                </PageSection>
            </Shell>
        );
    }

    if (!info.oscap || !info.content.present) {
        return (
            <Shell>
                <SetupNeeded backend={info} onRetry={() => backend.reload()} />
            </Shell>
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
            <PageSection
hasBodyWrapper={false} isFilled id={`page-${page}`}
                         role="tabpanel" aria-labelledby={`pf-tab-${page}-tab-${page}`}
            >
                <Component />
            </PageSection>
        );
    }

    return (
        <AppContext.Provider value={context}>
            <Shell>
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
key={name} eventKey={name} id={`tab-${name}`} tabContentId={`page-${name}`}
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
            </Shell>
        </AppContext.Provider>
    );
};

export const Application = () => (
    <WithDialogs>
        <AppShell />
    </WithDialogs>
);
