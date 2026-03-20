import React, { useEffect, useState } from 'react';
import { Nav, NavItem, NavList } from "@patternfly/react-core/dist/esm/components/Nav/index.js";
import { Page, PageSidebar, PageSidebarBody } from "@patternfly/react-core/dist/esm/components/Page/index.js";
import cockpit from 'cockpit';

import { OverviewPage } from './pages/OverviewPage.jsx';
import { ProfilesPage } from './pages/ProfilesPage.jsx';
import { TailoringEditor } from './pages/TailoringEditor.jsx';
import { ScanPage } from './pages/ScanPage.jsx';
import { ResultsPage } from './pages/ResultsPage.jsx';
import { ResultDetailPage } from './pages/ResultDetailPage.jsx';
import { SchedulePage } from './pages/SchedulePage.jsx';

const _ = cockpit.gettext;

type PageName = "overview" | "profiles" | "scan" | "results" | "schedule";

const validPages: PageName[] = ["overview", "profiles", "scan", "results", "schedule"];

function getPage(): PageName {
    const segment = cockpit.location.path[0];
    if (segment && validPages.includes(segment as PageName))
        return segment as PageName;
    return "overview";
}

export const Application = () => {
    const [currentPage, setCurrentPage] = useState<PageName>(getPage());

    useEffect(() => {
        const onLocationChanged = () => {
            setCurrentPage(getPage());
        };
        cockpit.addEventListener("locationchanged", onLocationChanged);
        return () => {
            cockpit.removeEventListener("locationchanged", onLocationChanged);
        };
    }, []);

    const onNavSelect = (_event: React.FormEvent<HTMLInputElement>, selectedItem: { itemId: number | string }) => {
        const page = selectedItem.itemId as PageName;
        cockpit.location.go([page]);
    };

    const renderPage = () => {
        const path = cockpit.location.path;

        switch (currentPage) {
        case "overview":
            return <OverviewPage />;
        case "profiles":
            if (path.length > 1) {
                return <TailoringEditor profileId={path[1]} />;
            }
            return <ProfilesPage />;
        case "scan":
            return <ScanPage />;
        case "results":
            if (path.length > 1) {
                return <ResultDetailPage resultId={path[1]} />;
            }
            return <ResultsPage />;
        case "schedule":
            return <SchedulePage />;
        default:
            return <OverviewPage />;
        }
    };

    const sidebar = (
        <PageSidebar>
            <PageSidebarBody>
                <Nav onSelect={onNavSelect}>
                    <NavList>
                        <NavItem itemId="overview" isActive={currentPage === "overview"}>
                            {_("Overview")}
                        </NavItem>
                        <NavItem itemId="profiles" isActive={currentPage === "profiles"}>
                            {_("Profiles")}
                        </NavItem>
                        <NavItem itemId="scan" isActive={currentPage === "scan"}>
                            {_("Scan")}
                        </NavItem>
                        <NavItem itemId="results" isActive={currentPage === "results"}>
                            {_("Results")}
                        </NavItem>
                        <NavItem itemId="schedule" isActive={currentPage === "schedule"}>
                            {_("Schedule")}
                        </NavItem>
                    </NavList>
                </Nav>
            </PageSidebarBody>
        </PageSidebar>
    );

    return (
        <Page sidebar={sidebar}>
            {renderPage()}
        </Page>
    );
};
