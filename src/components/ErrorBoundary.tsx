/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * A rendering error in one page shows an error with a way out instead of a
 * blank frame.
 */

import React from "react";
import { Button } from "@patternfly/react-core/dist/esm/components/Button/index.js";
import { PageSection } from "@patternfly/react-core/dist/esm/components/Page/index.js";
import cockpit from "cockpit";

import { ErrorState } from "./states";

const _ = cockpit.gettext;

interface State {
    error: Error | null;
}

export class ErrorBoundary extends React.Component<{ children: React.ReactNode }, State> {
    state: State = { error: null };

    static getDerivedStateFromError(error: Error): State {
        return { error };
    }

    componentDidCatch(error: Error, info: React.ErrorInfo): void {
        console.error("cockpit-oscap: page failed to render", error, info.componentStack);
    }

    render(): React.ReactNode {
        if (!this.state.error)
            return this.props.children;
        return (
            <PageSection hasBodyWrapper={false} isFilled>
                <ErrorState
                    title={_("This page could not be displayed")}
                    error={this.state.error.message}
                    onRetry={() => this.setState({ error: null })}
                />
                <Button variant="link" onClick={() => cockpit.location.go(["overview"])}>{_("Back to overview")}</Button>
            </PageSection>
        );
    }
}
