/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * "About 2 minutes left": extrapolated from the time elapsed and the share of
 * rules evaluated so far. Rules vary a lot in cost, so it is an estimate.
 */

import React, { useEffect, useState } from "react";
import cockpit from "cockpit";

import { parseTimestamp } from "../helpers";

const _ = cockpit.gettext;

const TICK_MS = 5000;
/** Below this share of rules the extrapolation is too noisy to show. */
const MIN_PROGRESS = 5;

export function remainingText(started: string | undefined, progress: number, now: number): string | null {
    const startedAt = parseTimestamp(started)?.getTime();
    if (!startedAt || progress < MIN_PROGRESS || progress >= 100)
        return null;
    const elapsed = now - startedAt;
    if (elapsed <= 0)
        return null;
    const minutes = Math.round((elapsed * (100 - progress)) / progress / 60000);
    if (minutes < 1)
        return _("less than a minute left");
    return cockpit.format(cockpit.ngettext("about $0 minute left", "about $0 minutes left", minutes), minutes);
}

export const ScanEta = ({ started, progress }: { started?: string | undefined; progress: number }) => {
    const [now, setNow] = useState(() => Date.now());
    useEffect(() => {
        const timer = window.setInterval(() => setNow(Date.now()), TICK_MS);
        return () => window.clearInterval(timer);
    }, []);
    const text = remainingText(started, progress, now);
    return text ? <span className="oscap-muted oscap-eta">{text}</span> : null;
};
