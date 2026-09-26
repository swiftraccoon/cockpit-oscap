/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * "About 2 minutes left": extrapolated from the progress observed since this
 * component first saw the scan, so it never compares the browser's clock with
 * the server's. Rules vary a lot in cost, so it is an estimate.
 */

import React, { useEffect, useState } from "react";
import cockpit from "cockpit";

const _ = cockpit.gettext;

const TICK_MS = 5000;
/** Below this much observed progress the extrapolation is too noisy to show. */
const MIN_ADVANCE = 3;

export interface EtaAnchor {
    progress: number;
    time: number;
}

export function remainingText(anchor: EtaAnchor, progress: number, now: number): string | null {
    const advanced = progress - anchor.progress;
    const elapsed = now - anchor.time;
    if (advanced < MIN_ADVANCE || elapsed <= 0 || progress >= 100)
        return null;
    const minutes = Math.round(((100 - progress) * elapsed) / advanced / 60000);
    if (minutes < 1)
        return _("less than a minute left");
    return cockpit.format(cockpit.ngettext("about $0 minute left", "about $0 minutes left", minutes), minutes);
}

/** One anchor per scan, kept outside React so the estimate survives the banner being hidden by a dialog. */
const anchors = new Map<string, EtaAnchor>();

function anchorFor(scanKey: string, progress: number): EtaAnchor {
    const existing = anchors.get(scanKey);
    if (existing && progress >= existing.progress)
        return existing;
    anchors.clear();  // only one scan runs at a time; earlier ones are history
    const anchor = { progress, time: Date.now() };
    anchors.set(scanKey, anchor);
    return anchor;
}

export const ScanEta = ({ scanKey, progress }: {
    /** Identifies the scan, e.g. its start timestamp. */
    scanKey: string;
    progress: number;
}) => {
    const anchor = anchorFor(scanKey, progress);
    const [now, setNow] = useState(() => Date.now());
    useEffect(() => {
        const timer = window.setInterval(() => setNow(Date.now()), TICK_MS);
        return () => window.clearInterval(timer);
    }, []);
    const text = remainingText(anchor, progress, now);
    return text ? <span className="oscap-muted oscap-eta">{text}</span> : null;
};
