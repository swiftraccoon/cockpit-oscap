/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Long prose clamped to a few lines with a "Show more" toggle. Unlike
 * PatternFly's truncating ExpandableSection it adds no landmark, so many
 * of them on one page (profile cards) stay quiet for screen readers.
 */

import React, { useState } from "react";
import { Button } from "@patternfly/react-core/dist/esm/components/Button/index.js";
import cockpit from "cockpit";

const _ = cockpit.gettext;

/** Roughly three lines of card text; shorter texts get no toggle at all. */
const CLAMP_THRESHOLD = 220;

export const TruncatedText = ({ text, id }: { text: string; id: string }) => {
    const [expanded, setExpanded] = useState(false);
    const clamp = text.length > CLAMP_THRESHOLD;
    return (
        <div className="oscap-truncated">
            <div id={id} className={`oscap-prose${clamp && !expanded ? " oscap-clamp" : ""}`}>{text}</div>
            {clamp && (
                <Button
                    variant="link" isInline size="sm"
                    aria-expanded={expanded} aria-controls={id}
                    onClick={() => setExpanded(value => !value)}
                >
                    {expanded ? _("Show less") : _("Show more")}
                </Button>
            )}
        </div>
    );
};
