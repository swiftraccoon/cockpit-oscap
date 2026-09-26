/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Long prose clamped to a few lines with a "Show more" toggle that only
 * appears when the text really overflows. Unlike PatternFly's truncating
 * ExpandableSection it adds no landmark, so many of them on one page
 * (profile cards) stay quiet for screen readers.
 */

import React, { useLayoutEffect, useRef, useState } from "react";
import { Button } from "@patternfly/react-core/dist/esm/components/Button/index.js";
import cockpit from "cockpit";

const _ = cockpit.gettext;

export const TruncatedText = ({ text, id }: { text: string; id: string }) => {
    const [expanded, setExpanded] = useState(false);
    const [overflows, setOverflows] = useState(false);
    const ref = useRef<HTMLDivElement>(null);

    useLayoutEffect(() => {
        const element = ref.current;
        if (!element || expanded)
            return undefined;
        const measure = () => setOverflows(element.scrollHeight > element.clientHeight + 1);
        measure();
        const observer = new ResizeObserver(measure);
        observer.observe(element);
        return () => observer.disconnect();
    }, [expanded, text]);

    return (
        <div className="oscap-truncated">
            <div ref={ref} id={id} className={`oscap-prose${expanded ? "" : " oscap-clamp"}`}>{text}</div>
            {(overflows || expanded) && (
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
