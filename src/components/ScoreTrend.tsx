/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * A compact score-over-time chart for one profile: a single thin line with
 * ringed markers, a crosshair readout driven by pointer or arrow keys, and a
 * direct label on the latest scan only. Colors come from theme tokens (see
 * .oscap-trend in app.scss); the Results tab is the table view of the same data.
 */

import React, { useState } from "react";
import cockpit from "cockpit";

import * as timeformat from "timeformat";

import { formatScore, parseTimestamp } from "../helpers";

const _ = cockpit.gettext;

export interface TrendPoint {
    id: string;
    timestamp: string;
    score: number;
}

const WIDTH = 320;
const HEIGHT = 84;
const PAD_X = 10;
const PAD_TOP = 18;
const PAD_BOTTOM = 10;
/** Never zoom in further than this many points, so a flat line still reads as flat. */
const MIN_SPAN = 10;
const DOT_RADIUS = 4;
const ACTIVE_RADIUS = 5.5;

function domain(scores: number[]): [number, number] {
    let lo = Math.min(...scores);
    let hi = Math.max(...scores);
    if (hi - lo < MIN_SPAN) {
        const mid = (hi + lo) / 2;
        lo = mid - MIN_SPAN / 2;
        hi = mid + MIN_SPAN / 2;
    }
    return [Math.max(0, Math.floor(lo)), Math.min(100, Math.ceil(hi))];
}

export const ScoreTrend = ({ points, onSelect }: {
    /** Scans in chronological order, oldest first. */
    points: TrendPoint[];
    /** Called when a point is chosen with a click, Enter or Space. */
    onSelect?: (point: TrendPoint) => void;
}) => {
    const [hover, setHover] = useState<number | null>(null);

    if (points.length < 2)
        return null;

    const [lo, hi] = domain(points.map(p => p.score));
    const x = (index: number) => PAD_X + (index / (points.length - 1)) * (WIDTH - 2 * PAD_X);
    const y = (score: number) => PAD_TOP + (1 - (score - lo) / (hi - lo)) * (HEIGHT - PAD_TOP - PAD_BOTTOM);
    const path = points.map((p, i) => `${i === 0 ? "M" : "L"}${x(i).toFixed(1)} ${y(p.score).toFixed(1)}`).join(" ");
    const last = points.length - 1;
    const active = Math.min(hover ?? last, last);
    const current = points[active];
    const currentDate = parseTimestamp(current.timestamp);
    const firstDate = parseTimestamp(points[0].timestamp);
    const when = (date: Date | null, fallback: string) => (date ? timeformat.dateTime(date) : fallback);

    const description = cockpit.format(
        _("Score trend over $0 scans: $1 on $2, $3 on $4"),
        points.length, formatScore(points[0].score), when(firstDate, points[0].timestamp),
        formatScore(points[last].score), when(parseTimestamp(points[last].timestamp), points[last].timestamp));

    function locate(ev: React.PointerEvent<SVGSVGElement>) {
        const rect = ev.currentTarget.getBoundingClientRect();
        if (rect.width === 0)
            return;
        const rel = ((ev.clientX - rect.left) / rect.width) * WIDTH;
        let best = 0;
        for (let i = 1; i < points.length; i++) {
            if (Math.abs(x(i) - rel) < Math.abs(x(best) - rel))
                best = i;
        }
        setHover(best);
    }

    function onKeyDown(ev: React.KeyboardEvent<SVGSVGElement>) {
        if (ev.key === "ArrowLeft" || ev.key === "ArrowRight") {
            ev.preventDefault();
            setHover(Math.max(0, Math.min(last, active + (ev.key === "ArrowLeft" ? -1 : 1))));
        } else if ((ev.key === "Enter" || ev.key === " ") && onSelect) {
            ev.preventDefault();
            onSelect(current);
        }
    }

    return (
        <div className="oscap-trend" id="score-trend">
            <svg
                className="oscap-trend-svg"
                viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
                role="img"
                aria-label={description}
                tabIndex={0}
                onPointerMove={locate}
                onPointerLeave={() => setHover(null)}
                onBlur={() => setHover(null)}
                onKeyDown={onKeyDown}
                onClick={() => onSelect?.(current)}
            >
                {hover !== null && (
                    <line
                        className="oscap-trend-crosshair"
                        x1={x(active)} x2={x(active)} y1={PAD_TOP - 8} y2={HEIGHT - PAD_BOTTOM + 4}
                    />
                )}
                <path className="oscap-trend-line" d={path} />
                {points.map((p, i) => (
                    <circle
                        key={p.id}
                        className="oscap-trend-dot"
                        cx={x(i)} cy={y(p.score)}
                        r={i === active ? ACTIVE_RADIUS : DOT_RADIUS}
                    />
                ))}
                <text className="oscap-trend-label" x={x(last)} y={y(points[last].score) - 10} textAnchor="end">
                    {formatScore(points[last].score)}
                </text>
            </svg>
            <div className="oscap-trend-readout">
                <strong>{formatScore(current.score)}</strong>
                <span className="oscap-muted">
                    {" · "}{when(currentDate, current.timestamp)}
                    {hover === null && <>{" · "}{cockpit.format(_("last $0 scans"), points.length)}</>}
                </span>
            </div>
        </div>
    );
};
