/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { remainingText } from "../../src/components/ScanEta";

describe("remainingText", () => {
    const anchor = { progress: 10, time: 0 };

    it("stays quiet until enough progress was observed", () => {
        assert.equal(remainingText(anchor, 11, 10_000), null);
        assert.equal(remainingText(anchor, 50, 0), null);
        assert.equal(remainingText(anchor, 100, 60_000), null);
    });

    it("extrapolates from the observed rate", () => {
        // 40 points in 2 minutes leaves 50 points: about 2.5 minutes, rounded to 3
        assert.equal(remainingText(anchor, 50, 120_000), "about 3 minutes left");
        // 60 points in 90 seconds leaves 30 points: 45 seconds, rounded to a minute
        assert.equal(remainingText(anchor, 70, 90_000), "about 1 minute left");
        assert.equal(remainingText(anchor, 98, 60_000), "less than a minute left");
    });
});
