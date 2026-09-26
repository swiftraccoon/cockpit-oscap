/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * React hooks shared across the application.  (Cockpit's own hooks live in
 * pkg/lib/hooks.ts and are imported as "hooks".)
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { DependencyList } from "react";

import { useEvent, useFileWithError } from "hooks";
import { superuser } from "superuser";

import { SCAN_STATE_PATH } from "./api";
import { errorMessage } from "./helpers";
import type { ScanState } from "./types";

export interface AsyncState<T> {
    data: T | null;
    error: string | null;
    loading: boolean;
    reload: () => void;
    /** Replace the loaded data locally (e.g. after an optimistic update). */
    setData: (data: T | null | ((prev: T | null) => T | null)) => void;
}

/**
 * Run an asynchronous loader whenever `deps` change, exposing loading/error
 * state and a reload function.  Results from superseded calls are ignored.
 */
export function useAsync<T>(loader: () => Promise<T>, deps: DependencyList): AsyncState<T> {
    const [data, setData] = useState<T | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [loading, setLoading] = useState(true);
    const [generation, setGeneration] = useState(0);
    const latest = useRef(0);

    useEffect(() => {
        const id = ++latest.current;
        setLoading(true);
        loader()
                .then(result => {
                    if (id !== latest.current)
                        return;
                    setData(result);
                    setError(null);
                    setLoading(false);
                })
                .catch((err: unknown) => {
                    if (id !== latest.current)
                        return;
                    setError(errorMessage(err));
                    setLoading(false);
                });
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [...deps, generation]);

    const reload = useCallback(() => setGeneration(g => g + 1), []);
    return useMemo(() => ({ data, error, loading, reload, setData }), [data, error, loading, reload]);
}

/** The live content of scan-state.json, written by the bridge while a scan runs. */
export function useScanState(): ScanState | null {
    // the file does not exist until the first scan; that is not worth a console warning
    const [content] = useFileWithError(SCAN_STATE_PATH, { superuser: "try" }, { log_errors: false });
    return useMemo(() => {
        if (!content)
            return null;
        try {
            const parsed: unknown = JSON.parse(content);
            if (typeof parsed === "object" && parsed !== null && "running" in parsed)
                return parsed as ScanState;
        } catch {
            // partially written file; wait for the next change
        }
        return null;
    }, [content]);
}

/** true/false when known, null while Cockpit is still figuring it out. */
export function useSuperuser(): boolean | null {
    useEvent(superuser, "changed");
    const allowed: unknown = superuser.allowed;
    return typeof allowed === "boolean" ? allowed : null;
}

/** A value that only updates after `delay` ms without changes. */
export function useDebounced<T>(value: T, delay: number): T {
    const [debounced, setDebounced] = useState(value);
    useEffect(() => {
        const timer = window.setTimeout(() => setDebounced(value), delay);
        return () => window.clearTimeout(timer);
    }, [value, delay]);
    return debounced;
}
