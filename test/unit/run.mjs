#!/usr/bin/env node
/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Bundle test/unit/*.test.ts with esbuild (cockpit.js replaced by a stub) and
 * run them with node's built-in test runner. No extra dependencies.
 */

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import esbuild from "esbuild";

const root = fileURLToPath(new URL("../..", import.meta.url));
const outdir = path.join(root, "node_modules", ".cache", "oscap-unit-tests");
const entries = fs.readdirSync(path.join(root, "test", "unit"))
        .filter(name => name.endsWith(".test.ts"))
        .map(name => path.join(root, "test", "unit", name));

fs.rmSync(outdir, { recursive: true, force: true });
await esbuild.build({
    entryPoints: entries,
    outdir,
    bundle: true,
    format: "esm",
    platform: "node",
    target: "node18",
    // .mjs: package.json's "type" does not reach into node_modules, where the bundle lives
    outExtension: { ".js": ".mjs" },
    nodePaths: [path.join(root, "pkg", "lib")],
    alias: { cockpit: path.join(root, "test", "unit", "cockpit-stub.ts") },
    logLevel: "warning",
});

const result = spawnSync(process.execPath, ["--test", ...fs.readdirSync(outdir).map(name => path.join(outdir, name))],
                         { stdio: "inherit" });
process.exit(result.status ?? 1);
