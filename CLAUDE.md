# cockpit-oscap

Cockpit plugin for OpenSCAP compliance scanning. Lets administrators run SCAP
profiles, view results, apply remediations, customize tailoring, and schedule
automated scans through the Cockpit web console.

## Directory Structure

```
src/
  oscap-bridge.py     # Python bridge — single script, argv dispatch, JSON stdout (Python 3.9+)
  api.ts              # Typed cockpit.spawn wrappers (run/stream helpers → bridge commands)
  types.ts            # Shared TypeScript types (mirror the bridge TypedDicts)
  helpers.ts          # Pure helpers (score thresholds, labels, downloads, search)
  app-hooks.ts        # useAsync, useScanState (watches scan-state.json), useSuperuser
  app.tsx             # Shell — tabs, scan banner, cockpit.location routing, AppContext
  pages/              # Overview, Profiles, TailoringEditor, Results, ResultDetail, Schedule
  components/         # ScanDialog, RemediationDialog, RuleDetails, labels, states, ConfirmDialog
  app.scss            # Page styles (PatternFly 6 tokens only; light and dark themes)
  manifest.json       # Cockpit manifest — menu entry, keywords, docs, install hints
test-bridge/          # pytest unit tests (synthetic datastream + ARF fixtures, mocked systemctl)
test/                 # Browser integration tests (check-oscap, run in a cockpit test VM)
systemd/              # cockpit-oscap-scan.service + .timer for scheduled scans
packaging/            # RPM spec template, Arch PKGBUILD
.github/workflows/    # ci.yml runs every check below on pull requests
po/                   # i18n (gettext .po files)
```

## Build

```bash
npm install               # Install JS dependencies
make                      # Build dist/ (esbuild, runs build.js)
make devel-install        # Symlink dist/ into ~/.local/share/cockpit/oscap
make devel-uninstall      # Remove the dev symlink
make install PREFIX=/usr  # Page, bridge script and systemd units
```

The Makefile auto-fetches `pkg/lib` and `test/common` from cockpit.git on first
build (see `COCKPIT_REPO_COMMIT` in Makefile).

## Testing

```bash
python3 -m pytest         # Bridge unit tests; an end-to-end scan runs when oscap + SSG content exist
make lint                 # tsc, eslint, stylelint, ruff, mypy
make check                # Browser integration tests (needs VM image)
make codecheck            # Static analysis via test/common/static-code
```

## Quality Requirements

- **Python:** must run on Python 3.9 (RHEL 9). mypy strict, ruff (broad ruleset, see
  pyproject.toml). Keep `src/oscap-bridge.py` under ~120 KB: the frontend passes it as
  a single `python3 -c` argument (`test_cli.py` guards both).
- **TypeScript:** strict mode with `exactOptionalPropertyTypes`, ESLint (cockpit's config)
- **CSS:** stylelint with SCSS config; use PatternFly 6 design tokens, no hard-coded colors

## Architecture

### Python Bridge (`src/oscap-bridge.py`)

Commands (argv[1]): `detect-backend`, `get-config`, `set-config`, `list-profiles`,
`profile-rules`, `rule-info`, `scan`, `list-results`, `get-result`, `delete-result`,
`generate-report`, `generate-fix`, `remediate`, `create-tailoring`, `parse-tailoring`,
`import-tailoring`, `delete-tailoring`, `manage-timer`, `validate-calendar`.

Every command prints one JSON document; errors are `{"error": "..."}` with exit
status 1 (raised as `BridgeError` internally). `scan` and `remediate` stream
`{"type": "progress", ...}` lines and finish with `{"type": "done", "result": ...}`.
`scan` runs `oscap xccdf eval --progress`, holds a lock (`scan.lock`), forwards
SIGTERM to oscap, and keeps `scan-state.json` updated so the UI can show scheduled
scans too. Datastreams are detected from `/etc/os-release` (config override first).
Tailoring writes XCCDF 1.2 files with `<base profile id>_customized` profiles, which
scans use automatically. Remediation generates fixes from the ARF result
(`--result-id`) and runs the selected rule blocks one at a time.

Data persisted in `/var/lib/cockpit-oscap/` (`config.json`, `results/`, `tailoring/`,
`remediation/`, `scan-state.json`).

### Frontend

React + PatternFly 6, reusing cockpit's shared components from `pkg/lib`
(`ListingTable`, `EmptyStatePanel`, `KebabDropdown`, `SimpleSelect`, `dialogs`,
`timeformat`, `superuser`). Routing via `cockpit.location`: `overview`, `profiles`,
`profiles/<id>` (tailoring editor), `results`, `results/<id>`, `schedule`. Scanning is a
dialog available from every tab (the old `scan` route redirects to `overview`).
`AppContext` (`useApp()`) exposes backend info, a `version` counter pages reload on,
`superuser` state and `runScan()`.

### Systemd Timer

`cockpit-oscap-scan.service` + `.timer` — the bridge's `manage-timer` command
enables/disables/configures the timer (drop-in `override.conf`) via `systemctl`.

## Key Design Decisions

- **Python bridge pattern** over D-Bus: simpler to develop/test, no daemon needed.
  Cockpit's `spawn()` handles privilege escalation via polkit.
- **PatternFly 6** and cockpit's `pkg/lib` components for consistency with Cockpit.
- **cockpit.location** routing instead of react-router — avoids extra dependency,
  integrates with Cockpit's URL handling and browser history.
- **Single bridge script** with command dispatch — follows cockpit-starter-kit
  convention, keeps packaging simple (no Python package installation).
- **scan-state.json + file watch** instead of D-Bus for live scan progress: works for
  interactive and scheduled scans alike with no extra services.

## License

LGPL-2.1-or-later
