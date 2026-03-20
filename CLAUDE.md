# cockpit-oscap

Cockpit plugin for OpenSCAP compliance scanning. Lets administrators run SCAP
profiles, view results, apply remediations, customize tailoring, and schedule
automated scans through the Cockpit web console.

## Directory Structure

```
src/
  oscap-bridge.py     # Python bridge — single script, argv dispatch, JSON stdout
  api.ts              # TypeScript spawn wrapper (cockpit.spawn → bridge commands)
  types.ts            # Shared TypeScript types (mirrors bridge JSON shapes)
  app.tsx             # App shell — sidebar nav, cockpit.location routing
  pages/              # One component per route (Overview, Profiles, Scan, Results, Schedule)
  components/         # Shared UI (ScoreCard, RiskBadge, RuleRow)
  manifest.json       # Cockpit manifest — menu entry, conditions (requires oscap)
  index.html          # Entry point
test-bridge/          # pytest unit tests for oscap-bridge.py
test/                 # Browser integration tests (check-application)
systemd/              # cockpit-oscap-scan.service + .timer for scheduled scans
packaging/            # RPM spec template, Arch PKGBUILD
po/                   # i18n (gettext .po files)
```

## Build

```bash
npm install               # Install JS dependencies
make                      # Build dist/ (esbuild, runs build.js)
make devel-install        # Symlink dist/ into ~/.local/share/cockpit/oscap
make devel-uninstall      # Remove the dev symlink
```

The Makefile auto-fetches `pkg/lib` and `test/common` from cockpit.git on first
build (see `COCKPIT_REPO_COMMIT` in Makefile).

## Testing

```bash
pytest                    # Bridge unit tests (test-bridge/)
make check                # Browser integration tests (needs VM image)
make codecheck            # Static analysis via test/common/static-code
```

## Quality Requirements

- **Python:** mypy strict, ruff (broad ruleset — see pyproject.toml), Python 3.11+
- **TypeScript:** strict mode (`tsconfig.json`), ESLint
- **CSS:** stylelint with SCSS config

## Architecture

### Python Bridge (`src/oscap-bridge.py`)

Single script dispatched by `argv[1]`:
`detect-backend`, `list-profiles`, `profile-rules`, `scan`, `generate-fix`,
`apply-fix`, `manage-timer`, `create-tailoring`, `parse-tailoring`.

All commands print JSON to stdout. The frontend calls them via
`cockpit.spawn()` with `superuser: "try"`. Long operations (scan) emit
newline-delimited progress JSON. Data persisted in `/var/lib/cockpit-oscap/`.

### Frontend

React + PatternFly 6. Routing via `cockpit.location` (path-segment based):
`overview`, `profiles`, `profiles/<id>` (tailoring editor), `scan`,
`results`, `results/<id>` (detail view), `schedule`.

The `api.ts` layer wraps every bridge command into a typed async function.

### Systemd Timer

`cockpit-oscap-scan.service` + `.timer` — the bridge's `manage-timer` command
enables/disables/queries the timer via `systemctl`.

## Key Design Decisions

- **Python bridge pattern** over D-Bus: simpler to develop/test, no daemon needed.
  Cockpit's `spawn()` handles privilege escalation via polkit.
- **PatternFly 6** for UI consistency with Cockpit's own pages.
- **cockpit.location** routing instead of react-router — avoids extra dependency,
  integrates with Cockpit's URL handling and browser history.
- **Single bridge script** with command dispatch — follows cockpit-starter-kit
  convention, keeps packaging simple (no Python package installation).

## License

LGPL-2.1-or-later
