# Changelog

All notable changes to cockpit-oscap are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); releases are cut from
annotated tags (see "Releasing" in the README).

## Unreleased

A complete rewrite of the plugin as an end-to-end compliance workflow.

### Added
- Overview with the latest score, the change since the previous scan, a score
  trend, the rules needing attention grouped by severity, and the schedule state.
- Profiles page with per-profile last scores, datastream selection and a
  tailoring editor (rule selection, value editing, a justification per changed
  rule stored as an XCCDF remark, review of unsaved changes, import and export
  of SCAP Workbench tailoring files).
- Scanning from every page with live progress, a remaining-time estimate and a
  banner for scheduled scans; scan results as ARF plus JSON, pruned to a
  configurable count.
- Results history with filtering by profile, bulk deletion, per-rule details on
  demand, filters by result, severity and category, comparison with the
  previous scan, HTML report, ARF and CSV downloads, and deep links to a rule.
- Guided remediation with per-rule risk classification, one fix at a time,
  re-scan to verify, a recorded remediation history per scan, and Bash script
  or Ansible playbook downloads.
- Scheduled scans through a systemd timer with daily, weekly, monthly or custom
  schedules, result retention, and a journal link for failed runs.
- A Cockpit navigation status when the last scan failed or the score is poor.
- Limited-access mode: everything readable, privileged actions explained.
- Bridge unit tests, frontend helper unit tests, a browser integration test,
  an accessibility audit, and CI that builds the tarball and the RPM.
