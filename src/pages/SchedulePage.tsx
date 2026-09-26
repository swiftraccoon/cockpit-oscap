/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Schedule: the systemd timer that runs unattended scans, the profile it
 * uses and how many results to keep.
 */

import React, { useEffect, useState } from "react";
import { Alert, AlertActionCloseButton } from "@patternfly/react-core/dist/esm/components/Alert/index.js";
import { Button } from "@patternfly/react-core/dist/esm/components/Button/index.js";
import { Card, CardBody, CardFooter, CardHeader, CardTitle } from "@patternfly/react-core/dist/esm/components/Card/index.js";
import {
    DescriptionList,
    DescriptionListDescription,
    DescriptionListGroup,
    DescriptionListTerm,
} from "@patternfly/react-core/dist/esm/components/DescriptionList/index.js";
import { ActionGroup, Form, FormGroup } from "@patternfly/react-core/dist/esm/components/Form/index.js";
import { Label } from "@patternfly/react-core/dist/esm/components/Label/index.js";
import { NumberInput } from "@patternfly/react-core/dist/esm/components/NumberInput/index.js";
import { Switch } from "@patternfly/react-core/dist/esm/components/Switch/index.js";
import { TextInput } from "@patternfly/react-core/dist/esm/components/TextInput/index.js";
import { TimePicker } from "@patternfly/react-core/dist/esm/components/TimePicker/index.js";
import { ToggleGroup, ToggleGroupItem } from "@patternfly/react-core/dist/esm/components/ToggleGroup/index.js";
import { Stack, StackItem } from "@patternfly/react-core/dist/esm/layouts/Stack/index.js";
import cockpit from "cockpit";

import { FormHelper } from "cockpit-components-form-helper";
import { SimpleSelect } from "cockpit-components-simple-select";
import * as timeformat from "timeformat";

import { TIMER_UNIT, getConfig, listProfiles, manageTimer, setConfig, validateCalendar } from "../api";
import { useApp } from "../app";
import { useAsync, useDebounced } from "../app-hooks";
import { TailoredLabel, When } from "../components/labels";
import { ErrorAlert, ErrorState, Loading } from "../components/states";
import { errorMessage, parseTimestamp } from "../helpers";
import type { CalendarCheck, ConfigPatch, ScheduleFrequency, TimerConfig, TimerStatus } from "../types";

const _ = cockpit.gettext;

const WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const DEFAULT_TIME = "03:00";
const DEFAULT_MAX_RESULTS = 30;
const MIN_RESULTS = 1;
const MAX_RESULTS = 500;
const MAX_DAY_OF_MONTH = 28;

interface ParsedCalendar {
    frequency: ScheduleFrequency;
    weekday: string;
    monthday: number;
    time: string;
    calendar: string;
}

/** Localized weekday name for a systemd weekday abbreviation. */
function weekdayName(short: string, style: "long" | "short" = "long"): string {
    const index = WEEKDAYS.indexOf(short);
    if (index < 0)
        return short;
    // 2024-01-01 is a Monday
    const date = new Date(2024, 0, 1 + index, 12);
    return timeformat.formatter({ weekday: style }).format(date);
}

/** Interpret the OnCalendar expression written by the bridge (or the packaged default). */
export function parseCalendar(raw: string): ParsedCalendar {
    const defaults: ParsedCalendar = { frequency: "weekly", weekday: "Mon", monthday: 1, time: DEFAULT_TIME, calendar: raw };
    const spec = raw.trim();
    if (!spec || spec === "weekly")
        return { ...defaults, time: "00:00" };
    if (spec === "daily")
        return { ...defaults, frequency: "daily", time: "00:00" };
    if (spec === "monthly")
        return { ...defaults, frequency: "monthly", time: "00:00" };

    let match = /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun) \*-\*-\* (\d{2}):(\d{2}):\d{2}$/.exec(spec);
    if (match)
        return { ...defaults, frequency: "weekly", weekday: match[1], time: `${match[2]}:${match[3]}` };
    match = /^\*-\*-\* (\d{2}):(\d{2}):\d{2}$/.exec(spec);
    if (match)
        return { ...defaults, frequency: "daily", time: `${match[1]}:${match[2]}` };
    match = /^\*-\*-(\d{2}) (\d{2}):(\d{2}):\d{2}$/.exec(spec);
    if (match)
        return { ...defaults, frequency: "monthly", monthday: parseInt(match[1], 10), time: `${match[2]}:${match[3]}` };
    return { ...defaults, frequency: "custom" };
}

function describeCalendar(raw: string): string {
    const parsed = parseCalendar(raw);
    switch (parsed.frequency) {
    case "daily":
        return cockpit.format(_("Daily at $0"), parsed.time);
    case "weekly":
        return cockpit.format(_("Weekly on $0 at $1"), weekdayName(parsed.weekday), parsed.time);
    case "monthly":
        return cockpit.format(_("Monthly on day $0 at $1"), parsed.monthday, parsed.time);
    default:
        return raw;
    }
}

function timerStateLabel(timer: TimerStatus): React.ReactNode {
    if (!timer.installed)
        return <Label color="grey" isCompact>{_("Not installed")}</Label>;
    if (timer.status === "active")
        return <Label status="success" isCompact>{_("Enabled")}</Label>;
    if (timer.status === "failed")
        return <Label status="danger" isCompact>{_("Failed")}</Label>;
    return <Label color="grey" isCompact>{_("Disabled")}</Label>;
}

function lastOutcome(timer: TimerStatus): React.ReactNode {
    if (timer.service_state === "activating")
        return <Label status="info" isCompact>{_("Running now")}</Label>;
    if (!timer.last_scan_finished)
        return <span className="oscap-muted">{_("No scheduled scan has run yet")}</span>;
    const label = timer.service_result === "success"
        ? <Label status="success" isCompact>{_("Succeeded")}</Label>
        : <Label status="danger" isCompact>{cockpit.format(_("Failed ($0)"), timer.service_result)}</Label>;
    return <>{label} <When iso={timer.last_scan_finished} fallback="" /></>;
}

export const SchedulePage = () => {
    const app = useApp();
    const data = useAsync(async () => {
        const [timer, config, profiles] = await Promise.all([manageTimer("status"), getConfig(), listProfiles()]);
        return { timer, config, profiles };
    }, [app.version]);

    const [timer, setTimer] = useState<TimerStatus | null>(null);
    const [frequency, setFrequency] = useState<ScheduleFrequency>("weekly");
    const [weekday, setWeekday] = useState("Mon");
    const [monthday, setMonthday] = useState(1);
    const [time, setTime] = useState(DEFAULT_TIME);
    const [calendar, setCalendar] = useState("");
    const [profileId, setProfileId] = useState("");
    const [maxResults, setMaxResults] = useState(DEFAULT_MAX_RESULTS);
    const [calendarCheck, setCalendarCheck] = useState<CalendarCheck | null>(null);
    const [toggling, setToggling] = useState(false);
    const [saving, setSaving] = useState(false);
    const [notice, setNotice] = useState<string | null>(null);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        if (!data.data)
            return;
        const { timer: status, config, profiles } = data.data;
        const parsed = parseCalendar(status.calendar);
        setTimer(status);
        setFrequency(parsed.frequency);
        setWeekday(parsed.weekday);
        setMonthday(parsed.monthday);
        setTime(parsed.time);
        setCalendar(parsed.frequency === "custom" ? status.calendar : "");
        setMaxResults(config.max_results ?? DEFAULT_MAX_RESULTS);
        const active = config.active_profile;
        setProfileId(active && profiles.some(p => p.id === active) ? active : (profiles[0]?.id ?? ""));
    }, [data.data]);

    const debouncedCalendar = useDebounced(calendar, 400);
    useEffect(() => {
        if (frequency !== "custom" || !debouncedCalendar.trim()) {
            setCalendarCheck(null);
            return undefined;
        }
        let cancelled = false;
        validateCalendar(debouncedCalendar)
                .then(check => { if (!cancelled) setCalendarCheck(check); })
                .catch(() => { if (!cancelled) setCalendarCheck(null); });
        return () => { cancelled = true };
    }, [debouncedCalendar, frequency]);

    if (data.error)
        return <ErrorState title={_("Failed to load the schedule")} error={data.error} onRetry={() => data.reload()} />;
    if (!data.data || !timer)
        return <Loading />;

    const { profiles, config: savedConfig } = data.data;
    const installed = timer.installed;
    const readOnly = app.superuser === false;
    const activeProfile = profiles.find(p => p.id === savedConfig.active_profile);
    const customInvalid = frequency === "custom" && (!calendar.trim() || (calendarCheck !== null && !calendarCheck.valid));

    async function toggle(enabled: boolean) {
        setToggling(true);
        setError(null);
        try {
            setTimer(await manageTimer(enabled ? "enable" : "disable"));
        } catch (err) {
            setError(errorMessage(err));
        } finally {
            setToggling(false);
        }
    }

    async function save() {
        setSaving(true);
        setError(null);
        setNotice(null);
        const config: TimerConfig = { frequency, time, ...profileId && { profile_id: profileId } };
        if (frequency === "weekly")
            config.day = weekday;
        else if (frequency === "monthly")
            config.day = String(monthday);
        else if (frequency === "custom")
            config.calendar = calendar.trim();
        try {
            // Retention and the active profile are plain settings; only the calendar needs the timer unit.
            const patch: ConfigPatch = {};
            if (maxResults !== (savedConfig.max_results ?? DEFAULT_MAX_RESULTS))
                patch.max_results = maxResults;
            if (!installed && profileId && profileId !== savedConfig.active_profile)
                patch.active_profile = profileId;
            if (Object.keys(patch).length > 0)
                await setConfig(patch);
            if (installed)
                setTimer(await manageTimer("configure", config));
            setNotice(installed ? _("Schedule saved.") : _("Settings saved."));
            app.bump();
        } catch (err) {
            setError(errorMessage(err));
        } finally {
            setSaving(false);
        }
    }

    async function runNow() {
        setError(null);
        setNotice(null);
        try {
            setTimer(await manageTimer("run-now"));
            setNotice(_("A scheduled scan was started; progress is shown at the top of the page."));
        } catch (err) {
            setError(errorMessage(err));
        }
    }

    return (
        <Stack hasGutter>
            {!timer.installed && (
                <StackItem>
                    <Alert variant="warning" isInline title={_("The scheduled scan timer is not installed")}>
                        {cockpit.format(_("The systemd units $0 and cockpit-oscap-scan.service were not found. They are installed by the cockpit-oscap package; a development checkout linked with make devel-install does not include them."), TIMER_UNIT)}
                    </Alert>
                </StackItem>
            )}
            {notice && (
                <StackItem>
                    <Alert
variant="success" isInline title={notice}
                           actionClose={<AlertActionCloseButton onClose={() => setNotice(null)} />}
                    />
                </StackItem>
            )}
            {error && (
                <StackItem>
                    <ErrorAlert title={_("Operation failed")} error={error} onDismiss={() => setError(null)} />
                </StackItem>
            )}
            <StackItem>
                <Card className="ct-card" id="schedule-status">
                    <CardHeader
                        actions={{
                            actions: (
                                <Switch
                                    id="schedule-enabled"
                                    label={_("Enabled")}
                                    isChecked={timer.status === "active"}
                                    isDisabled={!timer.installed || readOnly || toggling}
                                    onChange={(_ev, checked) => toggle(checked)}
                                />
                            ),
                            hasNoOffset: true,
                        }}
                    >
                        <CardTitle>{_("Scheduled scanning")}</CardTitle>
                    </CardHeader>
                    <CardBody>
                        <DescriptionList isHorizontal isCompact horizontalTermWidthModifier={{ default: "16ch" }}>
                            <DescriptionListGroup>
                                <DescriptionListTerm>{_("Status")}</DescriptionListTerm>
                                <DescriptionListDescription>{timerStateLabel(timer)}</DescriptionListDescription>
                            </DescriptionListGroup>
                            <DescriptionListGroup>
                                <DescriptionListTerm>{_("Schedule")}</DescriptionListTerm>
                                <DescriptionListDescription>
                                    {timer.installed ? describeCalendar(timer.calendar) : "—"}
                                </DescriptionListDescription>
                            </DescriptionListGroup>
                            <DescriptionListGroup>
                                <DescriptionListTerm>{_("Next run")}</DescriptionListTerm>
                                <DescriptionListDescription>
                                    {timer.status === "active"
                                        ? <When iso={timer.next_run} fallback={_("Not scheduled")} />
                                        : <span className="oscap-muted">{_("Scheduled scanning is disabled")}</span>}
                                </DescriptionListDescription>
                            </DescriptionListGroup>
                            <DescriptionListGroup>
                                <DescriptionListTerm>{_("Last run")}</DescriptionListTerm>
                                <DescriptionListDescription>{lastOutcome(timer)}</DescriptionListDescription>
                            </DescriptionListGroup>
                            <DescriptionListGroup>
                                <DescriptionListTerm>{_("Profile")}</DescriptionListTerm>
                                <DescriptionListDescription>
                                    {activeProfile
                                        ? <>{activeProfile.title}{activeProfile.tailoring_path && <> {" "}<TailoredLabel /></>}</>
                                        : <span className="oscap-muted">{_("No active profile")}</span>}
                                </DescriptionListDescription>
                            </DescriptionListGroup>
                        </DescriptionList>
                    </CardBody>
                    <CardFooter className="oscap-card-actions">
                        <Button
id="schedule-run-now" variant="secondary" size="sm" onClick={runNow}
                                isDisabled={!installed || !activeProfile || readOnly || app.scanning}
                        >
                            {_("Run scheduled scan now")}
                        </Button>
                        <Button variant="link" isInline onClick={() => cockpit.jump(`/system/services#/${TIMER_UNIT}`)}>
                            {_("View timer in Services")}
                        </Button>
                    </CardFooter>
                </Card>
            </StackItem>
            <StackItem>
                <Card className="ct-card" id="schedule-form">
                    <CardTitle>{_("Schedule")}</CardTitle>
                    <CardBody>
                        <Form isHorizontal onSubmit={ev => { ev.preventDefault(); save() }}>
                            <FormGroup label={_("Frequency")} fieldId="schedule-frequency">
                                <ToggleGroup aria-label={_("Frequency")}>
                                    {(["daily", "weekly", "monthly", "custom"] as ScheduleFrequency[]).map(value => (
                                        <ToggleGroupItem
                                            key={value}
                                            buttonId={`schedule-frequency-${value}`}
                                            text={{ daily: _("Daily"), weekly: _("Weekly"), monthly: _("Monthly"), custom: _("Custom") }[value]}
                                            isSelected={frequency === value}
                                            isDisabled={readOnly}
                                            onChange={() => setFrequency(value)}
                                        />
                                    ))}
                                </ToggleGroup>
                            </FormGroup>
                            {frequency === "weekly" && (
                                <FormGroup label={_("Day")} fieldId="schedule-weekday">
                                    <ToggleGroup aria-label={_("Day of week")}>
                                        {WEEKDAYS.map(day => (
                                            <ToggleGroupItem
                                                key={day}
                                                buttonId={`schedule-weekday-${day}`}
                                                text={weekdayName(day, "short")}
                                                isSelected={weekday === day}
                                                isDisabled={readOnly}
                                                onChange={() => setWeekday(day)}
                                            />
                                        ))}
                                    </ToggleGroup>
                                </FormGroup>
                            )}
                            {frequency === "monthly" && (
                                <FormGroup label={_("Day of month")} fieldId="schedule-monthday">
                                    <NumberInput
                                        id="schedule-monthday"
                                        value={monthday}
                                        min={1}
                                        max={MAX_DAY_OF_MONTH}
                                        isDisabled={readOnly}
                                        inputAriaLabel={_("Day of month")}
                                        onMinus={() => setMonthday(d => Math.max(1, d - 1))}
                                        onPlus={() => setMonthday(d => Math.min(MAX_DAY_OF_MONTH, d + 1))}
                                        onChange={ev => {
                                            const value = parseInt((ev.target as HTMLInputElement).value, 10);
                                            if (!Number.isNaN(value))
                                                setMonthday(Math.min(MAX_DAY_OF_MONTH, Math.max(1, value)));
                                        }}
                                        widthChars={3}
                                    />
                                    <FormHelper helperText={_("Days 29 to 31 are not offered so the scan runs every month.")} />
                                </FormGroup>
                            )}
                            {frequency !== "custom" && (
                                <FormGroup label={_("Time")} fieldId="schedule-time">
                                    <TimePicker
                                        id="schedule-time"
                                        time={time}
                                        is24Hour
                                        isDisabled={readOnly}
                                        onChange={(_ev, _value, hour, minute, _seconds, isValid) => {
                                            if (isValid && hour !== undefined && minute !== undefined)
                                                setTime(`${String(hour).padStart(2, "0")}:${String(minute).padStart(2, "0")}`);
                                        }}
                                    />
                                    <FormHelper helperText={_("Local time. systemd adds a random delay of up to one hour to spread load.")} />
                                </FormGroup>
                            )}
                            {frequency === "custom" && (
                                <FormGroup label={_("Calendar expression")} fieldId="schedule-calendar" isRequired>
                                    <TextInput
                                        id="schedule-calendar"
                                        value={calendar}
                                        isDisabled={readOnly}
                                        validated={customInvalid && calendar.trim() ? "error" : "default"}
                                        placeholder="Sat *-*-* 04:00:00"
                                        onChange={(_ev, value) => setCalendar(value)}
                                    />
                                    <FormHelper
                                        fieldId="schedule-calendar"
                                        helperText={calendarCheck?.valid && calendarCheck.next_elapse
                                            ? cockpit.format(_("Next run: $0. Uses systemd calendar syntax (see systemd.time(7))."),
                                                             timeformat.dateTime(parseTimestamp(calendarCheck.next_elapse) ?? new Date()))
                                            : _("Uses systemd calendar syntax, for example \"Sat *-*-* 04:00:00\" or \"*-*-01,15 03:00\" (see systemd.time(7)).")}
                                        helperTextInvalid={calendarCheck && !calendarCheck.valid ? calendarCheck.error : undefined}
                                    />
                                </FormGroup>
                            )}
                            <FormGroup label={_("Profile")} fieldId="schedule-profile">
                                <SimpleSelect
                                    toggleProps={{ id: "schedule-profile", isFullWidth: true }}
                                    options={profiles.map(p => ({ value: p.id, content: p.title }))}
                                    selected={profileId}
                                    onSelect={value => setProfileId(value)}
                                    isDisabled={readOnly}
                                    placeholder={_("Select a profile")}
                                />
                                <FormHelper helperText={_("Scheduled scans use this profile together with its saved customizations. It also becomes the active profile.")} />
                            </FormGroup>
                            <FormGroup label={_("Keep results")} fieldId="schedule-retention">
                                <NumberInput
                                    id="schedule-retention"
                                    value={maxResults}
                                    min={MIN_RESULTS}
                                    max={MAX_RESULTS}
                                    unit={_("scans")}
                                    isDisabled={readOnly}
                                    inputAriaLabel={_("Number of scan results to keep")}
                                    onMinus={() => setMaxResults(n => Math.max(MIN_RESULTS, n - 1))}
                                    onPlus={() => setMaxResults(n => Math.min(MAX_RESULTS, n + 1))}
                                    onChange={ev => {
                                        const value = parseInt((ev.target as HTMLInputElement).value, 10);
                                        if (!Number.isNaN(value))
                                            setMaxResults(Math.min(MAX_RESULTS, Math.max(MIN_RESULTS, value)));
                                    }}
                                    widthChars={4}
                                />
                                <FormHelper helperText={_("Older scan results and their reports are deleted automatically after each scan.")} />
                            </FormGroup>
                            <ActionGroup>
                                <Button
id="schedule-save" variant="primary" type="submit" isLoading={saving}
                                        isDisabled={saving || readOnly || (installed && customInvalid)}
                                >
                                    {_("Save")}
                                </Button>
                            </ActionGroup>
                        </Form>
                    </CardBody>
                </Card>
            </StackItem>
        </Stack>
    );
};
