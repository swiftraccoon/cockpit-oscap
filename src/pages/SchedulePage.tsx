import React, { useEffect, useRef, useState } from "react";
import { Alert } from "@patternfly/react-core/dist/esm/components/Alert/index.js";
import { Button } from "@patternfly/react-core/dist/esm/components/Button/index.js";
import { Card, CardBody, CardTitle } from "@patternfly/react-core/dist/esm/components/Card/index.js";
import {
    DescriptionList,
    DescriptionListDescription,
    DescriptionListGroup,
    DescriptionListTerm,
} from "@patternfly/react-core/dist/esm/components/DescriptionList/index.js";
import {
    Form,
    FormGroup,
    ActionGroup,
} from "@patternfly/react-core/dist/esm/components/Form/index.js";
import { Label } from "@patternfly/react-core/dist/esm/components/Label/index.js";
import { MenuToggle } from "@patternfly/react-core/dist/esm/components/MenuToggle/index.js";
import { NumberInput } from "@patternfly/react-core/dist/esm/components/NumberInput/index.js";
import { PageSection } from "@patternfly/react-core/dist/esm/components/Page/index.js";
import { Select, SelectList, SelectOption } from "@patternfly/react-core/dist/esm/components/Select/index.js";
import { Spinner } from "@patternfly/react-core/dist/esm/components/Spinner/index.js";
import { Switch } from "@patternfly/react-core/dist/esm/components/Switch/index.js";
import { TextInput } from "@patternfly/react-core/dist/esm/components/TextInput/index.js";
import {
    ToggleGroup,
    ToggleGroupItem,
} from "@patternfly/react-core/dist/esm/components/ToggleGroup/index.js";
import { Flex, FlexItem } from "@patternfly/react-core/dist/esm/layouts/Flex/index.js";
import cockpit from "cockpit";

import { listProfiles, loadConfig, manageTimer } from "../api";
import type { Config, ProfileInfo, TimerStatus } from "../types";

const _ = cockpit.gettext;

/** Frequency options for the schedule picker. */
type Frequency = "daily" | "weekly" | "monthly" | "custom";

/** Days of the week for the weekly frequency picker. */
const WEEKDAYS: { label: string; value: string }[] = [
    { label: "Mon", value: "Mon" },
    { label: "Tue", value: "Tue" },
    { label: "Wed", value: "Wed" },
    { label: "Thu", value: "Thu" },
    { label: "Fri", value: "Fri" },
    { label: "Sat", value: "Sat" },
    { label: "Sun", value: "Sun" },
];

/** Map timer status string to a PatternFly Label color. */
function statusColor(status: string): "green" | "red" | "grey" | "blue" {
    if (status === "active") return "green";
    if (status === "not-found") return "grey";
    if (status === "inactive") return "red";
    return "blue";
}

/** Map timer status string to a human-readable label. */
function statusLabel(status: string): string {
    switch (status) {
    case "active":
        return _("Active");
    case "inactive":
        return _("Inactive");
    case "not-found":
        return _("Not installed");
    case "activating":
        return _("Activating");
    case "running":
        return _("Running");
    default:
        return status;
    }
}

/** Parse a frequency string from the bridge into a Frequency category. */
function parseFrequency(raw: string): { frequency: Frequency; day: string; hour: string; minute: string } {
    const defaults = { frequency: "weekly" as Frequency, day: "Mon", hour: "03", minute: "00" };

    if (!raw || raw === "weekly") return defaults;
    if (raw === "daily") return { ...defaults, frequency: "daily" };
    if (raw === "monthly") return { ...defaults, frequency: "monthly" };

    // Try to parse systemd calendar spec like "Mon *-*-* 03:00:00" or "*-*-* 03:00:00"
    // or "*-*-1 03:00:00" (monthly day 1)
    const weekdayMatch = raw.match(/^(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s/i);
    const timeMatch = raw.match(/(\d{1,2}):(\d{2})/);
    const monthDayMatch = raw.match(/\*-\*-(\d{1,2})/);

    if (weekdayMatch && timeMatch) {
        return {
            frequency: "weekly",
            day: weekdayMatch[1],
            hour: timeMatch[1].padStart(2, "0"),
            minute: timeMatch[2],
        };
    }

    if (monthDayMatch && timeMatch) {
        return {
            frequency: "monthly",
            day: monthDayMatch[1],
            hour: timeMatch[1].padStart(2, "0"),
            minute: timeMatch[2],
        };
    }

    if (timeMatch) {
        return {
            frequency: "daily",
            day: defaults.day,
            hour: timeMatch[1].padStart(2, "0"),
            minute: timeMatch[2],
        };
    }

    // Unrecognised — show as custom
    return { ...defaults, frequency: "custom" };
}

export const SchedulePage: React.FunctionComponent = () => {
    /* ------------------------------------------------------------------ */
    /* State                                                              */
    /* ------------------------------------------------------------------ */
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [saving, setSaving] = useState(false);
    const [saveSuccess, setSaveSuccess] = useState(false);
    const [saveError, setSaveError] = useState<string | null>(null);

    const [timerStatus, setTimerStatus] = useState<TimerStatus | null>(null);
    const [profiles, setProfiles] = useState<ProfileInfo[]>([]);
    const [config, setConfig] = useState<Config>({});

    // Form state
    const [enabled, setEnabled] = useState(false);
    const [frequency, setFrequency] = useState<Frequency>("weekly");
    const [freqSelectOpen, setFreqSelectOpen] = useState(false);
    const [dayOfWeek, setDayOfWeek] = useState("Mon");
    const [dayOfMonth, setDayOfMonth] = useState(1);
    const [hour, setHour] = useState("03");
    const [minute, setMinute] = useState("00");
    const [selectedProfile, setSelectedProfile] = useState("");
    const [profileSelectOpen, setProfileSelectOpen] = useState(false);

    const freqToggleRef = useRef<HTMLButtonElement>(null);
    const profileToggleRef = useRef<HTMLButtonElement>(null);

    /* ------------------------------------------------------------------ */
    /* Initialisation                                                     */
    /* ------------------------------------------------------------------ */
    useEffect(() => {
        let cancelled = false;

        async function init() {
            try {
                const [status, profileList, configData] = await Promise.all([
                    manageTimer("status"),
                    listProfiles(),
                    loadConfig(),
                ]);
                if (cancelled) return;

                setTimerStatus(status);
                setProfiles(profileList);
                setConfig(configData);

                // Derive form state from timer status
                setEnabled(status.status === "active");

                const parsed = parseFrequency(status.frequency);
                setFrequency(parsed.frequency);
                setDayOfWeek(parsed.day);
                setHour(parsed.hour);
                setMinute(parsed.minute);

                if (parsed.frequency === "monthly") {
                    const dayNum = parseInt(parsed.day, 10);
                    if (!isNaN(dayNum) && dayNum >= 1 && dayNum <= 28) {
                        setDayOfMonth(dayNum);
                    }
                }

                // Default profile selection
                const activeId = configData.active_profile;
                if (activeId && profileList.some(p => p.id === activeId)) {
                    setSelectedProfile(activeId);
                } else if (profileList.length > 0) {
                    setSelectedProfile(profileList[0].id);
                }
            } catch (err) {
                if (cancelled) return;
                setError(String(err));
            } finally {
                if (!cancelled) setLoading(false);
            }
        }

        init();
        return () => { cancelled = true };
    }, []);

    /* ------------------------------------------------------------------ */
    /* Helpers                                                            */
    /* ------------------------------------------------------------------ */

    /** Find the title for a profile id. */
    function profileTitle(id: string): string {
        const match = profiles.find(p => p.id === id);
        return match ? match.title : id;
    }

    /* ------------------------------------------------------------------ */
    /* Event handlers                                                     */
    /* ------------------------------------------------------------------ */

    /** Toggle the timer on/off. */
    async function onToggleEnabled(_event: React.FormEvent, checked: boolean) {
        setSaveError(null);
        setSaveSuccess(false);
        try {
            const action = checked ? "enable" : "disable";
            const status = await manageTimer(action);
            setTimerStatus(status);
            setEnabled(status.status === "active");
        } catch (err) {
            setSaveError(cockpit.format(_("Failed to $0 timer: $1"), checked ? _("enable") : _("disable"), String(err)));
        }
    }

    /** Save the schedule configuration. */
    async function onSave() {
        setSaving(true);
        setSaveError(null);
        setSaveSuccess(false);

        try {
            const timerConfig: { frequency?: string; day?: string; time?: string; profile_id?: string } = {
                frequency,
                time: `${hour}:${minute}`,
            };

            if (selectedProfile) {
                timerConfig.profile_id = selectedProfile;
            }

            if (frequency === "weekly") {
                timerConfig.day = dayOfWeek;
            } else if (frequency === "monthly") {
                timerConfig.day = String(dayOfMonth);
            }

            const status = await manageTimer("configure", timerConfig);
            setTimerStatus(status);
            setSaveSuccess(true);
        } catch (err) {
            setSaveError(cockpit.format(_("Failed to save schedule: $0"), String(err)));
        } finally {
            setSaving(false);
        }
    }

    function onFreqSelect(
        _event: React.MouseEvent<Element, MouseEvent> | undefined,
        value: string | number | undefined,
    ) {
        if (value !== undefined) {
            setFrequency(value as Frequency);
        }
        setFreqSelectOpen(false);
    }

    function onProfileSelect(
        _event: React.MouseEvent<Element, MouseEvent> | undefined,
        value: string | number | undefined,
    ) {
        if (value !== undefined) {
            setSelectedProfile(String(value));
        }
        setProfileSelectOpen(false);
    }

    /** Clamp hour input to 00-23. */
    function onHourChange(_event: React.FormEvent, val: string) {
        const cleaned = val.replace(/\D/g, "").slice(0, 2);
        const num = parseInt(cleaned, 10);
        if (cleaned === "" || isNaN(num)) {
            setHour("");
            return;
        }
        if (num > 23) {
            setHour("23");
        } else {
            setHour(cleaned);
        }
    }

    /** Clamp minute input to 00-59. */
    function onMinuteChange(_event: React.FormEvent, val: string) {
        const cleaned = val.replace(/\D/g, "").slice(0, 2);
        const num = parseInt(cleaned, 10);
        if (cleaned === "" || isNaN(num)) {
            setMinute("");
            return;
        }
        if (num > 59) {
            setMinute("59");
        } else {
            setMinute(cleaned);
        }
    }

    /** Pad the hour/minute on blur for display consistency. */
    function onHourBlur() {
        if (hour === "") setHour("00");
        else setHour(hour.padStart(2, "0"));
    }

    function onMinuteBlur() {
        if (minute === "") setMinute("00");
        else setMinute(minute.padStart(2, "0"));
    }

    /** Navigate to systemd Services page for the timer unit. */
    function onViewInServices() {
        cockpit.jump("/system/services#/cockpit-oscap-scan.timer");
    }

    /* ------------------------------------------------------------------ */
    /* Loading state                                                      */
    /* ------------------------------------------------------------------ */
    if (loading) {
        return (
            <PageSection>
                <Flex justifyContent={{ default: "justifyContentCenter" }}>
                    <FlexItem>
                        <Spinner size="xl" aria-label={_("Loading")} />
                    </FlexItem>
                </Flex>
            </PageSection>
        );
    }

    /* ------------------------------------------------------------------ */
    /* Error state                                                        */
    /* ------------------------------------------------------------------ */
    if (error) {
        return (
            <PageSection>
                <Alert variant="danger" title={_("Failed to load schedule configuration")}>
                    {error}
                </Alert>
            </PageSection>
        );
    }

    /* ------------------------------------------------------------------ */
    /* Frequency label for the dropdown toggle                            */
    /* ------------------------------------------------------------------ */
    const frequencyLabels: Record<Frequency, string> = {
        daily: _("Daily"),
        weekly: _("Weekly"),
        monthly: _("Monthly"),
        custom: _("Custom"),
    };

    /* ------------------------------------------------------------------ */
    /* Render                                                             */
    /* ------------------------------------------------------------------ */
    return (
        <PageSection>
            {/* Timer status card */}
            <Card style={{ marginBottom: "var(--pf-t--global--spacer--md)" }}>
                <CardTitle>{_("Timer Status")}</CardTitle>
                <CardBody>
                    <DescriptionList isHorizontal isCompact>
                        <DescriptionListGroup>
                            <DescriptionListTerm>{_("Status")}</DescriptionListTerm>
                            <DescriptionListDescription>
                                <Label color={statusColor(timerStatus?.status ?? "unknown")} isCompact>
                                    {statusLabel(timerStatus?.status ?? "unknown")}
                                </Label>
                            </DescriptionListDescription>
                        </DescriptionListGroup>
                        <DescriptionListGroup>
                            <DescriptionListTerm>{_("Next run")}</DescriptionListTerm>
                            <DescriptionListDescription>
                                {timerStatus?.next_run || _("Not scheduled")}
                            </DescriptionListDescription>
                        </DescriptionListGroup>
                        <DescriptionListGroup>
                            <DescriptionListTerm>{_("Frequency")}</DescriptionListTerm>
                            <DescriptionListDescription>
                                {timerStatus?.frequency || _("Not configured")}
                            </DescriptionListDescription>
                        </DescriptionListGroup>
                        {config.active_profile && (
                            <DescriptionListGroup>
                                <DescriptionListTerm>{_("Active profile")}</DescriptionListTerm>
                                <DescriptionListDescription>
                                    {profileTitle(config.active_profile)}
                                </DescriptionListDescription>
                            </DescriptionListGroup>
                        )}
                    </DescriptionList>

                    <Button
                        variant="link"
                        isInline
                        onClick={onViewInServices}
                        style={{ marginTop: "var(--pf-t--global--spacer--sm)" }}
                    >
                        {_("View in Services")}
                    </Button>
                </CardBody>
            </Card>

            {/* Schedule configuration card */}
            <Card>
                <CardTitle>{_("Schedule Configuration")}</CardTitle>
                <CardBody>
                    {/* Save feedback alerts */}
                    {saveSuccess && (
                        <Alert
                            variant="success"
                            isInline
                            title={_("Schedule saved successfully")}
                            style={{ marginBottom: "var(--pf-t--global--spacer--md)" }}
                        />
                    )}
                    {saveError && (
                        <Alert
                            variant="danger"
                            isInline
                            title={_("Error")}
                            style={{ marginBottom: "var(--pf-t--global--spacer--md)" }}
                        >
                            {saveError}
                        </Alert>
                    )}

                    <Form isHorizontal>
                        {/* Enable/disable toggle */}
                        <FormGroup
                            label={_("Scheduled scanning")}
                            fieldId="timer-enabled"
                        >
                            <Switch
                                id="timer-enabled"
                                label={_("Enabled")}
                                isChecked={enabled}
                                onChange={onToggleEnabled}
                                isDisabled={timerStatus?.status === "not-found"}
                            />
                        </FormGroup>

                        {/* Frequency picker */}
                        <FormGroup
                            label={_("Frequency")}
                            fieldId="schedule-frequency"
                        >
                            <div style={{ maxWidth: "240px" }}>
                                <Select
                                    id="schedule-frequency"
                                    isOpen={freqSelectOpen}
                                    selected={frequency}
                                    onSelect={onFreqSelect}
                                    onOpenChange={isOpen => setFreqSelectOpen(isOpen)}
                                    toggle={toggleNode => (
                                        <MenuToggle
                                            ref={freqToggleRef}
                                            onClick={() => setFreqSelectOpen(prev => !prev)}
                                            isExpanded={freqSelectOpen}
                                            isFullWidth
                                            {...toggleNode}
                                        >
                                            {frequencyLabels[frequency]}
                                        </MenuToggle>
                                    )}
                                    popperProps={{ width: "trigger" }}
                                >
                                    <SelectList>
                                        <SelectOption value="daily" isSelected={frequency === "daily"}>
                                            {_("Daily")}
                                        </SelectOption>
                                        <SelectOption value="weekly" isSelected={frequency === "weekly"}>
                                            {_("Weekly")}
                                        </SelectOption>
                                        <SelectOption value="monthly" isSelected={frequency === "monthly"}>
                                            {_("Monthly")}
                                        </SelectOption>
                                        <SelectOption value="custom" isSelected={frequency === "custom"}>
                                            {_("Custom")}
                                        </SelectOption>
                                    </SelectList>
                                </Select>
                            </div>
                        </FormGroup>

                        {/* Day-of-week selector (weekly only) */}
                        {frequency === "weekly" && (
                            <FormGroup
                                label={_("Day of week")}
                                fieldId="schedule-day-of-week"
                            >
                                <ToggleGroup aria-label={_("Day of week")}>
                                    {WEEKDAYS.map(d => (
                                        <ToggleGroupItem
                                            key={d.value}
                                            text={_(d.label)}
                                            buttonId={`day-${d.value}`}
                                            isSelected={dayOfWeek === d.value}
                                            onChange={() => setDayOfWeek(d.value)}
                                        />
                                    ))}
                                </ToggleGroup>
                            </FormGroup>
                        )}

                        {/* Day-of-month selector (monthly only) */}
                        {frequency === "monthly" && (
                            <FormGroup
                                label={_("Day of month")}
                                fieldId="schedule-day-of-month"
                            >
                                <NumberInput
                                    id="schedule-day-of-month"
                                    value={dayOfMonth}
                                    min={1}
                                    max={28}
                                    onMinus={() => setDayOfMonth(prev => Math.max(1, prev - 1))}
                                    onPlus={() => setDayOfMonth(prev => Math.min(28, prev + 1))}
                                    onChange={event => {
                                        const val = parseInt((event.target as HTMLInputElement).value, 10);
                                        if (!isNaN(val) && val >= 1 && val <= 28) {
                                            setDayOfMonth(val);
                                        }
                                    }}
                                    widthChars={3}
                                />
                            </FormGroup>
                        )}

                        {/* Time picker */}
                        {frequency !== "custom" && (
                            <FormGroup
                                label={_("Time")}
                                fieldId="schedule-hour"
                            >
                                <Flex
                                    spaceItems={{ default: "spaceItemsSm" }}
                                    alignItems={{ default: "alignItemsCenter" }}
                                >
                                    <FlexItem>
                                        <TextInput
                                            id="schedule-hour"
                                            value={hour}
                                            onChange={onHourChange}
                                            onBlur={onHourBlur}
                                            aria-label={_("Hour (00-23)")}
                                            placeholder="HH"
                                            style={{ width: "60px", textAlign: "center" }}
                                        />
                                    </FlexItem>
                                    <FlexItem>:</FlexItem>
                                    <FlexItem>
                                        <TextInput
                                            id="schedule-minute"
                                            value={minute}
                                            onChange={onMinuteChange}
                                            onBlur={onMinuteBlur}
                                            aria-label={_("Minute (00-59)")}
                                            placeholder="MM"
                                            style={{ width: "60px", textAlign: "center" }}
                                        />
                                    </FlexItem>
                                </Flex>
                            </FormGroup>
                        )}

                        {/* Profile selector */}
                        {profiles.length > 0 && (
                            <FormGroup
                                label={_("Scan profile")}
                                fieldId="schedule-profile"
                            >
                                <div style={{ maxWidth: "480px" }}>
                                    <Select
                                        id="schedule-profile"
                                        isOpen={profileSelectOpen}
                                        selected={selectedProfile}
                                        onSelect={onProfileSelect}
                                        onOpenChange={isOpen => setProfileSelectOpen(isOpen)}
                                        toggle={toggleNode => (
                                            <MenuToggle
                                                ref={profileToggleRef}
                                                onClick={() => setProfileSelectOpen(prev => !prev)}
                                                isExpanded={profileSelectOpen}
                                                isFullWidth
                                                {...toggleNode}
                                            >
                                                {profileTitle(selectedProfile)}
                                            </MenuToggle>
                                        )}
                                        popperProps={{ width: "trigger" }}
                                    >
                                        <SelectList>
                                            {profiles.map(profile => (
                                                <SelectOption
                                                    key={profile.id}
                                                    value={profile.id}
                                                    isSelected={profile.id === selectedProfile}
                                                    description={cockpit.format(_("$0 rules"), profile.rule_count)}
                                                >
                                                    {profile.title}
                                                </SelectOption>
                                            ))}
                                        </SelectList>
                                    </Select>
                                </div>
                            </FormGroup>
                        )}

                        {/* Save button */}
                        <ActionGroup>
                            <Button
                                variant="primary"
                                onClick={onSave}
                                isLoading={saving}
                                isDisabled={saving || timerStatus?.status === "not-found"}
                            >
                                {_("Save")}
                            </Button>
                        </ActionGroup>
                    </Form>
                </CardBody>
            </Card>
        </PageSection>
    );
};
