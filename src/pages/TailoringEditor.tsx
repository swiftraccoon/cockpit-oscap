import React, { useEffect, useRef, useState } from "react";
import { Alert } from "@patternfly/react-core/dist/esm/components/Alert/index.js";
import { Button } from "@patternfly/react-core/dist/esm/components/Button/index.js";
import { Card, CardBody } from "@patternfly/react-core/dist/esm/components/Card/index.js";
import { Content, ContentVariants } from "@patternfly/react-core/dist/esm/components/Content/index.js";
import { ExpandableSection } from "@patternfly/react-core/dist/esm/components/ExpandableSection/index.js";
import { Label } from "@patternfly/react-core/dist/esm/components/Label/index.js";
import { MenuToggle } from "@patternfly/react-core/dist/esm/components/MenuToggle/index.js";
import { PageSection } from "@patternfly/react-core/dist/esm/components/Page/index.js";
import { Select, SelectList, SelectOption } from "@patternfly/react-core/dist/esm/components/Select/index.js";
import { Spinner } from "@patternfly/react-core/dist/esm/components/Spinner/index.js";
import { TextInput } from "@patternfly/react-core/dist/esm/components/TextInput/index.js";
import {
    Toolbar,
    ToolbarContent,
    ToolbarItem,
} from "@patternfly/react-core/dist/esm/components/Toolbar/index.js";
import { Flex, FlexItem } from "@patternfly/react-core/dist/esm/layouts/Flex/index.js";
import cockpit from "cockpit";

import { createTailoring, loadConfig, parseTailoring, profileRules } from "../api";
import { RuleRow } from "../components/RuleRow.jsx";
import type { Config, RuleInfo, TailoringModification } from "../types";

const _ = cockpit.gettext;

const TAILORING_DIR = "/var/lib/cockpit-oscap/tailoring";

// ---------------------------------------------------------------------------
// Category derivation from XCCDF rule IDs
// ---------------------------------------------------------------------------

/** Category keywords mapped from rule ID segments. */
const CATEGORY_MAP: [RegExp, string][] = [
    [/\brule_sysctl_/, "Kernel Settings"],
    [/\brule_audit_/, "Audit & Logging"],
    [/\brule_service_/, "Services & Daemons"],
    [/\brule_file_/, "File Permissions"],
    [/\brule_permissions_/, "File Permissions"],
    [/\brule_accounts_/, "Accounts & Authentication"],
    [/\brule_package_/, "Software & Packages"],
    [/\brule_selinux_/, "SELinux"],
    [/\brule_firewall_/, "Firewall"],
    [/\brule_network_/, "Network"],
    [/\brule_mount_/, "Filesystem & Mounts"],
    [/\brule_partition_/, "Filesystem & Mounts"],
    [/\brule_grub_/, "Bootloader"],
    [/\brule_banner_/, "Login Banners"],
    [/\brule_chronyd_/, "Time Synchronization"],
    [/\brule_crypto_/, "Cryptographic Policies"],
    [/\brule_sudo_/, "Privilege Escalation"],
    [/\brule_sshd_/, "SSH Configuration"],
    [/\brule_ssh_/, "SSH Configuration"],
    [/\brule_aide_/, "Integrity Checking"],
    [/\brule_rsyslog_/, "Logging"],
    [/\brule_journald_/, "Logging"],
    [/\brule_coredump_/, "Core Dumps"],
];

function deriveCategory(ruleId: string): string {
    for (const [pattern, category] of CATEGORY_MAP) {
        if (pattern.test(ruleId)) return category;
    }
    return "Other";
}

type FilterMode = "all" | "modified" | "enabled" | "disabled";

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

interface TailoringEditorProps {
    profileId: string;
}

export const TailoringEditor: React.FunctionComponent<TailoringEditorProps> = ({ profileId }) => {
    // State
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [rules, setRules] = useState<RuleInfo[]>([]);
    const [baseRules, setBaseRules] = useState<Map<string, boolean>>(new Map());
    const [, setConfig] = useState<Config>({});
    const [tailoringPath, setTailoringPath] = useState<string | null>(null);
    const [successMsg, setSuccessMsg] = useState<string | null>(null);
    const [warningMsg, setWarningMsg] = useState<string | null>(null);
    const [saving, setSaving] = useState(false);

    // Filter state
    const [searchText, setSearchText] = useState("");
    const [filterMode, setFilterMode] = useState<FilterMode>("all");
    const [filterOpen, setFilterOpen] = useState(false);

    // Category expand state
    const [expandedCategories, setExpandedCategories] = useState<Set<string>>(new Set());

    // File input ref for import
    const fileInputRef = useRef<HTMLInputElement>(null);

    // -----------------------------------------------------------------------
    // Load data on mount
    // -----------------------------------------------------------------------

    useEffect(() => {
        let cancelled = false;

        async function init() {
            try {
                const [ruleList, configData] = await Promise.all([
                    profileRules(profileId),
                    loadConfig(),
                ]);
                if (cancelled) return;

                setRules(ruleList);
                setConfig(configData);

                // Save baseline selections
                const baseline = new Map<string, boolean>();
                for (const r of ruleList) {
                    baseline.set(r.id, r.selected);
                }
                setBaseRules(baseline);

                // Check for existing tailoring
                const existingPath = configData[`tailoring_${profileId}`] as string | undefined;
                if (existingPath) {
                    setTailoringPath(existingPath);
                    try {
                        const parsed = await parseTailoring(existingPath);
                        if (!cancelled) {
                            applyModifications(ruleList, parsed.modifications);
                        }
                    } catch {
                        // Tailoring file may not exist yet — that's fine
                    }
                }

                // Expand all categories by default
                const cats = new Set<string>();
                for (const r of ruleList) {
                    cats.add(deriveCategory(r.id));
                }
                if (!cancelled) setExpandedCategories(cats);
            } catch (err) {
                if (!cancelled) setError(String(err));
            } finally {
                if (!cancelled) setLoading(false);
            }
        }

        init();
        return () => { cancelled = true };
    }, [profileId]);

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /** Apply tailoring modifications to the rules array. */
    function applyModifications(ruleList: RuleInfo[], modifications: TailoringModification[]) {
        const modMap = new Map<string, TailoringModification>();
        for (const m of modifications) {
            modMap.set(m.rule_id, m);
        }

        const orphaned: string[] = [];
        for (const m of modifications) {
            if (!ruleList.find(r => r.id === m.rule_id)) {
                orphaned.push(m.rule_id);
            }
        }

        if (orphaned.length > 0) {
            setWarningMsg(cockpit.format(
                _("$0 tailoring rule(s) not found in profile and were ignored."),
                orphaned.length,
            ));
        }

        setRules(ruleList.map(r => {
            const mod = modMap.get(r.id);
            if (mod) {
                return {
                    ...r,
                    selected: mod.action === "select",
                };
            }
            return r;
        }));
    }

    /** Check if a rule has been modified from its baseline. */
    function isModified(rule: RuleInfo): boolean {
        const original = baseRules.get(rule.id);
        return original !== undefined && original !== rule.selected;
    }

    /** Get all current modifications as TailoringModification[]. */
    function getModifications(): TailoringModification[] {
        const mods: TailoringModification[] = [];
        for (const rule of rules) {
            if (isModified(rule)) {
                mods.push({
                    rule_id: rule.id,
                    action: rule.selected ? "select" : "unselect",
                });
            }
        }
        return mods;
    }

    /** Count of modified rules. */
    function modifiedCount(): number {
        return rules.filter(r => isModified(r)).length;
    }

    // -----------------------------------------------------------------------
    // Handlers
    // -----------------------------------------------------------------------

    function handleToggle(ruleId: string, enabled: boolean) {
        setRules(prev => prev.map(r =>
            r.id === ruleId ? { ...r, selected: enabled } : r
        ));
        setSuccessMsg(null);
    }

    async function handleSave() {
        setSaving(true);
        setSuccessMsg(null);
        setError(null);

        try {
            const mods = getModifications();
            const result = await createTailoring(profileId, mods);
            setTailoringPath(result.path);

            // Persist tailoring path in config
            await cockpit
                    .file("/var/lib/cockpit-oscap/config.json", { superuser: "try" })
                    .modify((content: string | null) => {
                        const cfg: Config = content ? JSON.parse(content) : {};
                        cfg[`tailoring_${profileId}`] = result.path;
                        return JSON.stringify(cfg, null, 2);
                    });
            setConfig(prev => ({ ...prev, [`tailoring_${profileId}`]: result.path }));

            // Update baseline to current state
            const newBaseline = new Map<string, boolean>();
            for (const r of rules) {
                newBaseline.set(r.id, r.selected);
            }
            setBaseRules(newBaseline);

            setSuccessMsg(_("Tailoring saved successfully."));
        } catch (err) {
            setError(cockpit.format(_("Failed to save tailoring: $0"), String(err)));
        } finally {
            setSaving(false);
        }
    }

    async function handleExport() {
        if (!tailoringPath) {
            // Save first if no tailoring exists
            await handleSave();
        }

        const pathToExport = tailoringPath ?? `${TAILORING_DIR}/${profileId}-tailoring.xml`;

        try {
            const content = await cockpit
                    .file(pathToExport, { superuser: "try" })
                    .read();
            if (content === null || content === undefined) {
                setError(_("Tailoring file not found. Save tailoring first."));
                return;
            }

            const blob = new Blob([content], { type: "application/xml" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = profileId.replace(/[^a-zA-Z0-9_-]/g, "_") + "-tailoring.xml";
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        } catch (err) {
            setError(cockpit.format(_("Failed to export tailoring: $0"), String(err)));
        }
    }

    function handleImportClick() {
        fileInputRef.current?.click();
    }

    async function handleImportFile(event: React.ChangeEvent<HTMLInputElement>) {
        const file = event.target.files?.[0];
        if (!file) return;

        setWarningMsg(null);
        setError(null);

        try {
            const text = await file.text();

            // Write the imported file to a temp location so the bridge can parse it
            const importPath = `${TAILORING_DIR}/imported-${Date.now()}.xml`;
            await cockpit
                    .file(importPath, { superuser: "try" })
                    .replace(text);

            const parsed = await parseTailoring(importPath);

            // Warn on product mismatch
            if (parsed.base_profile && parsed.base_profile !== profileId) {
                setWarningMsg(cockpit.format(
                    _("Imported tailoring is based on profile '$0' but you are editing '$1'. Rules were applied where possible."),
                    parsed.base_profile,
                    profileId,
                ));
            }

            // Reset to baseline first, then apply imported modifications
            const resetRules = rules.map(r => ({
                ...r,
                selected: baseRules.get(r.id) ?? r.selected,
            }));
            applyModifications(resetRules, parsed.modifications);

            setSuccessMsg(_("Tailoring imported successfully."));
        } catch (err) {
            setError(cockpit.format(_("Failed to import tailoring: $0"), String(err)));
        } finally {
            // Reset file input so the same file can be re-imported
            if (fileInputRef.current) {
                fileInputRef.current.value = "";
            }
        }
    }

    function handleReset() {
        setRules(prev => prev.map(r => ({
            ...r,
            selected: baseRules.get(r.id) ?? r.selected,
        })));
        setSuccessMsg(null);
        setWarningMsg(null);
    }

    function handleBack() {
        cockpit.location.go(["profiles"]);
    }

    // -----------------------------------------------------------------------
    // Filtering and grouping
    // -----------------------------------------------------------------------

    function filteredRules(): RuleInfo[] {
        return rules.filter(r => {
            // Text search
            if (searchText) {
                const needle = searchText.toLowerCase();
                const haystack = `${r.title} ${r.id} ${r.description}`.toLowerCase();
                if (!haystack.includes(needle)) return false;
            }

            // Mode filter
            switch (filterMode) {
            case "modified":
                return isModified(r);
            case "enabled":
                return r.selected;
            case "disabled":
                return !r.selected;
            default:
                return true;
            }
        });
    }

    /** Group filtered rules by category, preserving order. */
    function groupedRules(): Map<string, RuleInfo[]> {
        const groups = new Map<string, RuleInfo[]>();
        for (const r of filteredRules()) {
            const cat = deriveCategory(r.id);
            const list = groups.get(cat);
            if (list) {
                list.push(r);
            } else {
                groups.set(cat, [r]);
            }
        }
        return groups;
    }

    /** Count modified rules in a category. */
    function categoryModifiedCount(categoryRules: RuleInfo[]): number {
        return categoryRules.filter(r => isModified(r)).length;
    }

    function toggleCategory(category: string) {
        setExpandedCategories(prev => {
            const next = new Set(prev);
            if (next.has(category)) {
                next.delete(category);
            } else {
                next.add(category);
            }
            return next;
        });
    }

    // -----------------------------------------------------------------------
    // Filter mode labels
    // -----------------------------------------------------------------------

    const filterLabels: Record<FilterMode, string> = {
        all: _("All rules"),
        modified: _("Modified only"),
        enabled: _("Enabled only"),
        disabled: _("Disabled only"),
    };

    // -----------------------------------------------------------------------
    // Render
    // -----------------------------------------------------------------------

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

    if (error && rules.length === 0) {
        return (
            <PageSection>
                <Alert variant="danger" title={_("Failed to load rules")}>
                    {error}
                </Alert>
                <Button
                    variant="link"
                    onClick={handleBack}
                    style={{ marginTop: "var(--pf-t--global--spacer--sm)" }}
                >
                    {_("Back to Profiles")}
                </Button>
            </PageSection>
        );
    }

    const groups = groupedRules();
    const totalModified = modifiedCount();

    return (
        <PageSection>
            {/* Header */}
            <Flex
                justifyContent={{ default: "justifyContentSpaceBetween" }}
                alignItems={{ default: "alignItemsCenter" }}
                style={{ marginBottom: "var(--pf-t--global--spacer--md)" }}
            >
                <FlexItem>
                    <Flex
                        alignItems={{ default: "alignItemsCenter" }}
                        spaceItems={{ default: "spaceItemsSm" }}
                    >
                        <FlexItem>
                            <Button variant="link" isInline onClick={handleBack}>
                                {_("Back to Profiles")}
                            </Button>
                        </FlexItem>
                        <FlexItem>
                            <Content component={ContentVariants.h1}>
                                {_("Tailoring Editor")}
                            </Content>
                        </FlexItem>
                    </Flex>
                </FlexItem>
                <FlexItem>
                    <Flex spaceItems={{ default: "spaceItemsSm" }}>
                        <FlexItem>
                            <Button
                                variant="primary"
                                onClick={handleSave}
                                isLoading={saving}
                                isDisabled={saving || totalModified === 0}
                            >
                                {_("Save Tailoring")}
                            </Button>
                        </FlexItem>
                        <FlexItem>
                            <Button variant="secondary" onClick={handleExport}>
                                {_("Export")}
                            </Button>
                        </FlexItem>
                        <FlexItem>
                            <Button variant="secondary" onClick={handleImportClick}>
                                {_("Import")}
                            </Button>
                            <input
                                ref={fileInputRef}
                                type="file"
                                accept=".xml"
                                style={{ display: "none" }}
                                onChange={handleImportFile}
                            />
                        </FlexItem>
                        <FlexItem>
                            <Button
                                variant="plain"
                                onClick={handleReset}
                                isDisabled={totalModified === 0}
                            >
                                {_("Reset")}
                            </Button>
                        </FlexItem>
                    </Flex>
                </FlexItem>
            </Flex>

            {/* Alerts */}
            {successMsg && (
                <Alert
                    variant="success"
                    isInline
                    title={successMsg}
                    actionClose={<Button variant="plain" onClick={() => setSuccessMsg(null)}>{_("Dismiss")}</Button>}
                    style={{ marginBottom: "var(--pf-t--global--spacer--sm)" }}
                />
            )}
            {warningMsg && (
                <Alert
                    variant="warning"
                    isInline
                    title={warningMsg}
                    actionClose={<Button variant="plain" onClick={() => setWarningMsg(null)}>{_("Dismiss")}</Button>}
                    style={{ marginBottom: "var(--pf-t--global--spacer--sm)" }}
                />
            )}
            {error && (
                <Alert
                    variant="danger"
                    isInline
                    title={error}
                    actionClose={<Button variant="plain" onClick={() => setError(null)}>{_("Dismiss")}</Button>}
                    style={{ marginBottom: "var(--pf-t--global--spacer--sm)" }}
                />
            )}

            {/* Profile info bar */}
            <Content
                component={ContentVariants.small}
                style={{ marginBottom: "var(--pf-t--global--spacer--sm)" }}
            >
                {cockpit.format(
                    _("Profile: $0 \u00B7 $1 rules \u00B7 $2 modified"),
                    profileId,
                    rules.length,
                    totalModified,
                )}
            </Content>

            {/* Filter toolbar */}
            <Toolbar>
                <ToolbarContent>
                    <ToolbarItem>
                        <TextInput
                            type="search"
                            aria-label={_("Search rules")}
                            placeholder={_("Search rules...")}
                            value={searchText}
                            onChange={(_event, value) => setSearchText(value)}
                        />
                    </ToolbarItem>
                    <ToolbarItem>
                        <Select
                            isOpen={filterOpen}
                            selected={filterMode}
                            onSelect={(_event, value) => {
                                setFilterMode(value as FilterMode);
                                setFilterOpen(false);
                            }}
                            onOpenChange={setFilterOpen}
                            toggle={(toggleRef) => (
                                <MenuToggle
                                    ref={toggleRef}
                                    onClick={() => setFilterOpen(prev => !prev)}
                                    isExpanded={filterOpen}
                                >
                                    {filterLabels[filterMode]}
                                </MenuToggle>
                            )}
                        >
                            <SelectList>
                                <SelectOption value="all">{filterLabels.all}</SelectOption>
                                <SelectOption value="modified">{filterLabels.modified}</SelectOption>
                                <SelectOption value="enabled">{filterLabels.enabled}</SelectOption>
                                <SelectOption value="disabled">{filterLabels.disabled}</SelectOption>
                            </SelectList>
                        </Select>
                    </ToolbarItem>
                </ToolbarContent>
            </Toolbar>

            {/* Rule categories */}
            {groups.size === 0 && (
                <Card>
                    <CardBody>
                        <Content component={ContentVariants.p}>
                            {_("No rules match the current filter.")}
                        </Content>
                    </CardBody>
                </Card>
            )}

            {Array.from(groups.entries()).map(([category, categoryRules]) => {
                const catModCount = categoryModifiedCount(categoryRules);
                const isExpanded = expandedCategories.has(category);

                const toggleContent = (
                    <Flex
                        spaceItems={{ default: "spaceItemsSm" }}
                        alignItems={{ default: "alignItemsCenter" }}
                    >
                        <FlexItem>
                            <strong>{category}</strong>
                        </FlexItem>
                        <FlexItem>
                            <Label isCompact color="blue">
                                {cockpit.format(_("$0 rules"), categoryRules.length)}
                            </Label>
                        </FlexItem>
                        {catModCount > 0 && (
                            <FlexItem>
                                <Label isCompact color="purple">
                                    {cockpit.format(_("$0 modified"), catModCount)}
                                </Label>
                            </FlexItem>
                        )}
                    </Flex>
                );

                return (
                    <Card
                        key={category}
                        style={{ marginBottom: "var(--pf-t--global--spacer--sm)" }}
                    >
                        <CardBody style={{ padding: "var(--pf-t--global--spacer--sm)" }}>
                            <ExpandableSection
                                toggleContent={toggleContent}
                                isExpanded={isExpanded}
                                onToggle={() => toggleCategory(category)}
                            >
                                {categoryRules.map(rule => (
                                    <RuleRow
                                        key={rule.id}
                                        rule={rule}
                                        modified={isModified(rule)}
                                        onToggle={handleToggle}
                                    />
                                ))}
                            </ExpandableSection>
                        </CardBody>
                    </Card>
                );
            })}

            {/* Footer with tailoring file path */}
            <Content
                component={ContentVariants.small}
                style={{
                    marginTop: "var(--pf-t--global--spacer--md)",
                    textAlign: "center",
                }}
            >
                {tailoringPath
                    ? cockpit.format(_("Tailoring file: $0"), tailoringPath)
                    : _("No tailoring file saved yet.")}
            </Content>
        </PageSection>
    );
};
