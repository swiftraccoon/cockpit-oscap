/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Exclude one rule from a profile's customization, with the justification that
 * the tailoring file keeps as an XCCDF remark. Rendered outside the application
 * context (dialogs are), so everything it needs is passed in.
 */

import React, { useState } from "react";
import { Button } from "@patternfly/react-core/dist/esm/components/Button/index.js";
import { Content } from "@patternfly/react-core/dist/esm/components/Content/index.js";
import { Form, FormGroup, FormHelperText } from "@patternfly/react-core/dist/esm/components/Form/index.js";
import { HelperText, HelperTextItem } from "@patternfly/react-core/dist/esm/components/HelperText/index.js";
import { Modal, ModalBody, ModalFooter, ModalHeader } from "@patternfly/react-core/dist/esm/components/Modal/index.js";
import { TextArea } from "@patternfly/react-core/dist/esm/components/TextArea/index.js";
import cockpit from "cockpit";

import type { DialogResult } from "dialogs";

import { tailorRule } from "../api";
import { errorMessage } from "../helpers";
import { ErrorAlert } from "./states";

const _ = cockpit.gettext;

export interface ExcludeRuleDialogProps {
    baseProfileId: string;
    profileTitle: string;
    ruleId: string;
    ruleTitle: string;
    /** The content the rule belongs to; the configured one when unset. */
    datastream?: string;
}

/** Use with `Dialogs.run(ExcludeRuleDialog, {...})`; resolves to true once the rule is excluded. */
export const ExcludeRuleDialog = (props: ExcludeRuleDialogProps & { dialogResult: DialogResult<boolean> }) => {
    const { baseProfileId, profileTitle, ruleId, ruleTitle, datastream, dialogResult } = props;
    const [remark, setRemark] = useState("");
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const ready = remark.trim().length > 0 && !busy;

    async function exclude() {
        setBusy(true);
        setError(null);
        try {
            await tailorRule(baseProfileId, ruleId, false, remark, datastream);
            dialogResult.resolve(true);
        } catch (err) {
            setError(errorMessage(err));
            setBusy(false);
        }
    }

    return (
        <Modal
            isOpen variant="medium" position="top" id="exclude-rule-dialog"
            onClose={() => { if (!busy) dialogResult.resolve(false); }}
        >
            <ModalHeader title={_("Exclude rule from profile?")} />
            <ModalBody>
                <Form id="exclude-rule-form" onSubmit={ev => { ev.preventDefault(); if (ready) exclude(); }}>
                    <Content component="p">
                        {cockpit.format(_("$0 will be disabled in the customization of $1. The next scan of the profile skips it; the score no longer counts it."),
                                        ruleTitle || ruleId, profileTitle || baseProfileId)}
                    </Content>
                    {error && <ErrorAlert title={_("The rule could not be excluded")} error={error} />}
                    <FormGroup label={_("Justification")} isRequired fieldId="exclude-rule-remark">
                        <TextArea
                            id="exclude-rule-remark"
                            value={remark}
                            isRequired
                            autoFocus
                            resizeOrientation="vertical"
                            placeholder={_("Why this rule does not apply here, or how its risk is accepted")}
                            onChange={(_ev, text) => setRemark(text)}
                        />
                        <FormHelperText>
                            <HelperText>
                                <HelperTextItem>
                                    {_("Kept in the tailoring file as an XCCDF remark and shown with every later scan, so auditors and SCAP Workbench see it too.")}
                                </HelperTextItem>
                            </HelperText>
                        </FormHelperText>
                    </FormGroup>
                </Form>
            </ModalBody>
            <ModalFooter>
                <Button
                    id="exclude-rule-confirm" variant="primary" type="submit" form="exclude-rule-form"
                    isDisabled={!ready} isLoading={busy}
                >
                    {_("Exclude rule")}
                </Button>
                <Button variant="link" onClick={() => dialogResult.resolve(false)} isDisabled={busy}>{_("Cancel")}</Button>
            </ModalFooter>
        </Modal>
    );
};
