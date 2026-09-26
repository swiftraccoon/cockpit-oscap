/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

import React from "react";
import { Button } from "@patternfly/react-core/dist/esm/components/Button/index.js";
import { Modal, ModalBody, ModalFooter, ModalHeader } from "@patternfly/react-core/dist/esm/components/Modal/index.js";
import cockpit from "cockpit";

import type { DialogResult } from "dialogs";

const _ = cockpit.gettext;

export interface ConfirmDialogProps {
    title: string;
    body: React.ReactNode;
    confirmText: string;
    isDanger?: boolean;
}

/** Use with `Dialogs.run(ConfirmDialog, {...})`; resolves to true when confirmed. */
export const ConfirmDialog = (props: ConfirmDialogProps & { dialogResult: DialogResult<boolean> }) => {
    const { title, body, confirmText, isDanger = false, dialogResult } = props;
    const cancel = () => dialogResult.resolve(false);
    const confirm = () => dialogResult.resolve(true);

    return (
        <Modal isOpen variant="small" position="top" onClose={cancel}>
            <ModalHeader title={title} {...isDanger && { titleIconVariant: "warning" }} />
            <ModalBody>{body}</ModalBody>
            <ModalFooter>
                <Button variant={isDanger ? "danger" : "primary"} onClick={confirm}>{confirmText}</Button>
                <Button variant="link" onClick={cancel}>{_("Cancel")}</Button>
            </ModalFooter>
        </Modal>
    );
};
