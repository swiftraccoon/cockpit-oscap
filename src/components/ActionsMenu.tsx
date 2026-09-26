/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * A kebab menu whose toggle has an accessible name. Same shape as cockpit's
 * KebabDropdown, which leaves the toggle button unnamed for screen readers.
 */

import React, { useState } from "react";
import { Dropdown, DropdownList } from "@patternfly/react-core/dist/esm/components/Dropdown/index.js";
import type { DropdownPopperProps } from "@patternfly/react-core/dist/esm/components/Dropdown/index.js";
import { MenuToggle } from "@patternfly/react-core/dist/esm/components/MenuToggle/index.js";
import EllipsisVIcon from "@patternfly/react-icons/dist/esm/icons/ellipsis-v-icon";

export const ActionsMenu = ({ ariaLabel, dropdownItems, toggleButtonId, isDisabled = false, position = "end" }: {
    /** What the menu acts on, e.g. "Actions for the CIS profile". */
    ariaLabel: string;
    dropdownItems: React.ReactNode;
    toggleButtonId?: string;
    isDisabled?: boolean;
    position?: DropdownPopperProps["position"];
}) => {
    const [isOpen, setIsOpen] = useState(false);
    return (
        <Dropdown
            onOpenChange={setIsOpen}
            onSelect={() => setIsOpen(false)}
            isOpen={isOpen}
            popperProps={{ position }}
            toggle={toggleRef => (
                <MenuToggle
                    ref={toggleRef}
                    {...toggleButtonId && { id: toggleButtonId }}
                    aria-label={ariaLabel}
                    variant="plain"
                    isDisabled={isDisabled}
                    isExpanded={isOpen}
                    onClick={() => setIsOpen(open => !open)}
                >
                    <EllipsisVIcon />
                </MenuToggle>
            )}
        >
            <DropdownList>{dropdownItems}</DropdownList>
        </Dropdown>
    );
};
