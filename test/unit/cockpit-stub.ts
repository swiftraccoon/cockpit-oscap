/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * The bits of cockpit.js that pure helpers use, for running them under node.
 */

const cockpit = {
    language: "en",
    gettext: (text: string) => text,
    ngettext: (singular: string, plural: string, count: number) => (count === 1 ? singular : plural),
    format: (template: string, ...args: unknown[]) =>
        template.replace(/\$(\d+)/g, (_match, index: string) => String(args[Number(index)] ?? "")),
    event_target: (obj: object) => obj,
};

export default cockpit;
