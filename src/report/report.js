/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * The Compliance page opens this page and hands it the report over postMessage
 * (the page that opened us renders it through the bridge). The report goes into
 * a sandboxed frame; when a rule is named, a small script added to the report
 * opens that rule's details once the report has loaded.
 */

/* global window, document, URLSearchParams, location */

(function () {
    "use strict";

    const status = document.getElementById("status");
    const frame = document.getElementById("report");
    const params = new URLSearchParams(location.search);
    const rule = params.get("rule") || "";

    // Runs inside the report: the report gives each rule's panel the class rule-detail-id-<rule id>,
    // a dialog per panel id, and an overview row with data-tt-id=<rule id>.
    const focusScript = [
        "window.addEventListener('load', function () {",
        "    const rule = " + JSON.stringify(rule) + ";",
        "    var panel = rule && document.getElementsByClassName('rule-detail-id-' + rule)[0];",
        "    if (!panel) return;",
        "    var suffix = (panel.id || '').replace(/^rule-detail-/, '');",
        "    if (suffix && typeof openRuleDetailsDialog === 'function') {",
        "        try { openRuleDetailsDialog(suffix); return; } catch (e) { /* fall back to the overview row */ }",
        "    }",
        "    var rows = document.querySelectorAll('tr[data-tt-id]');",
        "    for (var i = 0; i < rows.length; i++) {",
        "        if (rows[i].getAttribute('data-tt-id') === rule) { rows[i].scrollIntoView(); break; }",
        "    }",
        "});",
    ].join("\n");

    function fail(message) {
        status.textContent = message;
        status.className = "error";
        status.hidden = false;
        frame.hidden = true;
    }

    function show(html, title) {
        // a function replacement: the script would otherwise be read for "$&"-style patterns
        const injected = rule
            ? html.replace(/<\/body>/i, () => "<script>" + focusScript + "</script></body>")
            : html;
        document.title = title || document.title;
        frame.srcdoc = injected;
        frame.hidden = false;
        status.hidden = true;
    }

    window.addEventListener("message", function (event) {
        if (event.origin !== location.origin || !event.data || typeof event.data !== "object")
            return;
        if (event.data.type === "oscap-report" && typeof event.data.html === "string")
            show(event.data.html, event.data.title);
        else if (event.data.type === "oscap-report-error")
            fail(String(event.data.message || "The report could not be rendered."));
    });

    if (window.opener)
        window.opener.postMessage({ type: "oscap-report-ready" }, location.origin);
    else
        fail("Open the report from the Compliance page: this page shows the report that page renders.");
})();
