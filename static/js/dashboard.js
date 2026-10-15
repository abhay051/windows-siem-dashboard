
"use strict";

const $ = (id) => document.getElementById(id);

const history = { labels: [], cpu: [], memory: [] };
const MAX_POINTS = 30;

let allAlerts = [];
let allEvents = [];
let metricsChart = null;
let metricsRequestRunning = false;
let alertsRequestRunning = false;
let eventsRequestRunning = false;

const EVENT_INFO = {
    4624: {
        title: "Successful logon",
        description: "Windows recorded a successful sign-in."
    },
    4625: {
        title: "Failed logon",
        description: "Windows recorded an unsuccessful sign-in."
    },
    1102: {
        title: "Security audit log cleared",
        description: "Windows recorded that the Security audit log was cleared."
    }
};

const ALERT_GUIDANCE = {
    "repeated failed windows logins": {
        meaning: "Multiple failed logon records were detected within the configured time window.",
        why: "Repeated failures can result from a mistyped password, a misconfigured service, or an attempted password guess.",
        actions: [
            "Review the event messages and account names.",
            "Look for repeated attempts against the same account.",
            "Check the source workstation or network address when available.",
            "Compare the timestamps with expected user or service activity."
        ]
    },
    "windows security log cleared": {
        meaning: "Windows reported an event indicating that the Security audit log was cleared.",
        why: "Clearing an audit log can be legitimate administration, but it may also reduce available investigation evidence.",
        actions: [
            "Confirm whether an authorized administrator performed the action.",
            "Review nearby events and available audit records.",
            "Check other available logs for activity around the same time.",
            "Preserve relevant evidence before making changes."
        ]
    },
    "critical memory usage": {
        meaning: "System memory utilization crossed the configured detection threshold.",
        why: "High memory usage can slow applications or indicate a process consuming more resources than expected.",
        actions: [
            "Review memory usage and the processes consuming the most RAM.",
            "Check whether the increase is temporary or sustained.",
            "Inspect application logs if performance problems continue."
        ]
    },
    "sustained high cpu": {
        meaning: "CPU utilization crossed the configured detection threshold.",
        why: "Sustained high CPU use can be caused by normal workloads, a stuck application, or an unexpected process.",
        actions: [
            "Review CPU-intensive processes in Task Manager.",
            "Check whether the workload is expected.",
            "Compare CPU activity with application and system logs."
        ]
    }
};

function formatRate(bytesPerSecond) {
    const value = Number(bytesPerSecond) || 0;

    if (value < 1024) return `${value.toFixed(0)} B/s`;
    if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KB/s`;

    return `${(value / 1024 ** 2).toFixed(2)} MB/s`;
}

function formatDate(value) {
    if (!value) return "Time unavailable";

    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);

    return date.toLocaleString();
}

function escapeSeverity(value) {
    return String(value || "Info").toLowerCase().replace(/[^a-z]/g, "");
}

function setMetric(id, barId, value) {
    const numericValue = Number(value);

    if (!Number.isFinite(numericValue)) {
        $(id).textContent = "--";
        $(barId).style.width = "0%";
        return;
    }

    const boundedValue = Math.max(0, Math.min(100, numericValue));
    $(id).textContent = numericValue.toFixed(1);
    $(barId).style.width = `${boundedValue}%`;
}

function setText(id, value) {
    const element = $(id);
    if (element) element.textContent = value;
}

function showTableMessage(body, columns, title, detail = "") {
    body.replaceChildren();

    const row = body.insertRow();
    const cell = row.insertCell();
    cell.colSpan = columns;
    cell.className = "empty-state";

    const heading = document.createElement("strong");
    heading.textContent = title;
    cell.appendChild(heading);

    if (detail) {
        const message = document.createElement("span");
        message.textContent = detail;
        cell.appendChild(message);
    }
}

function addCell(row, value, className = "") {
    const cell = row.insertCell();
    cell.textContent = value == null || value === "" ? "—" : String(value);

    if (className) cell.className = className;
    return cell;
}

function makeChart() {
    const canvas = $("metrics-chart");

    if (!canvas || typeof Chart === "undefined") {
        console.error("Chart.js is unavailable. Check your internet connection.");
        return;
    }

    metricsChart = new Chart(canvas, {
        type: "line",
        data: {
            labels: [],
            datasets: [
                {
                    label: "CPU %",
                    data: [],
                    borderColor: "#38d9e6",
                    backgroundColor: "rgba(56,217,230,0.08)",
                    fill: true,
                    tension: 0.3,
                    pointRadius: 0,
                    borderWidth: 2
                },
                {
                    label: "Memory %",
                    data: [],
                    borderColor: "#a68aff",
                    backgroundColor: "rgba(166,138,255,0.05)",
                    fill: true,
                    tension: 0.3,
                    pointRadius: 0,
                    borderWidth: 2
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            interaction: { intersect: false, mode: "index" },
            plugins: {
                legend: {
                    labels: {
                        color: "#a9bbcf",
                        usePointStyle: true,
                        padding: 18
                    }
                }
            },
            scales: {
                x: {
                    ticks: { color: "#8291a5", maxTicksLimit: 8 },
                    grid: { color: "rgba(130,145,165,0.08)" }
                },
                y: {
                    min: 0,
                    max: 100,
                    ticks: {
                        color: "#8291a5",
                        callback: value => `${value}%`
                    },
                    grid: { color: "rgba(130,145,165,0.12)" }
                }
            }
        }
    });
}

async function fetchJson(url, options = {}) {
    const response = await fetch(url, options);

    let data;
    try {
        data = await response.json();
    } catch {
        throw new Error(`The server returned an invalid response (${response.status}).`);
    }

    if (!response.ok) {
        throw new Error(data.error || `Request failed (${response.status}).`);
    }

    return data;
}

async function loadMetrics() {
    if (metricsRequestRunning) return;
    metricsRequestRunning = true;

    try {
        const data = await fetchJson("/api/metrics");

        if (data.error) throw new Error(data.error);

        setMetric("cpu", "cpu-bar", data.cpu);
        setMetric("memory", "memory-bar", data.memory);
        setMetric("disk", "disk-bar", data.disk);

        setText(
            "memory-detail",
            `${data.memory_used_gb} / ${data.memory_total_gb} GB used`
        );

        setText("download", formatRate(data.download_bps));
        setText("upload", formatRate(data.upload_bps));
        setText("monitoring-status", "Operational");
        setText("agent-status", "ONLINE");

        const label = data.timestamp
            ? new Date(data.timestamp).toLocaleTimeString()
            : new Date().toLocaleTimeString();

        history.labels.push(label);
        history.cpu.push(Number(data.cpu) || 0);
        history.memory.push(Number(data.memory) || 0);

        if (history.labels.length > MAX_POINTS) {
            history.labels.shift();
            history.cpu.shift();
            history.memory.shift();
        }

        if (metricsChart) {
            metricsChart.data.labels = [...history.labels];
            metricsChart.data.datasets[0].data = [...history.cpu];
            metricsChart.data.datasets[1].data = [...history.memory];
            metricsChart.update("none");
        }

        setText("summary-updated", `Updated ${new Date().toLocaleTimeString()}`);
        updateSecuritySummary();
    } catch (error) {
        console.error("Metrics request failed:", error);
        setText("monitoring-status", "Connection issue");
        setText("agent-status", "CHECK");
        setText("summary-updated", "Metrics unavailable");
    } finally {
        metricsRequestRunning = false;
    }
}

function getAlertGuidance(alert) {
    const title = String(alert.title || "").trim().toLowerCase();
    return ALERT_GUIDANCE[title] || {
        meaning: alert.details || "The monitoring engine recorded a detection.",
        why: "The significance depends on the surrounding activity and the detection rule that generated this alert.",
        actions: [
            "Review the alert details and timestamp.",
            "Inspect related Windows events and application logs.",
            "Determine whether the activity is expected before resolving the alert."
        ]
    };
}

function openAlertDetails(alert) {
    const dialog = $("alert-dialog");
    const content = $("dialog-content");

    if (!dialog || !content) return;

    const guidance = getAlertGuidance(alert);
    content.replaceChildren();
    setText("dialog-title", alert.title || "Alert details");

    const summary = document.createElement("div");
    summary.className = "detail-grid";

    const fields = [
        ["Severity", alert.severity],
        ["Status", alert.status],
        ["Risk score", `${Number(alert.risk) || 0}/100`],
        ["Source", alert.source],
        ["Detected at", formatDate(alert.timestamp)],
        ["Alert ID", alert.id]
    ];

    for (const [label, value] of fields) {
        const field = document.createElement("div");
        field.className = "detail-field";

        const small = document.createElement("small");
        small.textContent = label;

        const strong = document.createElement("strong");
        strong.textContent = value == null || value === "" ? "—" : String(value);

        field.append(small, strong);
        summary.appendChild(field);
    }

    content.appendChild(summary);

    addDetailSection(content, "What happened?", alert.details || guidance.meaning);
    addDetailSection(content, "Why it matters", guidance.why);

    const actionsSection = document.createElement("section");
    actionsSection.className = "detail-section";

    const heading = document.createElement("h3");
    heading.textContent = "Recommended next steps";

    const list = document.createElement("ul");

    for (const action of guidance.actions) {
        const item = document.createElement("li");
        item.textContent = action;
        list.appendChild(item);
    }

    actionsSection.append(heading, list);
    content.appendChild(actionsSection);

    if (typeof dialog.showModal === "function") {
        if (!dialog.open) dialog.showModal();
    } else {
        dialog.setAttribute("open", "");
    }
}

function addDetailSection(container, headingText, paragraphText) {
    const section = document.createElement("section");
    section.className = "detail-section";

    const heading = document.createElement("h3");
    heading.textContent = headingText;

    const paragraph = document.createElement("p");
    paragraph.textContent = paragraphText;

    section.append(heading, paragraph);
    container.appendChild(section);
}

function renderAlerts() {
    const body = $("alerts-body");
    if (!body) return;

    const severityFilter = $("severity-filter")?.value || "all";
    const statusFilter = $("status-filter")?.value || "all";
    const search = ($("alert-search")?.value || "").trim().toLowerCase();

    const filtered = allAlerts.filter(alert => {
        const severity = String(alert.severity || "").toLowerCase();
        const status = String(alert.status || "").toLowerCase();

        const matchesSeverity =
            severityFilter === "all" || severity === severityFilter;
        const matchesStatus =
            statusFilter === "all" || status === statusFilter;
        const haystack = [
            alert.title,
            alert.details,
            alert.source,
            alert.status,
            alert.severity
        ].join(" ").toLowerCase();
        const matchesSearch = !search || haystack.includes(search);

        return matchesSeverity && matchesStatus && matchesSearch;
    });

    body.replaceChildren();

    if (filtered.length === 0) {
        showTableMessage(
            body,
            7,
            allAlerts.length === 0 ? "No alerts recorded" : "No alerts match these filters",
            allAlerts.length === 0
                ? "Monitoring is active. An empty alert list does not guarantee that no threats exist."
                : "Try a different severity, status, or search term."
        );
    } else {
        for (const alert of filtered) {
            const row = body.insertRow();

            addCell(row, formatDate(alert.timestamp));

            const severityCell = row.insertCell();
            const badge = document.createElement("span");
            badge.className = `severity ${escapeSeverity(alert.severity)}`;
            badge.textContent = alert.severity || "Info";
            severityCell.appendChild(badge);

            const titleCell = row.insertCell();
            const title = document.createElement("strong");
            title.textContent = alert.title || "Untitled alert";

            const description = document.createElement("div");
            description.className = "event-description";
            description.textContent = alert.details || "No additional details provided.";

            titleCell.append(title, description);

            const riskCell = addCell(row, `${Number(alert.risk) || 0}/100`, "risk");

            const statusCell = row.insertCell();
            const select = document.createElement("select");
            select.className = "status-select";
            select.setAttribute("aria-label", `Status for alert ${alert.id}`);

            for (const status of ["Open", "Investigating", "Resolved"]) {
                const option = document.createElement("option");
                option.value = status;
                option.textContent = status;
                option.selected =
                    String(alert.status || "Open").toLowerCase() === status.toLowerCase();
                select.appendChild(option);
            }

            select.addEventListener("change", () => updateAlertStatus(alert, select));
            statusCell.appendChild(select);

            const sourceCell = addCell(row, alert.source || "Local system", "source-text");

            const actionCell = row.insertCell();
            const detailButton = document.createElement("button");
            detailButton.type = "button";
            detailButton.className = "detail-btn";
            detailButton.textContent = "View details";
            detailButton.addEventListener("click", () => openAlertDetails(alert));
            actionCell.appendChild(detailButton);
        }
    }

    setText("alert-count", `Showing ${filtered.length} of ${allAlerts.length} alerts`);

    const openCount = allAlerts.filter(
        alert => String(alert.status || "Open").toLowerCase() !== "resolved"
    ).length;

    setText("open-alerts", String(openCount));
    setText(
        "open-alerts-note",
        openCount === 0 ? "No unresolved alerts" : `${openCount} alert(s) need review`
    );

    updateSecuritySummary();
}

async function updateAlertStatus(alert, select) {
    const previousStatus = alert.status;
    const newStatus = select.value;

    select.disabled = true;

    try {
        await fetchJson(`/api/alerts/${alert.id}/status`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ status: newStatus })
        });

        alert.status = newStatus;
        renderAlerts();
    } catch (error) {
        console.error("Alert status update failed:", error);
        window.alert(`Could not update alert status: ${error.message}`);
        alert.status = previousStatus;
        renderAlerts();
    } finally {
        select.disabled = false;
    }
}

async function loadAlerts() {
    if (alertsRequestRunning) return;
    alertsRequestRunning = true;

    try {
        const data = await fetchJson("/api/alerts?limit=50");
        if (!Array.isArray(data)) throw new Error("Unexpected alert response format.");

        allAlerts = data;
        renderAlerts();
    } catch (error) {
        console.error("Alert request failed:", error);
        setText("alert-count", "Could not load alerts");

        showTableMessage(
            $("alerts-body"),
            7,
            "Alerts could not be loaded",
            "Check that the Flask server is running, then refresh."
        );
    } finally {
        alertsRequestRunning = false;
    }
}

function getEventType(eventId) {
    const info = EVENT_INFO[Number(eventId)];

    if (info) return info;

    return {
        title: "Windows event",
        description: "A Windows event record was collected."
    };
}

function parseEventFields(value) {
    if (Array.isArray(value)) return value;

    if (typeof value === "string" && value.trim()) {
        try {
            const parsed = JSON.parse(value);
            return Array.isArray(parsed) ? parsed : [];
        } catch {
            return [];
        }
    }

    return [];
}

function renderEvents() {
    const body = $("events-body");
    if (!body) return;

    const typeFilter = $("event-type-filter")?.value || "all";
    const search = ($("event-search")?.value || "").trim().toLowerCase();

    const filtered = allEvents.filter(event => {
        const matchesType =
            typeFilter === "all" || String(event.event_id) === typeFilter;

        const haystack = [
            event.event_id,
            event.timestamp,
            event.computer,
            event.source,
            event.message,
            event.fields_json
        ].join(" ").toLowerCase();

        return matchesType && (!search || haystack.includes(search));
    });

    body.replaceChildren();

    if (filtered.length === 0) {
        showTableMessage(
            body,
            6,
            allEvents.length === 0 ? "No stored events yet" : "No events match these filters",
            allEvents.length === 0
                ? "Collected Windows Security records will appear here when available."
                : "Try a different event type or search term."
        );
    } else {
        for (const event of filtered) {
            const row = body.insertRow();

            addCell(row, formatDate(event.timestamp));

            const idCell = row.insertCell();
            const idBadge = document.createElement("span");
            idBadge.className = "event-id";
            idBadge.textContent = String(event.event_id ?? "—");
            idCell.appendChild(idBadge);

            const typeCell = row.insertCell();
            const info = getEventType(event.event_id);
            const typeTitle = document.createElement("span");
            typeTitle.className = "event-type";
            typeTitle.textContent = info.title;

            const typeDescription = document.createElement("span");
            typeDescription.className = "event-description";
            typeDescription.textContent = info.description;

            typeCell.append(typeTitle, typeDescription);

            addCell(row, event.computer || "Unknown");
            addCell(row, event.source || "Windows", "source-text");

            const messageCell = row.insertCell();
            messageCell.className = "cell-message";
            const message = String(event.message || "No event message was stored.");
            messageCell.textContent =
                message.length > 350 ? `${message.slice(0, 350)}…` : message;
            messageCell.title = message;
        }
    }

    setText("event-count", `Showing ${filtered.length} of ${allEvents.length} events`);
}

async function loadEvents() {
    if (eventsRequestRunning) return;
    eventsRequestRunning = true;

    try {
        const data = await fetchJson("/api/windows-events/stored?limit=200");
        if (!Array.isArray(data)) throw new Error("Unexpected Windows events response format.");

        allEvents = data;
        renderEvents();
    } catch (error) {
        console.error("Windows events request failed:", error);
        setText("event-count", "Could not load stored events");

        showTableMessage(
            $("events-body"),
            6,
            "Windows events could not be loaded",
            "Check the Flask server and the stored Windows events endpoint."
        );
    } finally {
        eventsRequestRunning = false;
    }
}

async function checkHealth() {
    try {
        const data = await fetchJson("/api/health");
        const online = data.status === "ok";

        setText("agent-status", online ? "ONLINE" : "CHECK");
        setText("monitoring-status", online ? "Operational" : "Check connection");
    } catch (error) {
        console.error("Health check failed:", error);
        setText("agent-status", "CHECK");
        setText("monitoring-status", "Connection issue");
    }
}

function updateSecuritySummary() {
    const summary = $("security-summary");
    if (!summary) return;

    const unresolved = allAlerts.filter(
        alert => String(alert.status || "Open").toLowerCase() !== "resolved"
    );

    if (unresolved.length > 0) {
        const highPriority = unresolved.filter(alert =>
            ["critical", "high"].includes(String(alert.severity || "").toLowerCase())
        ).length;

        summary.textContent = highPriority > 0
            ? `${unresolved.length} unresolved alert(s), including ${highPriority} high-priority alert(s). Review the alert queue below.`
            : `${unresolved.length} unresolved alert(s) are waiting for review. Check the alert queue below.`;

        return;
    }

    if (allAlerts.length > 0) {
        summary.textContent = "No unresolved alerts in the current alert list. Keep monitoring system activity.";
    } else {
        summary.textContent = "No alerts are currently recorded. Monitoring is active, but this is not a guarantee that the system is threat-free.";
    }
}

function updateClock() {
    setText("clock", new Date().toLocaleTimeString());
}

function setupControls() {
    $("severity-filter")?.addEventListener("change", renderAlerts);
    $("status-filter")?.addEventListener("change", renderAlerts);
    $("alert-search")?.addEventListener("input", renderAlerts);
    $("event-type-filter")?.addEventListener("change", renderEvents);
    $("event-search")?.addEventListener("input", renderEvents);

    $("refresh-btn")?.addEventListener("click", async () => {
        const button = $("refresh-btn");
        button.disabled = true;
        button.textContent = "Refreshing…";

        try {
            await Promise.all([
                loadMetrics(),
                loadAlerts(),
                loadEvents(),
                checkHealth()
            ]);
        } finally {
            button.disabled = false;
            button.textContent = "↻ Refresh data";
        }
    });

    $("dialog-close")?.addEventListener("click", () => $("alert-dialog")?.close());
    $("dialog-done")?.addEventListener("click", () => $("alert-dialog")?.close());

    $("alert-dialog")?.addEventListener("click", event => {
        if (event.target === $("alert-dialog")) {
            $("alert-dialog").close();
        }
    });

    document.querySelectorAll(".nav-item").forEach(link => {
        link.addEventListener("click", () => {
            document.querySelectorAll(".nav-item").forEach(item =>
                item.classList.remove("active")
            );
            link.classList.add("active");
        });
    });
}

function startDashboard() {
    makeChart();
    setupControls();
    updateClock();

    loadMetrics();
    loadAlerts();
    loadEvents();
    checkHealth();

    setInterval(updateClock, 1000);
    setInterval(loadMetrics, 3000);
    setInterval(loadAlerts, 5000);
    setInterval(loadEvents, 15000);
    setInterval(checkHealth, 30000);
}

startDashboard();
