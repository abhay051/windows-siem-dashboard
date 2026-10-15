
import os
import json
import sqlite3
import threading
import time
from datetime import datetime, timezone, timedelta

import psutil
from flask import Flask, jsonify, render_template, request
from windows_logs import read_security_events


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "siem.db")

app = Flask(__name__)

# Network monitoring state
previous_net = psutil.net_io_counters()
previous_net_time = time.time()
monitor_lock = threading.Lock()

# Alert cooldown state
alert_cooldowns = {}
alert_cooldown_lock = threading.Lock()
ALERT_COOLDOWN_SECONDS = 300

# Failed-login detection settings
FAILED_LOGIN_THRESHOLD = 5
FAILED_LOGIN_WINDOW_MINUTES = 5

# Windows event collection settings
WINDOWS_COLLECTION_INTERVAL = 60
WINDOWS_COLLECTION_LIMIT = 100


def connect_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create database tables without deleting existing data."""
    with connect_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                details TEXT NOT NULL,
                risk INTEGER NOT NULL,
                source TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Open'
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS windows_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                record_number INTEGER NOT NULL UNIQUE,
                event_id INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                computer TEXT NOT NULL,
                source TEXT NOT NULL,
                message TEXT NOT NULL,
                fields_json TEXT NOT NULL
            )
        """)
        conn.commit()


def now_utc():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def create_alert(
    severity,
    title,
    details,
    risk,
    source="Local system",
):
    with connect_db() as conn:
        conn.execute("""
            INSERT INTO alerts
                (timestamp, severity, title, details, risk, source)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            now_utc(),
            severity,
            title,
            details,
            risk,
            source,
        ))
        conn.commit()


def create_alert_with_cooldown(
    key,
    severity,
    title,
    details,
    risk,
    source="Local system",
):
    """Create an alert unless this detection is in its cooldown."""
    current_time = time.time()

    with alert_cooldown_lock:
        last_time = alert_cooldowns.get(key, 0)

        if current_time - last_time < ALERT_COOLDOWN_SECONDS:
            return

        alert_cooldowns[key] = current_time

    try:
        create_alert(severity, title, details, risk, source)
    except Exception:
        with alert_cooldown_lock:
            alert_cooldowns.pop(key, None)
        raise


def collect_metrics():
    global previous_net, previous_net_time

    cpu = psutil.cpu_percent(interval=0.2)
    memory = psutil.virtual_memory()

    system_drive = os.environ.get("SystemDrive", "C:")
    disk = psutil.disk_usage(system_drive + "\\")

    current_net = psutil.net_io_counters()
    current_time = time.time()

    with monitor_lock:
        elapsed = max(current_time - previous_net_time, 0.001)

        download_rate = max(
            0,
            current_net.bytes_recv - previous_net.bytes_recv,
        ) / elapsed

        upload_rate = max(
            0,
            current_net.bytes_sent - previous_net.bytes_sent,
        ) / elapsed

        previous_net = current_net
        previous_net_time = current_time

    return {
        "timestamp": now_utc(),
        "cpu": cpu,
        "memory": memory.percent,
        "memory_used_gb": round(memory.used / (1024 ** 3), 2),
        "memory_total_gb": round(memory.total / (1024 ** 3), 2),
        "disk": disk.percent,
        "download_bps": round(download_rate),
        "upload_bps": round(upload_rate),
    }


def run_detection(metrics):
    """Detect unusually high system resource usage."""
    if metrics["cpu"] >= 95:
        create_alert_with_cooldown(
            key="high_cpu",
            severity="High",
            title="Sustained high CPU",
            details=(
                f"CPU usage reached {metrics['cpu']}%. "
                "Investigate resource-heavy processes."
            ),
            risk=65,
        )

    if metrics["memory"] >= 95:
        create_alert_with_cooldown(
            key="critical_memory",
            severity="High",
            title="Critical memory usage",
            details=f"Memory usage reached {metrics['memory']}%.",
            risk=70,
        )


def parse_event_time(value):
    """Parse an event timestamp into a timezone-aware UTC datetime."""
    try:
        parsed = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None

    if parsed.tzinfo is None:
        parsed = parsed.astimezone()

    return parsed.astimezone(timezone.utc)


def store_windows_events(events):
    """Store new events and generate alerts for selected event IDs."""
    inserted = 0
    failed_login_details = None
    log_clear_details = None
    account_details = []
    global_group_details = []
    local_group_details = []

    with connect_db() as conn:
        for event in events:
            record_number = event.get("record_number")

            if record_number is None:
                continue

            try:
                record_number = int(record_number)
                event_id = int(event.get("event_id", 0))
            except (TypeError, ValueError):
                continue

            timestamp = str(event.get("time") or now_utc())
            computer = str(event.get("computer") or "Unknown")
            source = str(event.get("source") or "Windows Security")
            message = str(event.get("message") or "")
            fields_json = json.dumps(
                event.get("fields", []),
                ensure_ascii=False,
            )

            cursor = conn.execute("""
                INSERT OR IGNORE INTO windows_events
                    (record_number, event_id, timestamp, computer,
                     source, message, fields_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                record_number,
                event_id,
                timestamp,
                computer,
                source,
                message,
                fields_json,
            ))

            # A record number is unique; do not process duplicates.
            if cursor.rowcount == 0:
                continue

            inserted += 1

            if event_id == 1102:
                log_clear_details = (
                    f"Computer: {computer}\n"
                    f"Event time: {timestamp}\n"
                    f"Event details: {message}\n"
                    "Windows reported that the Security audit log "
                    "was cleared. Review whether this action was "
                    "authorized."
                )

            elif event_id == 4625:
                event_time = parse_event_time(timestamp)

                if event_time is None:
                    app.logger.warning(
                        "Could not parse failed-logon timestamp: %s",
                        timestamp,
                    )
                    continue

                cutoff = event_time - timedelta(
                    minutes=FAILED_LOGIN_WINDOW_MINUTES
                )

                rows = conn.execute("""
                    SELECT timestamp
                    FROM windows_events
                    WHERE event_id = 4625
                """).fetchall()

                matching_times = []

                for row in rows:
                    stored_time = parse_event_time(row["timestamp"])

                    if stored_time is not None and cutoff <= stored_time <= event_time:
                        matching_times.append(stored_time)

                if len(matching_times) >= FAILED_LOGIN_THRESHOLD:
                    failed_login_details = (
                        f"At least {FAILED_LOGIN_THRESHOLD} failed "
                        f"logon events (Event ID 4625) were recorded "
                        f"within {FAILED_LOGIN_WINDOW_MINUTES} minutes.\n"
                        f"Computer: {computer}\n"
                        f"Latest event time: {timestamp}\n"
                        f"Latest event details: {message}\n"
                        "Review the account and logon information. "
                        "Repeated failures can result from mistyped "
                        "credentials, misconfigured services, or "
                        "suspicious activity."
                    )

            elif event_id == 4720:
                account_details.append(
                    f"Computer: {computer}\n"
                    f"Event time: {timestamp}\n"
                    f"Event details: {message}\n"
                    "A new Windows user account was created. "
                    "Review whether this activity was authorized."
                )

            elif event_id == 4728:
                global_group_details.append(
                    f"Computer: {computer}\n"
                    f"Event time: {timestamp}\n"
                    f"Event details: {message}\n"
                    "A member was added to a global security group. "
                    "Review the group and membership change."
                )

            elif event_id == 4732:
                local_group_details.append(
                    f"Computer: {computer}\n"
                    f"Event time: {timestamp}\n"
                    f"Event details: {message}\n"
                    "A member was added to a local security group. "
                    "Review the group and membership change."
                )

        conn.commit()

    if failed_login_details:
        create_alert_with_cooldown(
            key="repeated_failed_logins",
            severity="High",
            title="Repeated failed Windows logins",
            details=failed_login_details,
            risk=75,
            source="Windows Security",
        )

    if log_clear_details:
        create_alert_with_cooldown(
            key="windows_security_log_cleared",
            severity="High",
            title="Windows Security log cleared",
            details=log_clear_details,
            risk=85,
            source="Windows Security",
        )

    if account_details:
        create_alert_with_cooldown(
            key="windows_account_created",
            severity="Medium",
            title="Windows user account created",
            details="\n\n".join(account_details),
            risk=60,
            source="Windows Security",
        )

    if global_group_details:
        create_alert_with_cooldown(
            key="global_security_group_membership_changed",
            severity="Medium",
            title="Global security group membership changed",
            details="\n\n".join(global_group_details),
            risk=70,
            source="Windows Security",
        )

    if local_group_details:
        create_alert_with_cooldown(
            key="local_security_group_membership_changed",
            severity="Medium",
            title="Local security group membership changed",
            details="\n\n".join(local_group_details),
            risk=70,
            source="Windows Security",
        )

    return inserted


def collect_windows_events_once():
    """Read and store one batch of Windows Security events."""
    events = read_security_events(limit=WINDOWS_COLLECTION_LIMIT)

    if isinstance(events, dict):
        if "error" in events:
            raise RuntimeError(str(events["error"]))
        raise RuntimeError("Unexpected response from Windows event reader.")

    if not isinstance(events, list):
        raise RuntimeError("Windows event reader returned an invalid result.")

    inserted = store_windows_events(events)

    print(
        f"[SIEM] Windows collection completed: "
        f"{len(events)} events checked, {inserted} new events stored."
    )
    return len(events), inserted


def background_windows_collector():
    """Collect Windows Security events periodically."""
    print(
        f"[SIEM] Background Windows collector started. "
        f"Interval: {WINDOWS_COLLECTION_INTERVAL} seconds."
    )

    while True:
        try:
            collect_windows_events_once()
        except Exception as exc:
            app.logger.exception(
                "Background Windows event collection failed: %s",
                exc,
            )

        time.sleep(WINDOWS_COLLECTION_INTERVAL)


@app.route("/")
def dashboard():
    return render_template("index.html")


@app.route("/api/metrics")
def metrics_api():
    try:
        metrics = collect_metrics()
        run_detection(metrics)
        return jsonify(metrics)
    except Exception:
        app.logger.exception("Metrics collection failed")
        return jsonify({
            "error": "Metrics collection failed. Check server logs."
        }), 500


@app.route("/api/alerts")
def alerts_api():
    limit = request.args.get("limit", default=50, type=int)
    limit = max(1, min(limit, 200))

    try:
        with connect_db() as conn:
            rows = conn.execute("""
                SELECT *
                FROM alerts
                ORDER BY id DESC
                LIMIT ?
            """, (limit,)).fetchall()

        return jsonify([dict(row) for row in rows])

    except sqlite3.Error:
        app.logger.exception("Alert retrieval failed")
        return jsonify({"error": "Could not retrieve alerts"}), 500


@app.route("/api/alerts/<int:alert_id>/status", methods=["POST"])
def update_alert_status(alert_id):
    payload = request.get_json(silent=True) or {}
    status = payload.get("status")
    allowed_statuses = ("Open", "Investigating", "Resolved")

    if status not in allowed_statuses:
        return jsonify({
            "error": "Invalid status",
            "allowed": list(allowed_statuses),
        }), 400

    try:
        with connect_db() as conn:
            cursor = conn.execute("""
                UPDATE alerts
                SET status = ?
                WHERE id = ?
            """, (status, alert_id))
            conn.commit()

        if cursor.rowcount == 0:
            return jsonify({"error": "Alert not found"}), 404

        return jsonify({"id": alert_id, "status": status})

    except sqlite3.Error:
        app.logger.exception("Alert status update failed")
        return jsonify({"error": "Could not update alert status"}), 500


@app.route("/api/windows-events")
def windows_events_api():
    limit = request.args.get("limit", default=10, type=int)
    limit = max(1, min(limit, 100))

    try:
        result = read_security_events(limit=limit)

        if isinstance(result, dict) and "error" in result:
            app.logger.warning(
                "Windows Security log read failed: %s",
                result["error"],
            )
            return jsonify(result), 500

        if not isinstance(result, list):
            return jsonify({
                "error": "Unexpected response from Windows event reader"
            }), 500

        inserted = store_windows_events(result)

        return jsonify({
            "count_returned": len(result),
            "count_stored": inserted,
            "events": result,
        })

    except Exception:
        app.logger.exception("Windows event retrieval or storage failed")
        return jsonify({
            "error": "Could not retrieve or store Windows Security events",
            "hint": (
                "Check the server console and ensure the process "
                "has permission to read the Windows Security log."
            ),
        }), 500


@app.route("/api/windows-events/stored")
def stored_windows_events_api():
    limit = request.args.get("limit", default=50, type=int)
    limit = max(1, min(limit, 200))

    try:
        with connect_db() as conn:
            rows = conn.execute("""
                SELECT *
                FROM windows_events
                ORDER BY id DESC
                LIMIT ?
            """, (limit,)).fetchall()

        return jsonify([dict(row) for row in rows])

    except sqlite3.Error:
        app.logger.exception("Stored Windows event retrieval failed")
        return jsonify({"error": "Could not retrieve stored events"}), 500


@app.route("/api/health")
def health_api():
    try:
        with connect_db() as conn:
            conn.execute("SELECT 1").fetchone()

        return jsonify({
            "status": "ok",
            "database": "sqlite",
            "windows_events_endpoint": "/api/windows-events",
            "stored_windows_events_endpoint": "/api/windows-events/stored",
            "background_collection_interval_seconds":
                WINDOWS_COLLECTION_INTERVAL,
        })

    except sqlite3.Error:
        app.logger.exception("Health check failed")
        return jsonify({
            "status": "error",
            "database": "unavailable",
        }), 500


if __name__ == "__main__":
    init_db()

    print("SIEM server starting at http://127.0.0.1:5000")
    print("Dashboard:       http://127.0.0.1:5000/")
    print("Health check:    http://127.0.0.1:5000/api/health")
    print("Windows logs:    http://127.0.0.1:5000/api/windows-events")
    print("Stored events:   http://127.0.0.1:5000/api/windows-events/stored")
    print(
        f"Background collection interval: "
        f"{WINDOWS_COLLECTION_INTERVAL} seconds"
    )

    collector_thread = threading.Thread(
        target=background_windows_collector,
        name="WindowsSecurityCollector",
        daemon=True,
    )
    collector_thread.start()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
    )
