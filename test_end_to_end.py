
import os
import sqlite3
from datetime import datetime, timedelta

import app


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DB = os.path.join(BASE_DIR, "test_end_to_end_v2.db")

# Protect existing databases.
if os.path.exists(TEST_DB):
    raise SystemExit(
        f"Test database already exists: {TEST_DB}\n"
        "No database was changed. Use a new test filename to rerun."
    )

# Isolate all app database operations from production.
app.DB_PATH = TEST_DB
app.alert_cooldowns.clear()
app.init_db()


def get_alerts():
    with sqlite3.connect(TEST_DB) as conn:
        conn.row_factory = sqlite3.Row
        return [
            dict(row)
            for row in conn.execute(
                "SELECT * FROM alerts ORDER BY id"
            ).fetchall()
        ]


def make_event(event_id, record_number, event_time, fields):
    return {
        "event_id": event_id,
        "source": "SIEM-End-to-End-Test",
        "time": event_time.isoformat(),
        "category": 0,
        "record_number": record_number,
        "computer": "TEST-PC",
        "message": " | ".join(fields),
        "fields": fields,
    }


def check_alert(label, expected_title):
    alerts = get_alerts()
    matches = [
        alert for alert in alerts
        if alert["title"] == expected_title
    ]

    if matches:
        print(f"PASS: {label}")
        return True

    print(f"FAIL: {label}")
    print(f"  Expected: {expected_title}")
    print("  Alerts found:", [a["title"] for a in alerts])
    return False


now = datetime.now().astimezone().replace(tzinfo=None)
results = []

print("\n=== ISOLATED END-TO-END DETECTION TEST ===")
print("Test database:", TEST_DB)
print("Production siem.db: NOT USED\n")


# 1. Five failed logins within five minutes.
failed_events = [
    make_event(
        4625,
        920000 + i,
        now - timedelta(minutes=4 - i),
        ["SIMULATED", "failed-login-test", f"attempt-{i + 1}"],
    )
    for i in range(5)
]

app.store_windows_events(failed_events)
results.append(
    check_alert(
        "Repeated failed logins (4625)",
        "Repeated failed Windows logins",
    )
)


# 2. Windows Security audit log cleared.
app.store_windows_events([
    make_event(
        1102,
        930001,
        now,
        ["SIMULATED", "security-log-cleared-test"],
    )
])

results.append(
    check_alert(
        "Security log cleared (1102)",
        "Windows Security log cleared",
    )
)


# 3. Windows user account created.
app.store_windows_events([
    make_event(
        4720,
        940001,
        now,
        ["SIMULATED", "account-created-test"],
    )
])

results.append(
    check_alert(
        "User account creation (4720)",
        "Windows user account created",
    )
)


# 4. Member added to a global security group.
app.store_windows_events([
    make_event(
        4728,
        950001,
        now,
        ["SIMULATED", "global-group-membership-test"],
    )
])

results.append(
    check_alert(
        "Global group membership change (4728)",
        "Global security group membership changed",
    )
)


# 5. Member added to a local security group.
app.store_windows_events([
    make_event(
        4732,
        960001,
        now,
        ["SIMULATED", "local-group-membership-test"],
    )
])

results.append(
    check_alert(
        "Local group membership change (4732)",
        "Local security group membership changed",
    )
)


print("\n=== END-TO-END SUMMARY ===")
passed = sum(results)
failed = len(results) - passed
print(f"Passed: {passed} / {len(results)}")
print(f"Failed: {failed} / {len(results)}")
print("Test database:", TEST_DB)
print("Production database was not used.")

if failed:
    raise SystemExit(1)
