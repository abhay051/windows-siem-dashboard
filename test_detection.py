
import os
import sqlite3
from datetime import datetime, timedelta

import app


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DB = os.path.join(BASE_DIR, "test_detection_v3.db")

# Do not overwrite an existing test database.
if os.path.exists(TEST_DB):
    raise SystemExit(
        f"\nTest database already exists:\n{TEST_DB}\n\n"
        "This test uses a separate database to protect production data.\n"
        "Use a new filename if you need to run it again."
    )

# Use an isolated database, never the production siem.db.
app.DB_PATH = TEST_DB
app.alert_cooldowns.clear()
app.init_db()


def get_alerts():
    with sqlite3.connect(TEST_DB) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY id"
        ).fetchall()
        return [dict(row) for row in rows]


def check_detection(name, expected_title):
    alerts = get_alerts()

    matching = [
        alert for alert in alerts
        if alert["title"] == expected_title
    ]

    if matching:
        print(f"PASS: {name}")
        for alert in matching:
            print(f"  Severity: {alert['severity']}")
            print(f"  Risk: {alert['risk']}")
        return True

    print(f"FAIL: {name}")
    print(f"  Expected alert: {expected_title}")
    print("  Alerts currently in test database:")
    for alert in alerts:
        print(f"    - {alert['title']}")
    return False


def make_event(event_id, record_number, event_time, fields):
    return {
        "event_id": event_id,
        "source": "SIEM-Synthetic-Test",
        "time": event_time.isoformat(),
        "category": 0,
        "record_number": record_number,
        "computer": "TEST-PC",
        "message": " | ".join(fields),
        "fields": fields,
    }


now = datetime.now().astimezone().replace(tzinfo=None)
results = []

print("\n=== SIEM SYNTHETIC DETECTION TESTS ===")
print("Test database:", TEST_DB)
print("Production database: NOT USED\n")


# Test 1: Five failed logons within five minutes.
failed_events = []

for i in range(5):
    event_time = now - timedelta(minutes=4 - i)
    failed_events.append(
        make_event(
            4625,
            950000 + i,
            event_time,
            ["SIMULATED", "failed-login-test", f"attempt-{i + 1}"],
        )
    )

app.store_windows_events(failed_events)

results.append(
    check_detection(
        "Repeated failed logins (4625)",
        "Repeated failed Windows logins",
    )
)


# Test 2: Windows Security audit log cleared.
app.store_windows_events([
    make_event(
        1102,
        951001,
        now,
        ["SIMULATED", "security-log-cleared-test"],
    )
])

results.append(
    check_detection(
        "Security log cleared (1102)",
        "Windows Security log cleared",
    )
)


# Test 3: A Windows user account was created.
app.store_windows_events([
    make_event(
        4720,
        952001,
        now,
        ["SIMULATED", "new-account-test"],
    )
])

results.append(
    check_detection(
        "User account creation (4720)",
        "Windows user account created",
    )
)


# Test 4: A member was added to a global security group.
app.store_windows_events([
    make_event(
        4728,
        953001,
        now,
        ["SIMULATED", "global-group-membership-test"],
    )
])

results.append(
    check_detection(
        "Global security group membership change (4728)",
        "Global security group membership changed",
    )
)


# Test 5: A member was added to a local security group.
app.store_windows_events([
    make_event(
        4732,
        954001,
        now,
        ["SIMULATED", "local-group-membership-test"],
    )
])

results.append(
    check_detection(
        "Local security group membership change (4732)",
        "Local security group membership changed",
    )
)


print("\n=== TEST SUMMARY ===")
passed = sum(results)
failed = len(results) - passed
print(f"Passed: {passed} / {len(results)}")
print(f"Failed: {failed} / {len(results)}")
print("Test database:", TEST_DB)
print("Production database was not used.")

if failed:
    raise SystemExit(1)
