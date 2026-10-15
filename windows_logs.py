
import json

import win32evtlog


# Windows Security event IDs collected by this SIEM.
SECURITY_EVENT_IDS = {
    4624,  # Successful logon
    4625,  # Failed logon
    1102,  # Security audit log cleared
    4688,  # Process creation
    4720,  # User account created
    4728,  # Member added to a global security group
    4732,  # Member added to a local security group
}


def read_security_events(limit=50):
    """Read recent Windows Security events and extract event fields."""
    handle = None
    events = []

    try:
        handle = win32evtlog.OpenEventLog(
            "localhost",
            "Security",
        )

        flags = (
            win32evtlog.EVENTLOG_BACKWARDS_READ
            | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        )

        while len(events) < limit:
            batch = win32evtlog.ReadEventLog(
                handle,
                flags,
                0,
            )

            if not batch:
                break

            for event in batch:
                event_id = event.EventID & 0xFFFF

                if event_id not in SECURITY_EVENT_IDS:
                    continue

                inserts = event.StringInserts or []
                fields = [str(value) for value in inserts]

                events.append({
                    "event_id": event_id,
                    "source": event.SourceName,
                    "time": event.TimeGenerated.isoformat(),
                    "category": event.EventCategory,
                    "record_number": event.RecordNumber,
                    "computer": event.ComputerName,
                    "message": " | ".join(fields)
                    or "No event fields available",
                    "fields": fields,
                })

                if len(events) >= limit:
                    break

        return events

    except Exception as exc:
        return {
            "error": str(exc),
            "hint": (
                "Check Windows Security log permissions. "
                "The server may need to run with elevated privileges."
            ),
        }

    finally:
        if handle is not None:
            try:
                win32evtlog.CloseEventLog(handle)
            except Exception:
                pass


if __name__ == "__main__":
    result = read_security_events(limit=10)

    if isinstance(result, dict):
        print("ERROR:", result["error"])
        print(result["hint"])
    else:
        print(json.dumps(
            result,
            indent=2,
            ensure_ascii=False,
        ))
