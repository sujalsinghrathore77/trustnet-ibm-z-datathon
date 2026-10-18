import csv
from collections import defaultdict

# TRUSTNET detection configuration
SUSPICIOUS_PORTS = {4444, 5555, 1337}
LARGE_TRANSFER_LIMIT = 50000
FAILED_LOGIN_LIMIT = 5
REPEATED_FAILURE_LIMIT = 10


def detect_threats(file_path):
    alerts = []
    login_events = defaultdict(list)

    # Read the organization's local security logs
    with open(file_path, "r", newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)

        required_columns = {
            "timestamp",
            "source_ip",
            "event_type",
            "failed_attempts",
            "destination_port",
            "bytes_sent",
        }

        if not required_columns.issubset(set(reader.fieldnames or [])):
            raise ValueError("CSV is missing required columns")

        rows = list(reader)

    # Group failed logins by source IP
    for row in rows:
        if row["event_type"] == "failed_login":
            login_events[row["source_ip"]].append(row)

    # Generate one summary alert for repeated failed logins
    for source_ip, events in login_events.items():
        total_failures = sum(
            int(event["failed_attempts"] or 0)
            for event in events
        )

        if total_failures >= FAILED_LOGIN_LIMIT:
            severity = (
                "HIGH"
                if total_failures >= REPEATED_FAILURE_LIMIT
                else "MEDIUM"
            )

            alerts.append({
                "event_type": "repeated_failed_login",
                "count": len(events),
                "total_failed_attempts": total_failures,
                "severity": severity,
                "reasons": [
                    "Repeated failed login attempts"
                ],
                "source_ip": source_ip,
            })

    # Detect other suspicious events
    for row in rows:
        event_type = row["event_type"]
        port = int(row["destination_port"] or 0)
        sent = int(row["bytes_sent"] or 0)

        reasons = []

        if port in SUSPICIOUS_PORTS:
            reasons.append("Connection to a flagged port")

        if event_type == "outbound" and sent > LARGE_TRANSFER_LIMIT:
            reasons.append("Unusually large outbound transfer")

        if event_type == "port_scan":
            reasons.append("Possible port scanning activity")

        if reasons:
            severity = (
                "HIGH"
                if (
                    port in SUSPICIOUS_PORTS
                    and event_type == "outbound"
                    and sent > LARGE_TRANSFER_LIMIT
                )
                else "MEDIUM"
            )

            alerts.append({
                "timestamp": row["timestamp"],
                "event_type": event_type,
                "severity": severity,
                "reasons": reasons,
                "source_ip": row["source_ip"],
            })

    return alerts


if __name__ == "__main__":
    file_path = "sample_data/organization_a.csv"

    try:
        results = detect_threats(file_path)

        print("\n===== TRUSTNET THREAT DETECTION =====")

        for number, alert in enumerate(results, start=1):
            print(f"\nAlert {number}")
            print("Event:", alert["event_type"])
            print("Severity:", alert["severity"])
            print("Reasons:", ", ".join(alert["reasons"]))

            if "total_failed_attempts" in alert:
                print(
                    "Total failed attempts:",
                    alert["total_failed_attempts"]
                )

        print(f"\nTotal alerts: {len(results)}")

    except (OSError, ValueError, KeyError) as error:
        print("Detection error:", error)