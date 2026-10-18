# ==========================================
# TRUSTNET - Privacy Protection Module
# ==========================================

import re
from copy import deepcopy


# Fields that should never be shared directly.
SENSITIVE_FIELDS = {
    "source_ip",
    "destination_ip",
    "src_ip",
    "dst_ip",
    "source_ip_address",
    "destination_ip_address",
    "src_address",
    "dst_address",
    "username",
    "user_name",
    "email",
    "destination_email",
    "hostname",
    "mac_address",
    "device_id",
    "user_id",
    "internal_ip",
    "private_ip",
}

# Common IP address and email patterns.
SENSITIVE_TEXT_PATTERNS = [
    re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    ),
    re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    ),
]


def is_sensitive_field(key):
    """Identify common sensitive field names."""
    normalized_key = str(key).lower().strip()

    if normalized_key in SENSITIVE_FIELDS:
        return True

    # Catch common variations such as source_ip_address.
    sensitive_tokens = (
        "ip",
        "email",
        "username",
        "hostname",
        "mac_address",
        "device_id",
        "user_id",
    )

    return any(
        token in normalized_key
        for token in sensitive_tokens
    )


def sanitize_value(value):
    """Recursively sanitize nested values."""

    if isinstance(value, str):
        for pattern in SENSITIVE_TEXT_PATTERNS:
            value = pattern.sub("[REDACTED]", value)

        return value

    if isinstance(value, list):
        return [sanitize_value(item) for item in value]

    if isinstance(value, dict):
        return sanitize_record(value)

    if isinstance(value, tuple):
        return tuple(sanitize_value(item) for item in value)

    return value


def sanitize_record(record):
    """Remove sensitive fields recursively."""

    safe_record = {}

    for key, value in record.items():
        if is_sensitive_field(key):
            continue

        safe_record[key] = sanitize_value(value)

    return safe_record


def sanitize_alerts(alerts):
    """Return sanitized copies without modifying originals."""

    return [
        sanitize_record(deepcopy(alert))
        for alert in alerts
    ]


def find_privacy_leaks(data, path=""):
    """Find sensitive fields and unredacted IP/email patterns."""

    leaks = []

    if isinstance(data, dict):
        for key, value in data.items():
            current_path = (
                f"{path}.{key}" if path else str(key)
            )

            if is_sensitive_field(key):
                leaks.append(current_path)

            leaks.extend(
                find_privacy_leaks(value, current_path)
            )

    elif isinstance(data, (list, tuple)):
        for index, value in enumerate(data):
            leaks.extend(
                find_privacy_leaks(
                    value,
                    f"{path}[{index}]",
                )
            )

    elif isinstance(data, str):
        for pattern in SENSITIVE_TEXT_PATTERNS:
            if pattern.search(data):
                leaks.append(path)
                break

    return leaks


def generate_privacy_report(original_alerts, shared_alerts):
    """Report the actual result of privacy validation."""

    leaks = find_privacy_leaks(shared_alerts)

    # Verify that the number of records is preserved.
    record_counts_match = (
        len(original_alerts) == len(shared_alerts)
    )

    privacy_passed = (
        not leaks
        and record_counts_match
    )

    return {
        "original_alert_count": len(original_alerts),
        "shared_alert_count": len(shared_alerts),
        "sensitive_fields_removed": not leaks,
        "record_counts_match": record_counts_match,
        "privacy_check": (
            "PASSED" if privacy_passed else "FAILED"
        ),
        "leak_count": len(leaks),
        "leak_locations": leaks,
    }


if __name__ == "__main__":

    sample_alerts = [
        {
            "event_type": "outbound",
            "severity": "HIGH",
            "source_ip": "192.168.1.25",
            "reasons": [
                "Unusually large outbound transfer from 192.168.1.25"
            ],
            "details": {
                "username": "demo_user",
                "bytes_sent": 95000,
            },
        }
    ]

    shared_alerts = sanitize_alerts(sample_alerts)

    report = generate_privacy_report(
        sample_alerts,
        shared_alerts,
    )

    print("\n===== TRUSTNET PRIVACY REPORT =====")
    print("Shared alerts:", shared_alerts)

    for key, value in report.items():
        print(f"{key}: {value}")