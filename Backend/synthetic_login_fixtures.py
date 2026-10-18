"""Deterministic, unmistakably synthetic fixtures for the isolated prototype.

These records are test/demo inputs only. They are not detector output, real
telemetry, privacy-preserving tokens, or inputs to the production API.
"""

SCHEMA_VERSION = "trustnet-synthetic-login-evidence/v1"
SYNTHETIC_INDICATOR_A = "SYNTHETIC_ONLY_LOGIN_INDICATOR:ALPHA"
SYNTHETIC_INDICATOR_B = "SYNTHETIC_ONLY_LOGIN_INDICATOR:BETA"


def record(org, local_id, start, end, count, indicator):
    """Return a fresh synthetic record so tests cannot mutate shared fixtures."""
    organization = "SYNTHETIC_ORG_A" if org == "ORG_A" else "SYNTHETIC_ORG_B"
    return {
        "schema_version": SCHEMA_VERSION,
        "event_type": "repeated_failed_login",
        "organization_id": organization,
        "local_aggregation_id": "SYNTHETIC_ONLY_AGGREGATION:" + local_id,
        "window_start_utc": start,
        "window_end_utc": end,
        "failed_login_count": count,
        "protected_indicator_token": indicator,
        "synthetic": True,
    }


def organization_a_records():
    return [
        record(
            "ORG_A",
            "A-AGG-001",
            "2026-10-18T10:00:00Z",
            "2026-10-18T10:15:00Z",
            8,
            SYNTHETIC_INDICATOR_A,
        ),
        # Same count, different indicator: must not correlate by count alone.
        record(
            "ORG_A",
            "A-AGG-002",
            "2026-10-18T11:00:00Z",
            "2026-10-18T11:15:00Z",
            8,
            SYNTHETIC_INDICATOR_B,
        ),
    ]


def organization_b_records():
    return [
        record(
            "ORG_B",
            "B-AGG-001",
            "2026-10-18T10:05:00Z",
            "2026-10-18T10:20:00Z",
            7,
            SYNTHETIC_INDICATOR_A,
        ),
        # Same indicator as A-AGG-001, but a disjoint window.
        record(
            "ORG_B",
            "B-AGG-002",
            "2026-10-18T12:00:00Z",
            "2026-10-18T12:15:00Z",
            8,
            SYNTHETIC_INDICATOR_A,
        ),
    ]
