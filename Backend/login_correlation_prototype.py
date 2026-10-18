"""Synthetic-only repeated failed-login correlation prototype.

This module is deliberately separate from detector, API, collaboration, and
category fingerprint code. Its synthetic indicator tokens are placeholders,
not a cryptographic construction or production-safe shared identifier.
"""

from datetime import datetime, timedelta

from correlation_readiness import parse_utc_timestamp


SCHEMA_VERSION = "trustnet-synthetic-login-evidence/v1"
EVENT_TYPE = "repeated_failed_login"
MINIMUM_FAILED_LOGIN_COUNT = 5
MAX_EVIDENCE_WINDOW = timedelta(minutes=15)
DEFAULT_MINIMUM_WINDOW_OVERLAP = timedelta(minutes=1)
DEFAULT_MAXIMUM_START_SKEW = timedelta(minutes=5)
MAXIMUM_CONFIGURED_OVERLAP = timedelta(minutes=15)
SYNTHETIC_TOKEN_PREFIX = "SYNTHETIC_ONLY_LOGIN_INDICATOR:"
SYNTHETIC_AGGREGATION_ID_PREFIX = "SYNTHETIC_ONLY_AGGREGATION:"
SYNTHETIC_ORGANIZATIONS = frozenset({"SYNTHETIC_ORG_A", "SYNTHETIC_ORG_B"})

_ALLOWED_FIELDS = frozenset({
    "schema_version",
    "event_type",
    "organization_id",
    "local_aggregation_id",
    "window_start_utc",
    "window_end_utc",
    "failed_login_count",
    "protected_indicator_token",
    "synthetic",
})


def _parse_utc(value):
    parsed = parse_utc_timestamp(value)
    if parsed["status"] != "VALID":
        return None
    return datetime.fromisoformat(parsed["utc"].replace("Z", "+00:00"))


def validate_login_evidence(record):
    """Return validation status and generic reason codes, never input values."""
    if not isinstance(record, dict):
        return {"valid": False, "reason_codes": ["record_must_be_object"]}

    if set(record) - _ALLOWED_FIELDS:
        return {"valid": False, "reason_codes": ["fields_outside_prototype_allowlist"]}

    required = _ALLOWED_FIELDS
    missing = required - set(record)
    if missing:
        return {"valid": False, "reason_codes": ["required_fields_missing"]}

    if record.get("schema_version") != SCHEMA_VERSION:
        return {"valid": False, "reason_codes": ["unsupported_schema_version"]}
    if record.get("event_type") != EVENT_TYPE:
        return {"valid": False, "reason_codes": ["unsupported_event_type"]}
    if record.get("synthetic") is not True:
        return {"valid": False, "reason_codes": ["synthetic_data_required"]}
    organization_id = record.get("organization_id")
    if (
        not isinstance(organization_id, str)
        or organization_id not in SYNTHETIC_ORGANIZATIONS
    ):
        return {"valid": False, "reason_codes": ["invalid_synthetic_organization"]}
    local_id = record.get("local_aggregation_id")
    if (
        not isinstance(local_id, str)
        or not local_id.startswith(SYNTHETIC_AGGREGATION_ID_PREFIX)
        or len(local_id) <= len(SYNTHETIC_AGGREGATION_ID_PREFIX)
        or any(char.isspace() for char in local_id)
    ):
        return {"valid": False, "reason_codes": ["invalid_synthetic_aggregation_id"]}

    count = record.get("failed_login_count")
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        return {"valid": False, "reason_codes": ["invalid_failed_login_count"]}

    token = record.get("protected_indicator_token")
    if (
        not isinstance(token, str)
        or not token.startswith(SYNTHETIC_TOKEN_PREFIX)
        or len(token) <= len(SYNTHETIC_TOKEN_PREFIX)
        or any(char.isspace() for char in token)
    ):
        return {"valid": False, "reason_codes": ["invalid_synthetic_indicator_token"]}

    start = _parse_utc(record.get("window_start_utc"))
    end = _parse_utc(record.get("window_end_utc"))
    if start is None or end is None:
        return {"valid": False, "reason_codes": ["invalid_or_missing_utc_timestamp"]}
    if end <= start:
        return {"valid": False, "reason_codes": ["window_end_not_after_start"]}
    if end - start > MAX_EVIDENCE_WINDOW:
        return {"valid": False, "reason_codes": ["window_exceeds_maximum"]}

    return {
        "valid": True,
        "reason_codes": [],
        "window_start": start,
        "window_end": end,
    }


def _validate_policy(minimum_window_overlap, maximum_start_skew):
    if not isinstance(minimum_window_overlap, timedelta):
        raise ValueError("minimum_window_overlap_must_be_timedelta")
    if not isinstance(maximum_start_skew, timedelta):
        raise ValueError("maximum_start_skew_must_be_timedelta")
    if not timedelta(0) < minimum_window_overlap <= MAXIMUM_CONFIGURED_OVERLAP:
        raise ValueError("minimum_window_overlap_out_of_bounds")
    if not timedelta(0) <= maximum_start_skew <= MAXIMUM_CONFIGURED_OVERLAP:
        raise ValueError("maximum_start_skew_out_of_bounds")


def _deduplicate(records):
    """Deduplicate exact repeated records by local ID; quarantine ID conflicts."""
    unique = {}
    conflicts = set()
    invalid_count = 0
    duplicates_removed = 0

    if not isinstance(records, (list, tuple)):
        return {}, 0, 0, 1

    for record in records:
        validation = validate_login_evidence(record)
        if not validation["valid"]:
            invalid_count += 1
            continue
        local_id = record["local_aggregation_id"]
        if local_id in conflicts:
            invalid_count += 1
            continue
        existing = unique.get(local_id)
        if existing is None:
            unique[local_id] = record
        elif existing == record:
            duplicates_removed += 1
        else:
            # Conflicting content under one local aggregation ID is ambiguous.
            del unique[local_id]
            conflicts.add(local_id)
            invalid_count += 2

    return unique, duplicates_removed, invalid_count, 0


def correlate_repeated_failed_logins(
    organization_a_records,
    organization_b_records,
    minimum_count=MINIMUM_FAILED_LOGIN_COUNT,
    minimum_window_overlap=DEFAULT_MINIMUM_WINDOW_OVERLAP,
    maximum_start_skew=DEFAULT_MAXIMUM_START_SKEW,
):
    """Compare synthetic records; return aggregate status without raw IDs/tokens."""
    _validate_policy(minimum_window_overlap, maximum_start_skew)
    if isinstance(minimum_count, bool) or not isinstance(minimum_count, int) or minimum_count < 1:
        raise ValueError("minimum_count_must_be_positive_integer")

    a, dedup_a, invalid_a, container_error_a = _deduplicate(organization_a_records)
    b, dedup_b, invalid_b, container_error_b = _deduplicate(organization_b_records)
    invalid_count = invalid_a + invalid_b
    if container_error_a or container_error_b:
        invalid_count += container_error_a + container_error_b

    reason_codes = set()
    correlated_pairs = 0
    evaluated_pairs = 0
    org_pairs = 0

    for record_a in a.values():
        for record_b in b.values():
            if record_a["organization_id"] == record_b["organization_id"]:
                continue
            org_pairs += 1
            if record_a["failed_login_count"] < minimum_count or record_b["failed_login_count"] < minimum_count:
                reason_codes.add("below_minimum_count")
                evaluated_pairs += 1
                continue

            if record_a["protected_indicator_token"] != record_b["protected_indicator_token"]:
                reason_codes.add("protected_indicators_do_not_match")
                evaluated_pairs += 1
                continue

            validation_a = validate_login_evidence(record_a)
            validation_b = validate_login_evidence(record_b)
            start_a, end_a = validation_a["window_start"], validation_a["window_end"]
            start_b, end_b = validation_b["window_start"], validation_b["window_end"]
            overlap = min(end_a, end_b) - max(start_a, start_b)
            start_skew = abs(start_a - start_b)
            evaluated_pairs += 1
            if overlap < minimum_window_overlap or start_skew > maximum_start_skew:
                reason_codes.add("time_windows_incompatible")
                continue

            correlated_pairs += 1

    if correlated_pairs:
        status = "correlated"
        reason_codes.add("synthetic_evidence_compatible")
    elif org_pairs == 0:
        status = "insufficient_evidence"
        reason_codes.add("no_valid_cross_organization_pair")
    elif invalid_count and evaluated_pairs == 0:
        status = "insufficient_evidence"
        reason_codes.add("no_valid_evidence_pair")
    else:
        status = "not_correlated"
        if invalid_count:
            reason_codes.add("invalid_records_ignored")

    return {
        "status": status,
        "reason_codes": sorted(reason_codes),
        "correlated_pair_count": correlated_pairs,
        "evaluated_pair_count": evaluated_pairs,
        "duplicates_removed_count": dedup_a + dedup_b,
        "invalid_record_count": invalid_count,
        "synthetic_only": True,
    }
