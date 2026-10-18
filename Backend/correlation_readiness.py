"""Versioned evidence contracts and readiness checks; no correlation logic."""

from datetime import datetime, timedelta, timezone


EVIDENCE_SCHEMA_VERSION = "trustnet-correlation-evidence/v1"
CORRELATION_CLOCK_SKEW_TOLERANCE = timedelta(minutes=5)

# These are proposed evidence contracts. The detector does not currently emit
# these records, and this module never constructs them from alert data.
EVENT_EVIDENCE_SCHEMAS = {
    "repeated_failed_login": {
        "required": {
            "schema_version",
            "event_type",
            "window_start_utc",
            "window_end_utc",
            "failed_attempts_band",
            "service_class",
            "protected_origin_overlap",
        },
        "allowed": {
            "schema_version",
            "event_type",
            "window_start_utc",
            "window_end_utc",
            "failed_attempts_band",
            "service_class",
            "protected_origin_overlap",
        },
        "max_window": timedelta(minutes=15),
        "timestamps": ("window_start_utc", "window_end_utc"),
        "boolean_fields": ("protected_origin_overlap",),
        "string_fields": ("failed_attempts_band", "service_class"),
    },
    "outbound": {
        "required": {
            "schema_version",
            "event_type",
            "occurred_at_utc",
            "destination_service_class",
            "transfer_size_band",
            "protected_destination_overlap",
        },
        "allowed": {
            "schema_version",
            "event_type",
            "occurred_at_utc",
            "destination_service_class",
            "transfer_size_band",
            "protected_destination_overlap",
        },
        "timestamps": ("occurred_at_utc",),
        "boolean_fields": ("protected_destination_overlap",),
        "string_fields": ("destination_service_class", "transfer_size_band"),
    },
    "port_scan": {
        "required": {
            "schema_version",
            "event_type",
            "window_start_utc",
            "window_end_utc",
            "scan_volume_band",
            "protected_target_set_overlap",
            "protected_port_set_overlap",
        },
        "allowed": {
            "schema_version",
            "event_type",
            "window_start_utc",
            "window_end_utc",
            "scan_volume_band",
            "protected_target_set_overlap",
            "protected_port_set_overlap",
        },
        "max_window": timedelta(minutes=5),
        "timestamps": ("window_start_utc", "window_end_utc"),
        "boolean_fields": (
            "protected_target_set_overlap",
            "protected_port_set_overlap",
        ),
        "string_fields": ("scan_volume_band",),
    },
}

# Alert fields that must stay with the originating organization. The versioned
# evidence allowlists above reject these and every other unlisted field.
LOCAL_ONLY_FIELDS = frozenset({
    "source_ip",
    "destination_ip",
    "src_ip",
    "dst_ip",
    "username",
    "email",
    "hostname",
    "mac_address",
    "device_id",
    "user_id",
    "credential",
    "password",
    "raw_record",
    "raw_log",
    "local_event_id",
})


def parse_utc_timestamp(value):
    """Parse an offset-aware ISO timestamp and normalize it to UTC.

    Legacy clock-only values (for example ``10:05:00``) are explicitly
    identified and rejected as correlation timestamps because date and
    timezone cannot safely be inferred.
    """
    if value is None or value == "":
        return {"status": "MISSING", "utc": None}
    if not isinstance(value, str):
        return {"status": "MALFORMED", "utc": None}

    text = value.strip()
    if not text:
        return {"status": "MISSING", "utc": None}
    if len(text) <= 15 and "T" not in text and " " not in text:
        try:
            datetime.strptime(text, "%H:%M:%S")
            return {"status": "LEGACY_TIME_ONLY", "utc": None}
        except ValueError:
            try:
                datetime.strptime(text, "%H:%M")
                return {"status": "LEGACY_TIME_ONLY", "utc": None}
            except ValueError:
                pass

    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return {"status": "MALFORMED", "utc": None}

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return {"status": "TIMEZONE_REQUIRED", "utc": None}

    normalized = parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return {"status": "VALID", "utc": normalized}


def validate_evidence_record(record):
    """Validate a proposed v1 evidence record without correlating it."""
    if not isinstance(record, dict):
        return {"status": "INVALID", "issues": ["record_must_be_object"], "normalized_timestamps": {}}

    event_type = record.get("event_type")
    schema = EVENT_EVIDENCE_SCHEMAS.get(event_type)
    if schema is None:
        return {"status": "INVALID", "issues": ["unsupported_event_type"], "normalized_timestamps": {}}

    issues = []
    if record.get("schema_version") != EVIDENCE_SCHEMA_VERSION:
        issues.append("unsupported_or_missing_schema_version")

    unknown_fields = set(record) - schema["allowed"]
    if unknown_fields:
        issues.append("fields_outside_privacy_allowlist")

    missing_fields = sorted(schema["required"] - set(record))
    normalized_timestamps = {}
    timestamp_status = None

    for field in schema["timestamps"]:
        parsed = parse_utc_timestamp(record.get(field))
        if parsed["status"] == "VALID":
            normalized_timestamps[field] = parsed["utc"]
        elif parsed["status"] == "MISSING":
            if field not in missing_fields:
                missing_fields.append(field)
        else:
            timestamp_status = parsed["status"]

    for field in schema["boolean_fields"]:
        if field in record and not isinstance(record[field], bool):
            issues.append("invalid_boolean_field:{0}".format(field))

    for field in schema["string_fields"]:
        if field in record and (not isinstance(record[field], str) or not record[field].strip()):
            issues.append("invalid_string_field:{0}".format(field))

    if "window_start_utc" in normalized_timestamps and "window_end_utc" in normalized_timestamps:
        start = datetime.fromisoformat(normalized_timestamps["window_start_utc"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(normalized_timestamps["window_end_utc"].replace("Z", "+00:00"))
        if end < start:
            issues.append("window_end_before_start")
        elif end - start > schema["max_window"]:
            issues.append("window_exceeds_event_limit")

    if issues:
        status = "INVALID"
    elif timestamp_status is not None:
        status = "INSUFFICIENT_EVIDENCE" if timestamp_status == "TIMEZONE_REQUIRED" else "INVALID"
        issues.append("timestamp_{0}".format(timestamp_status.lower()))
    elif missing_fields:
        status = "INSUFFICIENT_EVIDENCE"
    else:
        status = "VALID_SCHEMA_ONLY"

    return {
        "status": status,
        "issues": issues,
        "missing_fields": sorted(set(missing_fields)),
        "normalized_timestamps": normalized_timestamps,
    }


def assess_sanitized_alert(alert):
    """Report readiness of a current sanitized alert; never create evidence."""
    if not isinstance(alert, dict):
        return {"status": "INVALID", "issues": ["alert_must_be_object"]}

    if LOCAL_ONLY_FIELDS.intersection(alert):
        return {"status": "INVALID", "issues": ["local_only_field_present"]}

    event_type = alert.get("event_type")
    schema = EVENT_EVIDENCE_SCHEMAS.get(event_type)
    if schema is None:
        return {"status": "INVALID", "issues": ["unsupported_event_type"]}

    timestamp_field = "occurred_at_utc" if event_type == "outbound" else "window_start_utc"
    legacy_timestamp = alert.get("timestamp")
    timestamp_status = parse_utc_timestamp(legacy_timestamp)["status"] if legacy_timestamp is not None else "MISSING"

    missing_fields = sorted(schema["required"] - set(alert))
    issues = ["insufficient_sanitized_fields"]
    if timestamp_status == "LEGACY_TIME_ONLY":
        issues.append("legacy_time_only_timestamp")
    elif timestamp_status == "MALFORMED":
        return {"status": "INVALID", "issues": ["malformed_timestamp"]}
    elif timestamp_status == "TIMEZONE_REQUIRED":
        issues.append("timestamp_timezone_missing")
    elif timestamp_status == "MISSING":
        issues.append("timestamp_missing")
    if timestamp_field not in alert and timestamp_field not in missing_fields:
        missing_fields.append(timestamp_field)

    return {
        "status": "INSUFFICIENT_EVIDENCE",
        "issues": issues,
        "missing_fields": sorted(set(missing_fields)),
    }


def assess_sanitized_alerts(alerts):
    """Preserve all records; without stable local event IDs, do not dedupe."""
    try:
        iterator = iter(alerts)
    except TypeError:
        return []
    return [assess_sanitized_alert(alert) for alert in iterator]
