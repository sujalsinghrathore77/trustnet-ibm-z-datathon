import unittest

from correlation_readiness import (
    EVIDENCE_SCHEMA_VERSION,
    assess_sanitized_alert,
    assess_sanitized_alerts,
    parse_utc_timestamp,
    validate_evidence_record,
)
from detector import detect_threats
from privacy import sanitize_alerts


class TimestampReadinessTests(unittest.TestCase):
    def test_offset_timestamp_is_normalized_to_utc(self):
        result = parse_utc_timestamp("2026-10-18T15:30:00+05:30")

        self.assertEqual(result, {
            "status": "VALID",
            "utc": "2026-10-18T10:00:00Z",
        })

    def test_utc_z_timestamp_is_preserved_as_normalized_utc(self):
        self.assertEqual(
            parse_utc_timestamp("2026-10-18T10:00:00Z")["utc"],
            "2026-10-18T10:00:00Z",
        )

    def test_timezone_naive_timestamp_is_not_assumed_to_be_utc(self):
        self.assertEqual(
            parse_utc_timestamp("2026-10-18T10:00:00")["status"],
            "TIMEZONE_REQUIRED",
        )

    def test_legacy_clock_only_timestamp_is_not_given_a_date(self):
        self.assertEqual(
            parse_utc_timestamp("11:05")["status"],
            "LEGACY_TIME_ONLY",
        )

    def test_missing_and_malformed_timestamps_are_distinguished(self):
        self.assertEqual(parse_utc_timestamp(None)["status"], "MISSING")
        self.assertEqual(parse_utc_timestamp("not-a-time")["status"], "MALFORMED")
        self.assertEqual(parse_utc_timestamp(123)["status"], "MALFORMED")


class EvidenceSchemaTests(unittest.TestCase):
    def _evidence_record(self, event_type):
        common = {
            "schema_version": EVIDENCE_SCHEMA_VERSION,
            "event_type": event_type,
        }
        if event_type == "repeated_failed_login":
            return dict(common, **{
                "window_start_utc": "2026-10-18T10:00:00Z",
                "window_end_utc": "2026-10-18T10:15:00Z",
                "failed_attempts_band": "10-19",
                "service_class": "ssh",
                "protected_origin_overlap": True,
            })
        if event_type == "outbound":
            return dict(common, **{
                "occurred_at_utc": "2026-10-18T10:00:00Z",
                "destination_service_class": "reviewed-service-class",
                "transfer_size_band": "reviewed-size-band",
                "protected_destination_overlap": True,
            })
        return dict(common, **{
            "window_start_utc": "2026-10-18T10:00:00Z",
            "window_end_utc": "2026-10-18T10:05:00Z",
            "scan_volume_band": "reviewed-volume-band",
            "protected_target_set_overlap": True,
            "protected_port_set_overlap": True,
        })

    def test_test_only_records_validate_for_each_versioned_event_schema(self):
        # Synthetic contract fixtures only; never produced by the detector or API.
        for event_type in ("repeated_failed_login", "outbound", "port_scan"):
            with self.subTest(event_type=event_type):
                result = validate_evidence_record(self._evidence_record(event_type))
                self.assertEqual(result["status"], "VALID_SCHEMA_ONLY")
                self.assertEqual(result["issues"], [])

    def test_raw_sensitive_field_is_rejected_by_allowlist(self):
        record = self._evidence_record("outbound")
        record["destination_ip"] = "203.0.113.8"

        result = validate_evidence_record(record)

        self.assertEqual(result["status"], "INVALID")
        self.assertIn("fields_outside_privacy_allowlist", result["issues"])

    def test_missing_required_fields_are_insufficient_not_matches(self):
        result = validate_evidence_record({
            "schema_version": EVIDENCE_SCHEMA_VERSION,
            "event_type": "outbound",
        })

        self.assertEqual(result["status"], "INSUFFICIENT_EVIDENCE")
        self.assertIn("occurred_at_utc", result["missing_fields"])

    def test_malformed_timestamp_and_window_are_rejected(self):
        record = self._evidence_record("port_scan")
        record["window_start_utc"] = "yesterday"

        result = validate_evidence_record(record)

        self.assertEqual(result["status"], "INVALID")
        self.assertIn("timestamp_malformed", result["issues"])

        record = self._evidence_record("port_scan")
        record["window_end_utc"] = "2026-10-18T10:06:00Z"
        result = validate_evidence_record(record)
        self.assertEqual(result["status"], "INVALID")
        self.assertIn("window_exceeds_event_limit", result["issues"])

    def test_non_object_and_unknown_event_type_are_invalid(self):
        self.assertEqual(validate_evidence_record(None)["status"], "INVALID")
        self.assertEqual(
            validate_evidence_record({"event_type": "unknown"})["status"],
            "INVALID",
        )


class ExistingAlertReadinessTests(unittest.TestCase):
    def test_current_sample_alerts_are_insufficient_for_event_correlation(self):
        for filename in (
            "sample_data/organization_a.csv",
            "sample_data/organization_b.csv",
        ):
            alerts = sanitize_alerts(detect_threats(filename))
            assessments = [assess_sanitized_alert(alert) for alert in alerts]

            self.assertEqual(len(assessments), len(alerts))
            self.assertTrue(all(
                result["status"] == "INSUFFICIENT_EVIDENCE"
                for result in assessments
            ))

    def test_identical_records_are_not_deduplicated_without_stable_local_ids(self):
        alert = {
            "event_type": "port_scan",
            "timestamp": "10:07:00",
            "severity": "MEDIUM",
            "reasons": ["Possible port scanning activity"],
        }

        assessments = assess_sanitized_alerts([alert, dict(alert)])

        self.assertEqual(len(assessments), 2)
        self.assertTrue(all(
            result["status"] == "INSUFFICIENT_EVIDENCE"
            for result in assessments
        ))

    def test_local_only_identifier_cannot_enter_shared_evidence(self):
        alert = {
            "event_type": "outbound",
            "local_event_id": "local-only-123",
        }

        result = assess_sanitized_alert(alert)

        self.assertEqual(result["status"], "INVALID")
        self.assertEqual(result["issues"], ["local_only_field_present"])


if __name__ == "__main__":
    unittest.main()
