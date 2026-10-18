import copy
import io
import unittest
from contextlib import redirect_stdout
from datetime import timedelta

from demo_login_correlation import main, run_demo
from fingerprint import match_fingerprints
from login_correlation_prototype import (
    DEFAULT_MAXIMUM_START_SKEW,
    DEFAULT_MINIMUM_WINDOW_OVERLAP,
    MINIMUM_FAILED_LOGIN_COUNT,
    correlate_repeated_failed_logins,
    validate_login_evidence,
)
from synthetic_login_fixtures import (
    SCHEMA_VERSION,
    SYNTHETIC_INDICATOR_A,
    SYNTHETIC_INDICATOR_B,
    organization_a_records,
    organization_b_records,
    record,
)


class SyntheticLoginCorrelationTests(unittest.TestCase):
    def test_compatible_indicator_count_and_windows_correlate(self):
        result = correlate_repeated_failed_logins(
            [organization_a_records()[0]], [organization_b_records()[0]]
        )

        self.assertEqual(result["status"], "correlated")
        self.assertEqual(result["correlated_pair_count"], 1)
        self.assertIn("synthetic_evidence_compatible", result["reason_codes"])

    def test_different_indicators_do_not_correlate(self):
        a = organization_a_records()[0]
        b = organization_b_records()[0]
        b["protected_indicator_token"] = SYNTHETIC_INDICATOR_B

        result = correlate_repeated_failed_logins([a], [b])

        self.assertEqual(result["status"], "not_correlated")
        self.assertIn("protected_indicators_do_not_match", result["reason_codes"])

    def test_non_overlapping_windows_do_not_correlate(self):
        result = correlate_repeated_failed_logins(
            [organization_a_records()[0]], [organization_b_records()[1]]
        )

        self.assertEqual(result["status"], "not_correlated")
        self.assertIn("time_windows_incompatible", result["reason_codes"])

    def test_overlap_boundary_is_inclusive_at_minimum_and_rejects_below(self):
        a = record("ORG_A", "A1", "2026-10-18T10:00:00Z", "2026-10-18T10:15:00Z", 8, SYNTHETIC_INDICATOR_A)
        exactly_one_minute = record("ORG_B", "B1", "2026-10-18T10:14:00Z", "2026-10-18T10:29:00Z", 8, SYNTHETIC_INDICATOR_A)
        below_one_minute = record("ORG_B", "B2", "2026-10-18T10:14:01Z", "2026-10-18T10:29:01Z", 8, SYNTHETIC_INDICATOR_A)

        # Widen only the allowed start skew to isolate the overlap threshold.
        accepted = correlate_repeated_failed_logins(
            [a], [exactly_one_minute], maximum_start_skew=timedelta(minutes=15)
        )
        rejected = correlate_repeated_failed_logins(
            [a], [below_one_minute], maximum_start_skew=timedelta(minutes=15)
        )

        self.assertEqual(accepted["status"], "correlated")
        self.assertEqual(rejected["status"], "not_correlated")

    def test_start_skew_boundary_is_inclusive(self):
        a = record("ORG_A", "A1", "2026-10-18T10:00:00Z", "2026-10-18T10:15:00Z", 8, SYNTHETIC_INDICATOR_A)
        b = record("ORG_B", "B1", "2026-10-18T10:05:00Z", "2026-10-18T10:20:00Z", 8, SYNTHETIC_INDICATOR_A)

        result = correlate_repeated_failed_logins(
            [a], [b], minimum_window_overlap=DEFAULT_MINIMUM_WINDOW_OVERLAP,
            maximum_start_skew=DEFAULT_MAXIMUM_START_SKEW,
        )

        self.assertEqual(result["status"], "correlated")

    def test_below_threshold_is_not_correlated(self):
        a = organization_a_records()[0]
        b = organization_b_records()[0]
        a["failed_login_count"] = MINIMUM_FAILED_LOGIN_COUNT - 1

        result = correlate_repeated_failed_logins([a], [b])

        self.assertEqual(result["status"], "not_correlated")
        self.assertIn("below_minimum_count", result["reason_codes"])

    def test_missing_fields_and_unsupported_version_are_insufficient(self):
        missing = {"schema_version": SCHEMA_VERSION, "event_type": "repeated_failed_login"}
        unsupported = organization_a_records()[0]
        unsupported["schema_version"] = "trustnet-synthetic-login-evidence/v999"

        self.assertFalse(validate_login_evidence(missing)["valid"])
        self.assertEqual(
            validate_login_evidence(unsupported)["reason_codes"],
            ["unsupported_schema_version"],
        )
        result = correlate_repeated_failed_logins([missing], [organization_b_records()[0]])
        self.assertEqual(result["status"], "insufficient_evidence")

    def test_invalid_timestamps_reversed_windows_and_wrong_types_rejected(self):
        base = organization_a_records()[0]
        cases = []
        invalid_timestamp = dict(base, window_start_utc="yesterday")
        reversed_window = dict(base, window_start_utc="2026-10-18T10:15:00Z", window_end_utc="2026-10-18T10:00:00Z")
        wrong_count_type = dict(base, failed_login_count=True)
        wrong_token_type = dict(base, protected_indicator_token=123)
        wrong_org_type = dict(base, organization_id=[])
        cases.extend((invalid_timestamp, reversed_window, wrong_count_type, wrong_token_type, wrong_org_type))

        for candidate in cases:
            with self.subTest(candidate=candidate):
                self.assertFalse(validate_login_evidence(candidate)["valid"])
                result = correlate_repeated_failed_logins([candidate], [organization_b_records()[0]])
                self.assertEqual(result["status"], "insufficient_evidence")

    def test_duplicate_records_are_deterministically_deduplicated(self):
        a = organization_a_records()[0]
        b = organization_b_records()[0]

        result = correlate_repeated_failed_logins([a, dict(a)], [b, dict(b)])
        repeat = correlate_repeated_failed_logins([dict(a), a], [dict(b), b])

        self.assertEqual(result, repeat)
        self.assertEqual(result["status"], "correlated")
        self.assertEqual(result["duplicates_removed_count"], 2)
        self.assertEqual(result["evaluated_pair_count"], 1)

    def test_conflicting_duplicate_local_id_is_quarantined(self):
        first = organization_a_records()[0]
        conflict = dict(first, failed_login_count=9)

        result = correlate_repeated_failed_logins(
            [first, conflict], [organization_b_records()[0]]
        )

        self.assertEqual(result["status"], "insufficient_evidence")
        self.assertEqual(result["correlated_pair_count"], 0)

    def test_same_count_different_indicator_does_not_correlate(self):
        a = organization_a_records()[1]
        b = record("ORG_B", "B-SAME-COUNT", "2026-10-18T11:01:00Z", "2026-10-18T11:16:00Z", 8, SYNTHETIC_INDICATOR_A)

        result = correlate_repeated_failed_logins([a], [b])

        self.assertEqual(a["failed_login_count"], b["failed_login_count"])
        self.assertEqual(result["status"], "not_correlated")

    def test_same_indicator_with_incompatible_time_does_not_correlate(self):
        a = organization_a_records()[0]
        b = organization_b_records()[1]

        self.assertEqual(a["protected_indicator_token"], b["protected_indicator_token"])
        result = correlate_repeated_failed_logins([a], [b])
        self.assertEqual(result["status"], "not_correlated")

    def test_inputs_are_not_mutated_and_output_does_not_expose_identifiers(self):
        a = organization_a_records()[0]
        b = organization_b_records()[0]
        before = copy.deepcopy((a, b))

        result = correlate_repeated_failed_logins([a], [b])

        self.assertEqual((a, b), before)
        output = str(result)
        for private_value in (a["local_aggregation_id"], b["local_aggregation_id"], a["protected_indicator_token"]):
            self.assertNotIn(private_value, output)
        self.assertNotIn("192.168.", output)
        self.assertNotIn("username", output)

    def test_raw_indicators_are_not_accepted_as_protected_tokens(self):
        a = organization_a_records()[0]
        a["protected_indicator_token"] = "192.0.2.25"

        self.assertFalse(validate_login_evidence(a)["valid"])
        result = correlate_repeated_failed_logins([a], [organization_b_records()[0]])
        self.assertEqual(result["status"], "insufficient_evidence")

    def test_category_matcher_remains_category_only_and_unchanged(self):
        result = match_fingerprints(
            [{"event_type": " repeated_failed_login "}],
            [{"event_type": "REPEATED_FAILED_LOGIN", "failed_login_count": 1}],
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["match_status"], "CATEGORY_MATCH")
        self.assertEqual(set(result[0]), {"fingerprint", "event_type", "match_status"})

    def test_demo_covers_evaluation_matrix_with_expected_outcomes(self):
        results = run_demo()
        outcomes = {item["scenario"]: item["actual_outcome"] for item in results}

        self.assertTrue(all(item["passed"] for item in results))
        self.assertEqual(outcomes["compatible_indicator_and_overlapping_windows"], "correlated")
        self.assertEqual(outcomes["different_indicators"], "not_correlated")
        self.assertEqual(outcomes["same_indicator_non_overlapping_windows"], "not_correlated")
        self.assertEqual(outcomes["below_minimum_failed_login_count"], "not_correlated")
        self.assertEqual(outcomes["count_at_minimum_threshold"], "correlated")
        self.assertEqual(outcomes["start_skew_at_allowed_boundary"], "correlated")
        self.assertEqual(outcomes["start_skew_above_allowed_boundary"], "not_correlated")
        self.assertEqual(outcomes["exact_duplicate_evidence"], "correlated")
        self.assertEqual(outcomes["conflicting_duplicate_identifier"], "insufficient_evidence")
        self.assertEqual(outcomes["missing_required_field"], "insufficient_evidence")
        self.assertEqual(outcomes["invalid_field_type"], "insufficient_evidence")
        self.assertEqual(outcomes["repeated_execution_is_deterministic"], "correlated")

    def test_demo_prints_expected_actual_pass_and_safe_reasons_only(self):
        output = io.StringIO()
        with redirect_stdout(output):
            main()
        rendered = output.getvalue()

        self.assertIn("expected: correlated", rendered)
        self.assertIn("actual: correlated", rendered)
        self.assertIn("PASS", rendered)
        self.assertIn("reasons: synthetic_evidence_compatible", rendered)
        for secret in (
            SYNTHETIC_INDICATOR_A,
            SYNTHETIC_INDICATOR_B,
            "SYNTHETIC_ONLY_AGGREGATION:",
            "A-AGG-001",
            "B-AGG-001",
            "192.168.",
            "username",
        ):
            self.assertNotIn(secret, rendered)

    def test_demo_reason_codes_reuse_existing_prototype_vocabulary(self):
        existing_reason_codes = {
            "below_minimum_count",
            "fields_outside_prototype_allowlist",
            "invalid_or_missing_utc_timestamp",
            "invalid_synthetic_indicator_token",
            "invalid_failed_login_count",
            "invalid_synthetic_aggregation_id",
            "invalid_synthetic_organization",
            "invalid_records_ignored",
            "no_valid_cross_organization_pair",
            "no_valid_evidence_pair",
            "protected_indicators_do_not_match",
            "record_must_be_object",
            "required_fields_missing",
            "synthetic_evidence_compatible",
            "synthetic_data_required",
            "time_windows_incompatible",
            "unsupported_schema_version",
            "unsupported_event_type",
            "window_end_not_after_start",
            "window_exceeds_maximum",
        }
        emitted = {
            reason
            for item in run_demo()
            for reason in item["reason_codes"]
        }

        self.assertLessEqual(emitted, existing_reason_codes)


if __name__ == "__main__":
    unittest.main()
