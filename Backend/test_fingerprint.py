import copy
import unittest

from fingerprint import generate_fingerprint, match_fingerprints
from privacy import generate_privacy_report, sanitize_alerts


class FingerprintMatcherTests(unittest.TestCase):
    def test_identical_normalized_categories_match(self):
        left = [{"event_type": "outbound"}]
        right = [{"event_type": "outbound"}]

        matches = match_fingerprints(left, right)

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["event_type"], "outbound")
        self.assertEqual(matches[0]["match_status"], "CATEGORY_MATCH")
        self.assertEqual(matches[0]["fingerprint"], generate_fingerprint(left[0]))

    def test_different_categories_do_not_match(self):
        self.assertEqual(
            match_fingerprints(
                [{"event_type": "outbound"}],
                [{"event_type": "port_scan"}],
            ),
            [],
        )

    def test_case_and_surrounding_whitespace_are_normalized(self):
        matches = match_fingerprints(
            [{"event_type": "  OUTBOUND  "}],
            [{"event_type": "outbound"}],
        )

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["event_type"], "outbound")

    def test_duplicate_alerts_do_not_inflate_category_match_count(self):
        matches = match_fingerprints(
            [
                {"event_type": "outbound", "severity": "HIGH"},
                {"event_type": "OUTBOUND", "severity": "LOW"},
                {"event_type": "outbound"},
            ],
            [{"event_type": "outbound"}],
        )

        self.assertEqual(len(matches), 1)

    def test_missing_empty_and_null_categories_do_not_match_unknown(self):
        invalid_alerts = [{}, {"event_type": ""}, {"event_type": None}]

        self.assertIsNone(generate_fingerprint({}))
        self.assertEqual(match_fingerprints(invalid_alerts, invalid_alerts), [])

    def test_malformed_alerts_are_ignored_without_crashing(self):
        malformed = [None, "outbound", 42, [], {"event_type": ["outbound"]}]

        self.assertEqual(match_fingerprints(malformed, malformed), [])
        self.assertEqual(match_fingerprints(None, [{"event_type": "outbound"}]), [])

    def test_matching_uses_sanitized_alert_copies_and_category_only_fields(self):
        original_a = {
            "event_type": "outbound",
            "source_ip": "192.168.1.10",
            "email": "analyst@example.test",
            "reasons": ["Activity from 192.168.1.10"],
            "severity": "HIGH",
        }
        original_b = {
            "event_type": "outbound",
            "source_ip": "10.0.0.8",
            "severity": "LOW",
            "reasons": ["Different activity"],
        }
        sanitized_a = sanitize_alerts([original_a])
        sanitized_b = sanitize_alerts([original_b])

        matches = match_fingerprints(sanitized_a, sanitized_b)

        self.assertEqual(len(matches), 1)
        self.assertEqual(set(matches[0]), {"fingerprint", "event_type", "match_status"})
        self.assertEqual(matches[0]["fingerprint"], generate_fingerprint({"event_type": "outbound"}))
        self.assertNotIn("192.168.1.10", str(matches))
        self.assertNotIn("analyst@example.test", str(matches))

    def test_sanitization_does_not_mutate_original_nested_alerts(self):
        original = [{
            "event_type": "outbound",
            "source_ip": "192.168.1.10",
            "details": {"username": "analyst", "bytes_sent": 1000},
            "reasons": ["Contact analyst@example.test"],
        }]
        expected_original = copy.deepcopy(original)

        sanitized = sanitize_alerts(original)
        privacy_report = generate_privacy_report(original, sanitized)

        self.assertEqual(original, expected_original)
        self.assertNotIn("source_ip", sanitized[0])
        self.assertNotIn("username", sanitized[0]["details"])
        self.assertNotIn("@example.test", sanitized[0]["reasons"][0])
        self.assertEqual(privacy_report["privacy_check"], "PASSED")


if __name__ == "__main__":
    unittest.main()
