import unittest
from unittest.mock import patch

from fastapi import HTTPException

import api


class PublicIndicatorLookupTests(unittest.TestCase):
    def test_invalid_ip_is_skipped(self):
        result = api.lookup_public_ips([[{"source_ip": "not-an-ip"}]])

        self.assertEqual(result["invalid_indicators"], 1)
        self.assertEqual(result["public_ip_lookups"], 0)
        self.assertEqual(result["results"], [])

    def test_private_ip_is_skipped_once_per_distinct_indicator(self):
        result = api.lookup_public_ips([
            [{"source_ip": "192.168.1.10"}],
            [{"source_ip": "192.168.1.10"}],
        ])

        self.assertEqual(result["skipped_non_public_indicators"], 1)
        self.assertEqual(result["public_ip_lookups"], 0)
        self.assertEqual(result["results"], [])

    def test_lookup_exception_is_counted_without_exposing_exception(self):
        with patch("api.is_api_key_configured", return_value=True), \
             patch("api.is_integration_requested", return_value=True), \
             patch("api.is_integration_enabled", return_value=True), \
             patch("api.check_ip_reputation", side_effect=RuntimeError("secret detail")):
            result = api.lookup_public_ips([[{"source_ip": "8.8.8.8"}]])

        self.assertEqual(result["public_ip_lookups"], 1)
        self.assertEqual(result["lookup_errors"], 1)
        self.assertEqual(result["results"][0]["status"], "ERROR")
        self.assertNotIn("secret detail", str(result))

    def test_successful_lookup_is_deduplicated_and_counted(self):
        with patch("api.is_api_key_configured", return_value=True), \
             patch("api.is_integration_requested", return_value=True), \
             patch("api.is_integration_enabled", return_value=True), \
             patch("api.check_ip_reputation", return_value={"status": "SUCCESS"}) as request:
            result = api.lookup_public_ips([
                [{"source_ip": "8.8.8.8"}],
                [{"source_ip": "8.8.8.8"}],
            ])

        request.assert_called_once_with("8.8.8.8")
        self.assertEqual(result["public_ip_indicators"], 1)
        self.assertEqual(result["public_ip_lookups"], 1)
        self.assertEqual(result["successful_lookups"], 1)
        self.assertEqual(result["lookup_errors"], 0)

    def test_malformed_indicator_record_is_skipped(self):
        result = api.lookup_public_ips([[None, {"source_ip": 17}]])

        self.assertEqual(result["invalid_indicators"], 2)
        self.assertEqual(result["public_ip_lookups"], 0)

    def test_missing_key_skips_public_indicator_without_request(self):
        with patch("api.is_api_key_configured", return_value=False), \
             patch("api.is_integration_requested", return_value=True), \
             patch("api.is_integration_enabled", return_value=False), \
             patch("api.check_ip_reputation") as request:
            result = api.lookup_public_ips([[{"source_ip": "8.8.8.8"}]])

        request.assert_not_called()
        self.assertFalse(result["api_key_configured"])
        self.assertTrue(result["integration_requested"])
        self.assertFalse(result["integration_enabled"])
        self.assertEqual(result["public_ip_lookups"], 0)
        self.assertEqual(result["skipped_missing_key_indicators"], 1)

    def test_disabled_integration_skips_public_indicator_without_request(self):
        with patch("api.is_api_key_configured", return_value=True), \
             patch("api.is_integration_requested", return_value=False), \
             patch("api.is_integration_enabled", return_value=False), \
             patch("api.check_ip_reputation") as request:
            result = api.lookup_public_ips([[{"source_ip": "8.8.8.8"}]])

        request.assert_not_called()
        self.assertTrue(result["api_key_configured"])
        self.assertFalse(result["integration_requested"])
        self.assertFalse(result["integration_enabled"])
        self.assertEqual(result["skipped_disabled_indicators"], 1)

    def test_malformed_detector_alert_fails_closed_at_api(self):
        from contextlib import redirect_stdout
        from io import StringIO

        with patch("api.detect_threats", return_value=[None]):
            with redirect_stdout(StringIO()):
                with self.assertRaises(HTTPException) as error:
                    api.get_summary()

        self.assertEqual(error.exception.status_code, 500)
        self.assertEqual(
            error.exception.detail,
            "Backend analysis failed. Check the VS Code terminal.",
        )


if __name__ == "__main__":
    unittest.main()
