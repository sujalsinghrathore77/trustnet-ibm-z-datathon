import unittest
from unittest.mock import Mock, patch

import requests

import virustotal


class VirusTotalClientTests(unittest.TestCase):
    def test_key_configuration_reports_presence_without_returning_key(self):
        with patch.object(virustotal, "API_KEY", "unit-test-key"), \
             patch.dict("os.environ", {"VIRUSTOTAL_ENABLED": "true"}):
            self.assertTrue(virustotal.is_api_key_configured())
            self.assertTrue(virustotal.is_integration_requested())
            self.assertTrue(virustotal.is_integration_enabled())

        with patch.object(virustotal, "API_KEY", ""), \
             patch.dict("os.environ", {"VIRUSTOTAL_ENABLED": "true"}):
            self.assertFalse(virustotal.is_api_key_configured())
            self.assertTrue(virustotal.is_integration_requested())
            self.assertFalse(virustotal.is_integration_enabled())

    def test_disabled_or_unconfigured_client_does_not_make_request(self):
        for api_key, enabled, expected_message in (
            ("unit-test-key", "false", "disabled"),
            ("", "true", "not configured"),
        ):
            with self.subTest(enabled=enabled, has_key=bool(api_key)):
                with patch.object(virustotal, "API_KEY", api_key), \
                     patch.dict("os.environ", {"VIRUSTOTAL_ENABLED": enabled}), \
                     patch.object(virustotal.requests, "get") as request:
                    result = virustotal.check_ip_reputation("8.8.8.8")

                request.assert_not_called()
                self.assertEqual(result["status"], "SKIPPED")
                self.assertIn(expected_message, result["message"])

    def test_non_public_ip_does_not_make_request(self):
        with patch.object(virustotal, "API_KEY", "unit-test-key"), \
             patch.dict("os.environ", {"VIRUSTOTAL_ENABLED": "true"}), \
             patch.object(virustotal.requests, "get") as request:
            result = virustotal.check_ip_reputation("192.168.1.10")

        request.assert_not_called()
        self.assertEqual(result["status"], "SKIPPED")

    def test_success_response_is_parsed_from_mocked_request(self):
        response = Mock(status_code=200)
        response.json.return_value = {
            "data": {"attributes": {
                "reputation": 3,
                "last_analysis_stats": {"malicious": 2, "suspicious": 1},
            }}
        }
        with patch.object(virustotal, "API_KEY", "unit-test-key"), \
             patch.dict("os.environ", {"VIRUSTOTAL_ENABLED": "true"}), \
             patch.object(virustotal.requests, "get", return_value=response) as request:
            result = virustotal.check_ip_reputation("8.8.8.8")

        self.assertEqual(result["status"], "SUCCESS")
        self.assertEqual(result["malicious_detections"], 2)
        self.assertEqual(result["suspicious_detections"], 1)
        self.assertEqual(request.call_args.args[0], f"{virustotal.BASE_URL}/ip_addresses/8.8.8.8")

    def test_http_errors_are_reported_without_response_body(self):
        for status_code in (401, 403, 429, 503):
            with self.subTest(status_code=status_code):
                response = Mock(status_code=status_code)
                with patch.object(virustotal, "API_KEY", "unit-test-key"), \
                     patch.dict("os.environ", {"VIRUSTOTAL_ENABLED": "true"}), \
                     patch.object(virustotal.requests, "get", return_value=response):
                    result = virustotal.check_ip_reputation("8.8.8.8")

                self.assertEqual(result["status"], "ERROR")
                self.assertNotIn("unit-test-key", str(result))

    def test_network_error_is_safely_reported(self):
        with patch.object(virustotal, "API_KEY", "unit-test-key"), \
             patch.dict("os.environ", {"VIRUSTOTAL_ENABLED": "true"}), \
             patch.object(virustotal.requests, "get", side_effect=requests.Timeout):
            result = virustotal.check_ip_reputation("8.8.8.8")

        self.assertEqual(result["status"], "ERROR")
        self.assertNotIn("unit-test-key", str(result))


if __name__ == "__main__":
    unittest.main()
