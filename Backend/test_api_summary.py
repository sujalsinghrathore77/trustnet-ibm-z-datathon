import unittest
from unittest.mock import patch

import api


class SummaryContractTests(unittest.TestCase):
    def test_summary_labels_category_matches_and_reports_virustotal_readiness(self):
        privacy = {"privacy_check": "PASSED", "leak_count": 0}
        organization_a = (
            [],
            [{"event_type": "outbound"}, {"event_type": "port_scan"}],
            privacy,
        )
        organization_b = (
            [],
            [{"event_type": " OUTBOUND "}, {"event_type": "repeated_failed_login"}],
            privacy,
        )

        with patch("api.analyze_organization", side_effect=[organization_a, organization_b]), \
             patch("api.is_api_key_configured", return_value=False), \
             patch("api.is_integration_requested", return_value=True), \
             patch("api.is_integration_enabled", return_value=False), \
             patch("api.check_ip_reputation") as request:
            result = api.get_summary()

        request.assert_not_called()
        self.assertEqual(result["category_matches"], 1)
        self.assertEqual(result["fingerprint_matches"], result["category_matches"])
        self.assertEqual(result["match_type"], "CATEGORY_MATCH")
        self.assertIn("not evidence", result["match_description"])
        self.assertFalse(result["virustotal"]["api_key_configured"])
        self.assertTrue(result["virustotal"]["integration_requested"])
        self.assertFalse(result["virustotal"]["integration_enabled"])
        self.assertEqual(result["virustotal"]["public_ip_lookups"], 0)


if __name__ == "__main__":
    unittest.main()
