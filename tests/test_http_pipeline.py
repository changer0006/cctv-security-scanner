
import unittest
from unittest.mock import patch

from app.pipeline import analyze_scan


class HTTPPipelineTests(unittest.TestCase):

    @patch("app.pipeline.check_http_headers")
    def test_open_http_service_is_checked(self, mock_check):
        mock_check.return_value = {
            "url": "http://192.168.1.9:80/",
            "reachable": True,
            "status_code": 200,
            "headers": {},
            "findings": [
                {
                    "id": "HTTP-HDR-001",
                    "title": "Missing test header",
                    "severity": "LOW",
                    "evidence": "Synthetic test evidence",
                    "remediation": "Synthetic test remediation",
                    "confirmed_vulnerability": False,
                }
            ],
        }

        scan = {
            "target": "192.168.1.9",
            "status": "up",
            "ports": [
                {
                    "port": 80,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "http",
                    "product": "Test Server",
                    "version": "1.0",
                }
            ],
        }

        result = analyze_scan(scan)

        mock_check.assert_called_once_with(
            "http://192.168.1.9:80/"
        )
        self.assertEqual(len(result["http_checks"]), 1)
        self.assertEqual(len(result["http_findings"]), 1)
        self.assertEqual(
            result["http_findings"][0]["port"], 80
        )
        self.assertGreaterEqual(
            result["risk"]["finding_count"], 1
        )

    @patch("app.pipeline.check_http_headers")
    def test_closed_http_port_is_not_checked(self, mock_check):
        scan = {
            "target": "192.168.1.9",
            "status": "up",
            "ports": [
                {
                    "port": 80,
                    "protocol": "tcp",
                    "state": "closed",
                    "service": "http",
                    "product": "",
                    "version": "",
                }
            ],
        }

        result = analyze_scan(scan)

        mock_check.assert_not_called()
        self.assertEqual(result["http_checks"], [])


if __name__ == "__main__":
    unittest.main()
