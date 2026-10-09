
import unittest

from app.checks.security_assessment import assess_device


class SecurityAssessmentTests(unittest.TestCase):

    def test_rtsp_exposure_is_reported(self):
        result = {
            "target": "192.168.1.20",
            "ports": [
                {
                    "port": 554,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "rtsp",
                }
            ],
        }

        findings = assess_device(result)

        self.assertTrue(
            any(f["id"] == "CAM-RTSP-001" for f in findings)
        )

    def test_http_without_https_is_reported(self):
        result = {
            "target": "192.168.1.20",
            "ports": [
                {
                    "port": 80,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "http",
                }
            ],
        }

        findings = assess_device(result)

        self.assertTrue(
            any(f["id"] == "WEB-HTTP-001" for f in findings)
        )

    def test_closed_rtsp_does_not_trigger_finding(self):
        result = {
            "target": "192.168.1.20",
            "ports": [
                {
                    "port": 554,
                    "protocol": "tcp",
                    "state": "closed",
                    "service": "rtsp",
                }
            ],
        }

        findings = assess_device(result)

        self.assertFalse(
            any(f["id"] == "CAM-RTSP-001" for f in findings)
        )

    def test_findings_include_evidence_and_remediation(self):
        result = {
            "target": "192.168.1.20",
            "ports": [
                {
                    "port": 23,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "telnet",
                }
            ],
        }

        findings = assess_device(result)

        telnet = next(f for f in findings if f["id"] == "NET-PORT-23")

        self.assertEqual(telnet["severity"], "HIGH")
        self.assertTrue(telnet["evidence"])
        self.assertTrue(telnet["remediation"])
        self.assertFalse(telnet["confirmed_vulnerability"])


if __name__ == "__main__":
    unittest.main()
