
import unittest

from app.risk.risk_engine import score_findings


class RiskEngineTests(unittest.TestCase):

    def test_no_findings(self):
        result = score_findings([])

        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_level"], "INFO")
        self.assertEqual(result["finding_count"], 0)

    def test_high_severity_finding(self):
        result = score_findings([
            {
                "id": "TEST-001",
                "target": "192.168.1.20",
                "severity": "HIGH",
            }
        ])

        self.assertEqual(result["risk_score"], 70)
        self.assertEqual(result["risk_level"], "HIGH")

    def test_multiple_findings_increase_score(self):
        one = score_findings([
            {"id": "A", "severity": "MEDIUM"}
        ])

        two = score_findings([
            {"id": "A", "severity": "MEDIUM"},
            {"id": "B", "severity": "HIGH"},
        ])

        self.assertGreater(two["risk_score"], one["risk_score"])

    def test_duplicate_findings_are_not_double_counted(self):
        finding = {
            "id": "CAM-RTSP-001",
            "target": "192.168.1.20",
            "severity": "MEDIUM",
        }

        result = score_findings([finding, finding])

        self.assertEqual(result["finding_count"], 1)

    def test_unknown_severity_defaults_to_info(self):
        result = score_findings([
            {"id": "TEST-002", "severity": "UNRECOGNIZED"}
        ])

        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["severity_counts"]["INFO"], 1)


if __name__ == "__main__":
    unittest.main()
