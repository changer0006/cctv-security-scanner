
import unittest

from app.risk.risk_engine import score_findings


class TestRiskEngine(unittest.TestCase):

    def test_empty_findings(self):
        result = score_findings([])
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_level"], "INFO")

    def test_single_high_finding(self):
        result = score_findings([
            {"id": "TEST-001", "target": "192.168.1.9",
             "severity": "HIGH"}
        ])
        self.assertEqual(result["risk_score"], 70)
        self.assertEqual(result["risk_level"], "HIGH")

    def test_multiple_findings_increase_score(self):
        medium = score_findings([
            {"id": "A", "target": "192.168.1.9",
             "severity": "MEDIUM"}
        ])
        combined = score_findings([
            {"id": "A", "target": "192.168.1.9",
             "severity": "MEDIUM"},
            {"id": "B", "target": "192.168.1.9",
             "severity": "HIGH"},
        ])
        self.assertGreater(
            combined["risk_score"], medium["risk_score"]
        )

    def test_duplicate_finding_is_removed(self):
        finding = {
            "id": "RTSP-001",
            "target": "192.168.1.9",
            "port": 554,
            "severity": "MEDIUM",
        }
        result = score_findings([finding, finding.copy()])
        self.assertEqual(result["finding_count"], 1)

    def test_unknown_severity_defaults_to_info(self):
        result = score_findings([
            {"id": "TEST-002", "severity": "UNKNOWN"}
        ])
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["findings"][0]["severity"], "INFO")


if __name__ == "__main__":
    unittest.main()
