
import json
import tempfile
import unittest

from app.pipeline import analyze_scan, save_report


class PipelineTests(unittest.TestCase):

    def setUp(self):
        # Synthetic scan data: no real device is contacted.
        self.scan = {
            "target": "192.168.1.9",
            "status": "up",
            "ports": [
                {
                    "port": 554,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "rtsp",
                    "product": "Test Camera",
                    "version": "1.0",
                }
            ],
        }

    def test_pipeline_returns_expected_sections(self):
        result = analyze_scan(self.scan)

        self.assertIn("fingerprint", result)
        self.assertIn("security_findings", result)
        self.assertIn("cve_candidates", result)
        self.assertIn("risk", result)
        self.assertGreaterEqual(
            result["risk"]["finding_count"], 1
        )

    def test_missing_database_does_not_discard_scan(self):
        result = analyze_scan(
            self.scan,
            database_path="/path/that/does/not/exist.json",
        )

        self.assertEqual(result["target"], "192.168.1.9")
        self.assertIsNotNone(result["cve_database_error"])
        self.assertGreaterEqual(
            len(result["security_findings"]), 1
        )

    def test_report_is_valid_json(self):
        result = analyze_scan(self.scan)

        with tempfile.TemporaryDirectory() as temp_dir:
            path = save_report(result, output_dir=temp_dir)

            with open(path, encoding="utf-8") as file:
                saved = json.load(file)

            self.assertEqual(saved["target"], "192.168.1.9")
            self.assertIn("risk", saved)


if __name__ == "__main__":
    unittest.main()
