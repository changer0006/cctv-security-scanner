
import json
import tempfile
import unittest
from pathlib import Path

from app.vulnerability.cve_matcher import match_vulnerabilities


class CVEMatcherTests(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp_dir.name) / "test_db.json"

        # Synthetic test fixture only; this is NOT a real CVE.
        database = {
            "schema_version": 1,
            "vulnerabilities": [
                {
                    "cve_id": "TEST-ONLY-001",
                    "product": "example camera firmware",
                    "affected_versions": ["1.0"],
                    "description": "Synthetic record for unit testing.",
                    "severity": "HIGH",
                    "references": [],
                }
            ],
        }

        self.database_path.write_text(
            json.dumps(database),
            encoding="utf-8",
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_exact_product_and_version_match(self):
        scan = {
            "target": "192.168.1.20",
            "ports": [
                {
                    "port": 80,
                    "product": "Example Camera Firmware",
                    "version": "1.0",
                }
            ],
        }

        matches = match_vulnerabilities(scan, self.database_path)

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["cve_id"], "TEST-ONLY-001")
        self.assertFalse(matches[0]["confirmed_vulnerability"])

    def test_unmatched_version_returns_no_match(self):
        scan = {
            "target": "192.168.1.20",
            "ports": [
                {
                    "port": 80,
                    "product": "Example Camera Firmware",
                    "version": "2.0",
                }
            ],
        }

        self.assertEqual(
            match_vulnerabilities(scan, self.database_path),
            [],
        )

    def test_missing_version_returns_no_match(self):
        scan = {
            "target": "192.168.1.20",
            "ports": [
                {
                    "port": 80,
                    "product": "Example Camera Firmware",
                    "version": None,
                }
            ],
        }

        self.assertEqual(
            match_vulnerabilities(scan, self.database_path),
            [],
        )


if __name__ == "__main__":
    unittest.main()
