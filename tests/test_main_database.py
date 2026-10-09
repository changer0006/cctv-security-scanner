
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.database.db import save_scan, get_scan


class MainDatabaseIntegrationTests(unittest.TestCase):

    def test_pipeline_result_can_be_saved_and_retrieved(self):
        result = {
            "target": "192.168.1.9",
            "generated_at": "2026-10-09T10:00:00+00:00",
            "scan_status": "up",
            "fingerprint": {
                "device_type": "Likely CCTV/NVR",
                "vendor": "Hikvision",
            },
            "security_findings": [],
            "http_findings": [],
            "cve_candidates": [],
            "risk": {
                "risk_score": 40,
                "risk_level": "MEDIUM",
                "finding_count": 1,
            },
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "integration.db"

            scan_id = save_scan(result, db_path)
            retrieved = get_scan(scan_id, db_path)

            self.assertIsNotNone(retrieved)
            self.assertEqual(retrieved["target"], result["target"])
            self.assertEqual(retrieved["risk_score"], 40)
            self.assertEqual(
                retrieved["result"]["risk"]["risk_level"],
                "MEDIUM",
            )


if __name__ == "__main__":
    unittest.main()
