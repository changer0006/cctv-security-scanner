
import tempfile
import unittest
from pathlib import Path

from app.database.db import save_scan, get_scan, list_scans


class DatabaseTests(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"

        self.result = {
            "target": "192.168.1.9",
            "generated_at": "2026-10-09T10:00:00+00:00",
            "scan_status": "up",
            "fingerprint": {
                "device_type": "Likely CCTV/NVR",
                "vendor": "Hikvision",
            },
            "risk": {
                "risk_score": 70,
                "risk_level": "HIGH",
            },
            "security_findings": [],
        }

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_save_and_retrieve_scan(self):
        scan_id = save_scan(self.result, self.db_path)
        saved = get_scan(scan_id, self.db_path)

        self.assertIsNotNone(saved)
        self.assertEqual(saved["target"], "192.168.1.9")
        self.assertEqual(saved["risk_score"], 70)
        self.assertEqual(
            saved["result"]["fingerprint"]["vendor"],
            "Hikvision",
        )

    def test_multiple_scans_are_separate_records(self):
        first_id = save_scan(self.result, self.db_path)
        second_id = save_scan(self.result, self.db_path)

        self.assertNotEqual(first_id, second_id)
        self.assertEqual(len(list_scans(db_path=self.db_path)), 2)

    def test_missing_scan_returns_none(self):
        self.assertIsNone(get_scan(999, self.db_path))

    def test_invalid_limit_is_rejected(self):
        with self.assertRaises(ValueError):
            list_scans(limit=0, db_path=self.db_path)


if __name__ == "__main__":
    unittest.main()
