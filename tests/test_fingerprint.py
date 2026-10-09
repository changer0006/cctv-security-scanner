import unittest

from app.fingerprint.fingerprint import fingerprint_device


class FingerprintTests(unittest.TestCase):

    def test_hikvision_like_device(self):
        sample = {
            "target": "192.168.1.20",
            "status": "up",
            "ports": [
                {
                    "port": 80,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "http",
                    "product": "HikVision NVR or camera http config",
                    "version": None,
                },
                {
                    "port": 554,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "rtsp",
                    "product": None,
                    "version": None,
                },
                {
                    "port": 8000,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "ipcam",
                    "product": "Hikvision IPCam control port",
                    "version": None,
                },
            ],
        }

        result = fingerprint_device(sample)

        self.assertEqual(result["vendor"], "Hikvision")
        self.assertEqual(result["device_type"], "Likely CCTV/NVR")
        self.assertEqual(result["confidence"], 90)
        self.assertGreaterEqual(len(result["evidence"]), 3)

    def test_router_not_automatically_classified_as_cctv(self):
        sample = {
            "target": "192.168.1.1",
            "status": "up",
            "ports": [
                {
                    "port": 53,
                    "service": "domain",
                    "product": "dnsmasq",
                    "version": "2.78",
                },
                {
                    "port": 80,
                    "service": "http",
                    "product": "Boa HTTPd",
                    "version": "0.94.13",
                },
            ],
        }

        result = fingerprint_device(sample)

        self.assertEqual(result["vendor"], "Unknown")
        self.assertEqual(result["device_type"], "Unknown")
        self.assertEqual(result["confidence"], 0)

    def test_empty_scan(self):
        result = fingerprint_device({
            "target": "192.168.1.50",
            "status": "up",
            "ports": [],
        })

        self.assertEqual(result["device_type"], "Unknown")
        self.assertEqual(result["services"], [])


if __name__ == "__main__":
    unittest.main()
