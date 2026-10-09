
import unittest
from unittest.mock import patch

from app.checks.http_checks import check_http_headers


class FakeResponse:
    status = 200
    headers = {
        "Content-Type": "text/html",
        "X-Content-Type-Options": "nosniff",
    }

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def geturl(self):
        return "https://camera.example/"


class HTTPChecksTests(unittest.TestCase):

    @patch("app.checks.http_checks.urllib.request.urlopen")
    def test_missing_headers_are_reported(self, mock_urlopen):
        mock_urlopen.return_value = FakeResponse()

        result = check_http_headers("https://camera.example/")

        self.assertTrue(result["reachable"])
        finding_ids = {item["id"] for item in result["findings"]}

        self.assertIn("HTTP-HDR-001", finding_ids)
        self.assertIn("HTTP-HDR-002", finding_ids)
        self.assertNotIn("HTTP-HDR-003", finding_ids)

    @patch("app.checks.http_checks.urllib.request.urlopen")
    def test_unreachable_endpoint(self, mock_urlopen):
        import urllib.error

        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

        result = check_http_headers("http://127.0.0.1:1/")

        self.assertFalse(result["reachable"])
        self.assertEqual(result["findings"], [])


if __name__ == "__main__":
    unittest.main()
