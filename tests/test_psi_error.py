import sys, unittest
from pathlib import Path
from unittest import mock
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from jevseo.psi import run_one

class FakeResp:
    status_code = 401
    def json(self):
        return {"error": {"code": 401, "message": "PageSpeed Insights API has not been used in project 123 before or it is disabled.", "status": "UNAUTHENTICATED"}}

class PsiErrorDetailTest(unittest.TestCase):
    def test_error_body_captured(self):
        with mock.patch("jevseo.psi.requests.get", return_value=FakeResp()):
            r = run_one("https://example.org/", "mobile", "fake-key")
        self.assertIn("HTTP 401", r["error"])
        self.assertIn("has not been used", r["error"])

    def test_error_body_truncated(self):
        class LongResp(FakeResp):
            def json(self):
                return {"error": {"message": "x" * 1000}}
        with mock.patch("jevseo.psi.requests.get", return_value=LongResp()):
            r = run_one("https://example.org/", "mobile", "fake-key")
        self.assertTrue(len(r["error"]) <= 310)

if __name__ == "__main__":
    unittest.main()
