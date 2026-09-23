import sys, unittest
from pathlib import Path
from unittest import mock
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from jevseo import psi

class FakeResp:
    status_code = 200
    def json(self):
        return {"lighthouseResult": {"fetchTime": "t", "lighthouseVersion": "12", "categories": {}, "audits": {}}}

class Capture:
    def __init__(self):
        self.calls = []
    def __call__(self, url, params=None, headers=None, timeout=None):
        self.calls.append({"params": dict(params), "headers": headers or {}})
        return FakeResp()

class PsiServiceAccountTest(unittest.TestCase):
    def test_bearer_header_replaces_key_param(self):
        cap = Capture()
        with mock.patch("jevseo.psi.requests.get", cap):
            r = psi.run_one("https://example.org/", "mobile", "fake-key", token="tok123")
        self.assertNotIn("error", r)
        self.assertEqual(cap.calls[0]["headers"].get("Authorization"), "Bearer tok123")
        self.assertNotIn("key", cap.calls[0]["params"])

    def test_key_param_when_no_token(self):
        cap = Capture()
        with mock.patch("jevseo.psi.requests.get", cap):
            psi.run_one("https://example.org/", "mobile", "fake-key")
        self.assertEqual(cap.calls[0]["params"].get("key"), "fake-key")
        self.assertNotIn("Authorization", cap.calls[0]["headers"])

    def test_run_prefers_service_account(self):
        with mock.patch("jevseo.psi.secret", side_effect=lambda n: {"GCP_SA_KEY": "{}", "PAGESPEED_API_KEY": "k"}.get(n)), \
             mock.patch("jevseo.psi._bearer_token", return_value="tok"), \
             mock.patch("jevseo.psi.requests.get", Capture()):
            out = psi.run(["https://example.org/"], log=lambda *a: None)
        self.assertEqual(out["auth"], "service_account")
        self.assertTrue(out["keyed"])

    def test_run_falls_back_to_api_key(self):
        with mock.patch("jevseo.psi.secret", side_effect=lambda n: {"PAGESPEED_API_KEY": "k"}.get(n)), \
             mock.patch("jevseo.psi.requests.get", Capture()):
            out = psi.run(["https://example.org/"], log=lambda *a: None)
        self.assertEqual(out["auth"], "api_key")

    def test_bearer_token_failure_returns_none_and_logs(self):
        notes = []
        with mock.patch.dict("sys.modules", {"google.auth": None, "google.oauth2": None, "google.oauth2.service_account": None}):
            tok = psi._bearer_token("not json", log=notes.append)
        self.assertIsNone(tok)
        self.assertTrue(any("falling back" in n for n in notes))

if __name__ == "__main__":
    unittest.main()
