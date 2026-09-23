"""Offline tests for write-time secret redaction. No network, no spend."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from jevseo.redact import redact, redact_text  # noqa: E402

# Tokens are assembled at runtime so this file itself contains no key-shaped strings.
LIVE = "bd_" + "live_" + "S9KLXyeH9fV1epdliLz731n1"
SK = "sk_" + "live_4eC39HqLyjWDarjtT1zdp7dc"


class RedactTextTest(unittest.TestCase):
    def test_provider_live_key(self):
        out = redact_text("src=//app.js?key=1&id=" + LIVE + " end")
        self.assertNotIn(LIVE, out)
        self.assertIn("[REDACTED:provider-key]", out)

    def test_stripe_shapes(self):
        for tok in ("sk_" + "live_4eC39HqLyjWDarjtT1zdp7dc", "pk_" + "test_TYooMQauvdEDq54NiTphI7jx"):
            self.assertNotIn(tok, redact_text(f"token: {tok}"))

    def test_google_api_key(self):
        tok = "AIza" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r"[:35]
        self.assertNotIn(tok, redact_text(f"key={tok}"))

    def test_github_and_slack_and_aws(self):
        toks = [
            "ghp_" + "a" * 36,
            "github_pat_" + "A" * 30,
            "xoxb-" + "123456789012-abcdefghijkl",
            "AKIA" + "IOSFODNN7EXAMPLE",
        ]
        for tok in toks:
            self.assertNotIn(tok, redact_text(f"t={tok} "), tok)

    def test_bearer_and_pem(self):
        self.assertNotIn("Bearer abcdef0123456789abcdef", redact_text("Authorization: Bearer abcdef0123456789abcdef"))
        self.assertIn("[REDACTED:private-key-block]", redact_text("-----BEGIN RSA PRIVATE KEY-----"))

    def test_secret_query_param_keeps_name(self):
        out = redact_text("https://x.test/p?api_key=abcdef1234567890&page=2")
        self.assertIn("api_key=[REDACTED:secret-query-param]", out)
        self.assertIn("page=2", out)
        self.assertNotIn("abcdef1234567890", out)

    def test_ordinary_text_untouched(self):
        text = "Emergency plumbers in Leeds, call now for 24 hour service. live_music and test_driven stay."
        self.assertEqual(text, redact_text(text))

    def test_idempotent(self):
        once = redact_text("id=" + LIVE)
        self.assertEqual(once, redact_text(once))


class RedactStructureTest(unittest.TestCase):
    def test_nested(self):
        data = {
            "pages": [{"url": "https://x.test/?token=abcdefgh12345678", "title": "ok"}],
            "evidence": ["plain", {"snippet": "key " + SK + " here"}],
            "n": 42,
        }
        out = redact(data)
        self.assertNotIn("abcdefgh12345678", str(out))
        self.assertNotIn(SK, str(out))
        self.assertEqual(out["pages"][0]["title"], "ok")
        self.assertEqual(out["n"], 42)


if __name__ == "__main__":
    unittest.main()
