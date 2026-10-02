import base64
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from jevseo.sa_key import load_sa_info

PEM = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
INFO = {
    "type": "service_account",
    "project_id": "p",
    "private_key_id": "k",
    "private_key": PEM,
    "client_email": "a@p.iam.gserviceaccount.com",
    "client_id": "1",
    "token_uri": "https://oauth2.googleapis.com/token",
}


def pairs(info):
    return "\t\n" + "\n".join(f"{k}\t{json.dumps(v)}" for k, v in info.items()) + "\ntype"


class SaKeyTest(unittest.TestCase):
    def test_canonical_json(self):
        self.assertEqual(load_sa_info(json.dumps(INFO, indent=2)), INFO)

    def test_pasted_pairs_form(self):
        self.assertEqual(load_sa_info(pairs(INFO)), INFO)

    def test_base64(self):
        self.assertEqual(load_sa_info(base64.b64encode(json.dumps(INFO).encode()).decode()), INFO)

    def test_rejects_duplicate_key(self):
        with self.assertRaises(ValueError):
            load_sa_info(pairs(INFO) + '\nproject_id\t"other"')

    def test_rejects_missing_field(self):
        bad = {k: v for k, v in INFO.items() if k != "client_email"}
        with self.assertRaises(ValueError):
            load_sa_info(pairs(bad))

    def test_rejects_wrong_type_and_tiny(self):
        with self.assertRaises(ValueError):
            load_sa_info(pairs({**INFO, "type": "authorized_user"}))
        with self.assertRaises(ValueError):
            load_sa_info("x\n")

    def test_error_has_no_content(self):
        with self.assertRaises(ValueError) as cm:
            load_sa_info("supersecretvalue")
        self.assertNotIn("supersecretvalue", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
