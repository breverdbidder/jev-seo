"""Strict loader for a service-account key stored in a CI secret.

The canonical form is the JSON file Google issues. A secret that went through
a copy and paste can lose its braces and commas and arrive as one
`key<TAB>"value"` pair per line. Both forms are accepted. Anything ambiguous
(duplicate keys, missing fields, wrong type, malformed key) is rejected, and
no error message ever includes secret content.
"""
from __future__ import annotations

import base64
import json

REQUIRED = ("type", "project_id", "private_key_id", "private_key", "client_email", "token_uri")


def _valid(obj) -> dict | None:
    if not isinstance(obj, dict):
        return None
    if obj.get("type") != "service_account":
        return None
    if any(not isinstance(obj.get(k), str) or not obj[k] for k in REQUIRED):
        return None
    if not obj["client_email"].endswith(".gserviceaccount.com"):
        return None
    if not obj["token_uri"].startswith("https://"):
        return None
    key = obj["private_key"]
    if "\\n" in key and "\n" not in key:
        key = key.replace("\\n", "\n")
        obj = {**obj, "private_key": key}
    if not (key.startswith("-----BEGIN PRIVATE KEY-----") and key.rstrip().endswith("-----END PRIVATE KEY-----")):
        return None
    return obj


def _from_pairs(text: str) -> dict | None:
    out: dict = {}
    for line in text.splitlines():
        line = line.strip().rstrip(",")
        if not line or line in ("{", "}"):
            continue
        key, sep, value = line.partition("\t")
        if not sep:
            if line in out:  # stray repeat of a key name with no value
                continue
            return None
        key = key.strip().strip('"')
        try:
            parsed = json.loads(value.strip())
        except ValueError:
            return None
        if not key or key in out:
            return None  # empty or duplicate key: ambiguous
        out[key] = parsed
    return out or None


def _dup_free_json(text: str):
    def hook(pairs):
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate key")
        return dict(pairs)

    return json.loads(text, object_pairs_hook=hook)


def load_sa_info(raw: str) -> dict:
    """Return a validated service-account info dict or raise ValueError (no content in the message)."""
    text = (raw or "").lstrip("\ufeff").strip()
    attempts = [
        lambda: _dup_free_json(text),
        lambda: _dup_free_json(text[text.index("{"): text.rindex("}") + 1]),
        lambda: _dup_free_json(base64.b64decode(text, validate=True).decode()),
        lambda: _from_pairs(text),
    ]
    for attempt in attempts:
        try:
            info = _valid(attempt())
        except Exception:
            continue
        if info:
            return info
    raise ValueError("GCP_SA_KEY is not a recognisable service-account key (length %d)" % len(text))
