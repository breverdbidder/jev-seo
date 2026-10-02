"""Tolerant loader for a service-account key pasted into a CI secret.

The canonical form is the JSON file Google issues. A secret that went through
a copy and paste can lose its braces and commas and arrive as one
`key<TAB>"value"` pair per line. This accepts both. It never logs content.
"""
from __future__ import annotations

import base64
import json


def _as_info(obj) -> dict | None:
    if isinstance(obj, dict) and obj.get("type") == "service_account" and obj.get("client_email") and obj.get("private_key"):
        return obj
    return None


def _from_pairs(text: str) -> dict | None:
    out: dict = {}
    for line in text.splitlines():
        line = line.strip().rstrip(",")
        if not line or line in ("{", "}"):
            continue
        key, sep, value = line.partition("\t")
        if not sep:
            key, sep, value = line.partition(":")
        key = key.strip().strip('"')
        value = value.strip()
        if not sep or not key:
            continue
        try:
            out[key] = json.loads(value)
        except ValueError:
            out[key] = value.strip('"')
    return out or None


def load_sa_info(raw: str) -> dict:
    """Return the service-account info dict, or raise ValueError (no content in the message)."""
    text = (raw or "").lstrip("\ufeff").strip()
    candidates = []
    try:
        candidates.append(json.loads(text))
    except ValueError:
        pass
    if "{" in text and "}" in text:
        try:
            candidates.append(json.loads(text[text.index("{"): text.rindex("}") + 1]))
        except ValueError:
            pass
    try:
        candidates.append(json.loads(base64.b64decode(text, validate=True).decode()))
    except Exception:
        pass
    candidates.append(_from_pairs(text))
    for cand in candidates:
        info = _as_info(cand)
        if info:
            if "\\n" in info["private_key"] and "\n" not in info["private_key"]:
                info["private_key"] = info["private_key"].replace("\\n", "\n")
            return info
    raise ValueError("GCP_SA_KEY is not a recognisable service-account key (length %d)" % len(text))
