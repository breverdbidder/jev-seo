"""Redact key-shaped secrets from captured content before it reaches disk.

Crawl evidence records whatever a site serves. When a site leaks a live key
(in a URL, inline config, or a comment), audit.json and every rendered report
would store and republish it. Redact at write time so artifacts are safe to
keep and share. Redaction is lossy by design: the finding keeps its evidence
shape via a marker, and the secret value never lands on disk.
"""
from __future__ import annotations

import re

# (label, compiled pattern). First matching pattern wins for a given span.
PATTERNS: list[tuple[str, "re.Pattern[str]"]] = [
    ("provider-key", re.compile(r"\b[A-Za-z]{1,5}_(?:live|test)_[A-Za-z0-9_-]{8,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("github-token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b")),
    ("github-pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("bearer-token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}")),
    ("private-key-block", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("secret-query-param", re.compile(r"(?i)([?&](?:api[-_]?key|apikey|key|token|access_token|secret|signature|sig)=)[^&\s\"'<>]{8,}")),
]


def redact_text(text: str) -> str:
    """Replace key-shaped spans in one string with [REDACTED:<label>] markers."""
    for label, pat in PATTERNS:
        if label == "secret-query-param":
            text = pat.sub(lambda m: m.group(1) + f"[REDACTED:{label}]", text)
        else:
            text = pat.sub(f"[REDACTED:{label}]", text)
    return text


def redact(obj):
    """Recursively redact every string in a JSON-shaped structure."""
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    if isinstance(obj, tuple):
        return tuple(redact(v) for v in obj)
    if isinstance(obj, dict):
        return {redact(k): redact(v) for k, v in obj.items()}
    return obj
