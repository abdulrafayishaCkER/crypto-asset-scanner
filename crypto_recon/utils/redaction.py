"""Secret redaction and fingerprint utilities."""

from __future__ import annotations

import hashlib


def redact_secret(value: str, keep_start: int = 4, keep_end: int = 4) -> str:
    """Return a redacted secret preview."""
    if not value:
        return ""
    if len(value) <= keep_start + keep_end:
        return "*" * len(value)
    return f"{value[:keep_start]}***{value[-keep_end:]}"


def fingerprint_secret(value: str) -> str:
    """Return a SHA-256 fingerprint for a secret value."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
