"""Secret detection engine using regex patterns."""

from __future__ import annotations

import os
import re
from typing import List

from crypto_recon.config import SECRET_PATTERNS
from crypto_recon.models.finding import Finding, Severity, Category
from crypto_recon.utils.logger import get_logger

logger = get_logger(__name__)

# Patterns that indicate private keys / PEM blocks — always CRITICAL
_CRITICAL_TITLES = {
    "RSA Private Key",
    "EC Private Key",
    "OpenSSH Private Key",
    "PGP Private Key Block",
}

# Compile patterns once at import time
_COMPILED: dict[str, re.Pattern] = {
    name: re.compile(pattern) for name, pattern in SECRET_PATTERNS.items()
}


def _severity_for(name: str) -> Severity:
    """Return the appropriate severity for a matched secret type."""
    if name in _CRITICAL_TITLES:
        return Severity.CRITICAL
    if any(kw in name for kw in ("AWS", "Private Key", "Stripe Live", "Azure", "DigitalOcean")):
        return Severity.CRITICAL
    return Severity.HIGH


class SecretScanner:
    """Scan text or files for exposed secrets using regex patterns."""

    def scan_text(self, text: str, source_url: str = "") -> List[Finding]:
        """Search *text* for known secret patterns.

        Args:
            text: Content to scan.
            source_url: Where the content came from (used in evidence).

        Returns:
            List of :class:`Finding` objects, one per matched secret type per source.
        """
        findings: List[Finding] = []
        seen: set[str] = set()

        for name, pattern in _COMPILED.items():
            try:
                match = pattern.search(text)
            except re.error as exc:
                logger.debug("Regex error for pattern %r: %s", name, exc)
                continue

            if match:
                key = f"{name}::{source_url}"
                if key in seen:
                    continue
                seen.add(key)

                matched_value = match.group(0)
                # Truncate long matches so they don't swamp the report
                evidence_value = matched_value[:120] + ("…" if len(matched_value) > 120 else "")

                findings.append(
                    Finding(
                        title=f"Exposed Secret: {name}",
                        description=(
                            f"A {name} pattern was detected in the scanned content. "
                            "This credential may grant unauthorised access."
                        ),
                        severity=_severity_for(name),
                        category=Category.SECRETS,
                        evidence=f"Match: {evidence_value}" + (f" | Source: {source_url}" if source_url else ""),
                        remediation=(
                            "Revoke and rotate the exposed credential immediately. "
                            "Remove it from the codebase and audit git history."
                        ),
                        url=source_url,
                        cwe="CWE-312",
                    )
                )

        return findings

    def scan_file(self, filepath: str) -> List[Finding]:
        """Scan a local *filepath* for secrets.

        Args:
            filepath: Absolute or relative path to the file.

        Returns:
            List of :class:`Finding` objects.
        """
        try:
            with open(filepath, "rb") as fh:
                raw = fh.read(65536)  # Limit to 64 KB per file
            text = raw.decode("utf-8", errors="ignore")
        except OSError as exc:
            logger.debug("Cannot read file %s: %s", filepath, exc)
            return []

        findings = self.scan_text(text, source_url=filepath)
        # Override category to LOCAL for file-based findings
        for f in findings:
            f.category = Category.LOCAL
        return findings
