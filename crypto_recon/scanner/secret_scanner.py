"""Secret detection engine using regex patterns."""

from __future__ import annotations

import os
import re

from crypto_recon.config import SECRET_PATTERNS
from crypto_recon.models.asset import Asset, AssetType, Confidence
from crypto_recon.models.evidence import Evidence
from crypto_recon.models.finding import Category, Finding, Severity
from crypto_recon.models.scan_result import ScanResults
from crypto_recon.utils.logger import get_logger
from crypto_recon.utils.redaction import fingerprint_secret, redact_secret

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

    def __init__(self, max_file_size: int | None = None, max_read_bytes: int | None = None) -> None:
        """Initialise the scanner.

        Args:
            max_file_size: Maximum file size to scan (bytes).
            max_read_bytes: Maximum bytes to read from a file.
        """
        from crypto_recon.config import MAX_FILE_READ_BYTES, MAX_FILE_SIZE_BYTES

        self.max_file_size = max_file_size or MAX_FILE_SIZE_BYTES
        self.max_read_bytes = max_read_bytes or MAX_FILE_READ_BYTES

    def scan_text(self, text: str, source_url: str = "") -> ScanResults:
        """Search *text* for known secret patterns.

        Args:
            text: Content to scan.
            source_url: Where the content came from (used in evidence).

        Returns:
            :class:`ScanResults` containing findings and secret-reference assets.
        """
        results = ScanResults()
        seen: set[str] = set()

        for name, pattern in _COMPILED.items():
            try:
                matches = list(pattern.finditer(text))
            except re.error as exc:
                logger.debug("Regex error for pattern %r: %s", name, exc)
                continue

            for match in matches:
                matched_value = match.group(0)
                redacted = redact_secret(matched_value)
                fingerprint = fingerprint_secret(matched_value)
                line_number = text[: match.start()].count("\n") + 1

                key = f"{name}::{fingerprint}::{source_url}::{line_number}"
                if key in seen:
                    continue
                seen.add(key)

                is_url = source_url.startswith("http") if source_url else False
                evidence = Evidence(
                    url=source_url if is_url else None,
                    file_path=source_url if source_url and not is_url else None,
                    line_number=line_number,
                    details={"redacted": redacted, "secret_type": name},
                )

                results.assets.append(
                    Asset(
                        asset_type=AssetType.SECRET_REFERENCE,
                        name=f"{name} reference",
                        description="Redacted secret reference detected in scanned content.",
                        confidence=Confidence.HIGH,
                        evidence=evidence,
                        fingerprint=fingerprint,
                        metadata={"redacted": redacted, "secret_type": name},
                    )
                )

                results.findings.append(
                    Finding(
                        title=f"Exposed Secret: {name}",
                        description=(
                            f"A {name} pattern was detected in the scanned content. "
                            "This credential may grant unauthorised access."
                        ),
                        severity=_severity_for(name),
                        category=Category.SECRETS,
                        confidence=Confidence.HIGH,
                        evidence=evidence,
                        remediation=(
                            "Revoke and rotate the exposed credential immediately. "
                            "Remove it from the codebase and audit git history."
                        ),
                        url=source_url if is_url else "",
                        cwe="CWE-312",
                    )
                )

        return results

    def scan_file(self, filepath: str) -> ScanResults:
        """Scan a local *filepath* for secrets.

        Args:
            filepath: Absolute or relative path to the file.

        Returns:
            :class:`ScanResults` containing findings and secret-reference assets.
        """
        try:
            file_size = os.path.getsize(filepath)
            if file_size > self.max_file_size:
                return ScanResults()

            with open(filepath, "rb") as fh:
                raw = fh.read(self.max_read_bytes)
            if b"\x00" in raw[:2048]:
                return ScanResults()
            text = raw.decode("utf-8", errors="ignore")
        except OSError as exc:
            logger.debug("Cannot read file %s: %s", filepath, exc)
            return ScanResults()

        results = self.scan_text(text, source_url=filepath)
        for f in results.findings:
            f.category = Category.LOCAL
        return results
