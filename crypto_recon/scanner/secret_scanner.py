"""Secret detection engine using regex patterns."""

from __future__ import annotations

import hashlib
import os
import re
from typing import Optional
from urllib.parse import urlparse

from crypto_recon.config import SECRET_PATTERNS, MAX_FILE_SIZE_BYTES
from crypto_recon.models.asset import Asset, AssetType, Confidence
from crypto_recon.models.evidence import Evidence
from crypto_recon.models.finding import Finding, Severity, Category
from crypto_recon.models.scan_result import ScanResult
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


def _hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _redact_secret_value(value: str) -> str:
    if "://" in value and "@" in value:
        parsed = urlparse(value)
        netloc = parsed.netloc
        if "@" in netloc:
            host = netloc.split("@", maxsplit=1)[1]
            redacted = f"[redacted]@{host}"
            return value.replace(netloc, redacted)
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}…{value[-4:]}"


def _line_number(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _is_binary(raw: bytes) -> bool:
    if not raw:
        return False
    if b"\0" in raw:
        return True
    sample = raw[:2048]
    allowed = set({7, 8, 9, 10, 12, 13, 27}) | set(range(0x20, 0x7F))
    nontext = sum(1 for b in sample if b not in allowed)
    return nontext / max(1, len(sample)) > 0.3


class SecretScanner:
    """Scan text or files for exposed secrets using regex patterns."""

    def scan_text(
        self,
        text: str,
        source_path: Optional[str] = None,
        source_url: Optional[str] = None,
    ) -> ScanResult:
        """Search *text* for known secret patterns.

        Args:
            text: Content to scan.
            source_path: File path if scanning local content.
            source_url: URL if scanning remote content.

        Returns:
            :class:`ScanResult` containing findings and assets.
        """
        result = ScanResult()
        seen: set[str] = set()

        for name, pattern in _COMPILED.items():
            try:
                matches = list(pattern.finditer(text))
            except re.error as exc:
                logger.debug("Regex error for pattern %r: %s", name, exc)
                continue

            for match in matches:
                secret_value = match.group(1) if match.lastindex else match.group(0)
                fingerprint = _hash_secret(secret_value)
                redacted = _redact_secret_value(secret_value)
                line_no = _line_number(text, match.start())
                evidence = Evidence(
                    path=source_path,
                    line=line_no,
                    url=source_url,
                    fingerprint=f"sha256:{fingerprint}",
                    snippet=redacted,
                    details=f"Secret pattern: {name}",
                )
                dedup = f"{name}:{fingerprint}:{source_path or source_url or ''}:{line_no}"
                if dedup in seen:
                    continue
                seen.add(dedup)

                asset_type = (
                    AssetType.KEY_REFERENCE if name in _CRITICAL_TITLES else AssetType.SECRET_REFERENCE
                )
                asset = Asset(
                    asset_type=asset_type,
                    name=name,
                    description="Redacted secret reference detected in source content.",
                    confidence=Confidence.HIGH,
                    evidence=evidence,
                    fingerprint=f"sha256:{fingerprint}",
                    metadata={"source": "pattern_match"},
                )
                asset.dedup_key = asset.compute_dedup_key()

                finding = Finding(
                    title=f"Exposed Secret Reference: {name}",
                    description=(
                        f"A {name} pattern was detected in the scanned content. "
                        "The value has been redacted for safety."
                    ),
                    severity=_severity_for(name),
                    category=Category.SECRETS if source_url else Category.LOCAL,
                    confidence=Confidence.HIGH,
                    evidence=evidence,
                    remediation=(
                        "Revoke and rotate the exposed credential immediately. "
                        "Remove it from the codebase and audit git history."
                    ),
                    url=source_url or "",
                    cwe="CWE-312",
                    related_assets=[asset.dedup_key],
                )
                finding.dedup_key = finding.compute_dedup_key()

                result.assets.append(asset)
                result.findings.append(finding)

        return result

    def scan_file(self, filepath: str) -> ScanResult:
        """Scan a local *filepath* for secrets.

        Args:
            filepath: Absolute or relative path to the file.

        Returns:
            :class:`ScanResult` with findings/assets.
        """
        try:
            size = os.path.getsize(filepath)
            if size > MAX_FILE_SIZE_BYTES:
                logger.debug("Skipping large file %s (size %d)", filepath, size)
                return ScanResult()
            with open(filepath, "rb") as fh:
                raw = fh.read()
            if _is_binary(raw):
                logger.debug("Skipping binary file %s", filepath)
                return ScanResult()
            text = raw.decode("utf-8", errors="ignore")
        except OSError as exc:
            logger.debug("Cannot read file %s: %s", filepath, exc)
            return ScanResult()

        return self.scan_text(text, source_path=filepath)
