"""Scan result container for findings and assets."""

from __future__ import annotations

from dataclasses import dataclass, field

from crypto_recon.models.asset import Asset
from crypto_recon.models.finding import Finding


@dataclass
class ScanResult:
    """Bundle of findings and assets from a scan step."""

    findings: list[Finding] = field(default_factory=list)
    assets: list[Asset] = field(default_factory=list)

    def extend(self, other: "ScanResult") -> None:
        """Merge another result into this one."""
        self.findings.extend(other.findings)
        self.assets.extend(other.assets)
