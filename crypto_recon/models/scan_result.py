"""Unified scan result for assets and findings."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import List

from crypto_recon.models.asset import Asset
from crypto_recon.models.finding import Finding


@dataclass
class ScanResults:
    """Aggregates findings and assets from a scanner step."""

    findings: List[Finding] = field(default_factory=list)
    assets: List[Asset] = field(default_factory=list)

    def extend(self, other: ScanResults) -> None:
        """Merge another ScanResults into this one."""
        self.findings.extend(other.findings)
        self.assets.extend(other.assets)

    def add_findings(self, findings: Iterable[Finding]) -> None:
        """Append findings to this result."""
        self.findings.extend(findings)

    def add_assets(self, assets: Iterable[Asset]) -> None:
        """Append assets to this result."""
        self.assets.extend(assets)
