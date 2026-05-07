"""Report model aggregating all findings from a scan."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Iterable

from crypto_recon.models.asset import Asset, AssetType
from crypto_recon.models.finding import Finding, Severity
from crypto_recon.models.scan_result import ScanResult


@dataclass
class Report:
    """Aggregated scan report."""

    target: str
    scan_type: str  # "web" or "local"
    start_time: datetime
    findings: List[Finding] = field(default_factory=list)
    assets: List[Asset] = field(default_factory=list)
    end_time: Optional[datetime] = None
    metadata: dict = field(default_factory=dict)
    _finding_keys: set[str] = field(default_factory=set, init=False, repr=False)
    _asset_keys: set[str] = field(default_factory=set, init=False, repr=False)

    def __post_init__(self) -> None:
        for finding in self.findings:
            if not finding.dedup_key:
                finding.dedup_key = finding.compute_dedup_key()
            self._finding_keys.add(finding.dedup_key)
        for asset in self.assets:
            if not asset.dedup_key:
                asset.dedup_key = asset.compute_dedup_key()
            self._asset_keys.add(asset.dedup_key)

    def summary(self) -> dict:
        """Return a high-level summary of the report."""
        counts = self.findings_by_severity()
        assets_by_type = self.assets_by_type()
        return {
            "target": self.target,
            "scan_type": self.scan_type,
            "total_findings": len(self.findings),
            "by_severity": {k: len(v) for k, v in counts.items()},
            "total_assets": len(self.assets),
            "assets_by_type": {k: len(v) for k, v in assets_by_type.items()},
            "duration_seconds": (
                (self.end_time - self.start_time).total_seconds()
                if self.end_time
                else None
            ),
        }

    def findings_by_severity(self) -> dict:
        """Return findings grouped by severity."""
        grouped: dict[str, list[Finding]] = {s.value: [] for s in Severity}
        for finding in self.findings:
            grouped[finding.severity.value].append(finding)
        return grouped

    def assets_by_type(self) -> dict:
        """Return assets grouped by asset type."""
        grouped: dict[str, list[Asset]] = {t.value: [] for t in AssetType}
        for asset in self.assets:
            grouped[asset.asset_type.value].append(asset)
        return grouped

    def add_finding(self, finding: Finding) -> None:
        """Add a finding, applying deduplication."""
        if not finding.dedup_key:
            finding.dedup_key = finding.compute_dedup_key()
        if finding.dedup_key in self._finding_keys:
            return
        self._finding_keys.add(finding.dedup_key)
        self.findings.append(finding)

    def add_findings(self, findings: Iterable[Finding]) -> None:
        """Add multiple findings with deduplication."""
        for finding in findings:
            self.add_finding(finding)

    def add_asset(self, asset: Asset) -> None:
        """Add an asset, applying deduplication."""
        if not asset.dedup_key:
            asset.dedup_key = asset.compute_dedup_key()
        if asset.dedup_key in self._asset_keys:
            return
        self._asset_keys.add(asset.dedup_key)
        self.assets.append(asset)

    def add_assets(self, assets: Iterable[Asset]) -> None:
        """Add multiple assets with deduplication."""
        for asset in assets:
            self.add_asset(asset)

    def add_scan_result(self, result: ScanResult) -> None:
        """Add all findings/assets from a scan result."""
        self.add_findings(result.findings)
        self.add_assets(result.assets)

    def to_dict(self) -> dict:
        """Serialize the full report to a plain dictionary."""
        return {
            "target": self.target,
            "scan_type": self.scan_type,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "metadata": self.metadata,
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
            "assets": [a.to_dict() for a in self.assets],
        }
