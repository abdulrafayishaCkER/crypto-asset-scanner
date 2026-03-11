"""Report model aggregating all findings from a scan."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List

from crypto_recon.models.finding import Finding, Severity


@dataclass
class Report:
    """Aggregated scan report."""

    target: str
    scan_type: str  # "web" or "local"
    start_time: datetime
    findings: List[Finding] = field(default_factory=list)
    end_time: Optional[datetime] = None
    metadata: dict = field(default_factory=dict)

    def summary(self) -> dict:
        """Return a high-level summary of the report."""
        counts = self.findings_by_severity()
        return {
            "target": self.target,
            "scan_type": self.scan_type,
            "total_findings": len(self.findings),
            "by_severity": {k: len(v) for k, v in counts.items()},
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
        }
