from datetime import datetime, timezone

from crypto_recon.models.asset import Confidence
from crypto_recon.models.evidence import Evidence
from crypto_recon.models.finding import Category, Finding, Severity
from crypto_recon.models.report import Report


def test_finding_deduplication() -> None:
    report = Report(target="example.com", scan_type="web", start_time=datetime.now(timezone.utc))
    finding = Finding(
        title="Duplicate",
        description="Duplicate finding",
        severity=Severity.LOW,
        category=Category.TLS,
        confidence=Confidence.MEDIUM,
        evidence=Evidence(url="https://example.com"),
    )
    report.add_finding(finding)
    report.add_finding(finding)
    assert len(report.findings) == 1
