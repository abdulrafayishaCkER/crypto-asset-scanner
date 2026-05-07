from datetime import datetime, timezone

from crypto_recon.models.evidence import Evidence
from crypto_recon.models.finding import Finding, Severity, Category
from crypto_recon.models.report import Report


def test_report_deduplicates_findings():
    report = Report(
        target="example.com",
        scan_type="web",
        start_time=datetime.now(timezone.utc),
    )
    finding1 = Finding(
        title="Test Finding",
        description="Test description",
        severity=Severity.LOW,
        category=Category.TLS,
        evidence=Evidence(endpoint="example.com", details="test"),
    )
    finding2 = Finding(
        title="Test Finding",
        description="Test description",
        severity=Severity.LOW,
        category=Category.TLS,
        evidence=Evidence(endpoint="example.com", details="test"),
    )
    report.add_findings([finding1, finding2])

    assert len(report.findings) == 1
