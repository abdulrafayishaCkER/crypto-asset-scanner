from datetime import datetime, timezone

from crypto_recon.models.asset import Asset, AssetType, Confidence
from crypto_recon.models.evidence import Evidence
from crypto_recon.models.report import Report
from crypto_recon.output.cbom_output import CBOMOutput


def test_cbom_asset_serialization() -> None:
    report = Report(target="example.com", scan_type="web", start_time=datetime.now(timezone.utc))
    report.add_asset(
        Asset(
            asset_type=AssetType.ENDPOINT,
            name="https://example.com",
            description="Example endpoint",
            confidence=Confidence.LOW,
            evidence=Evidence(url="https://example.com"),
        )
    )
    cbom = CBOMOutput().to_dict(report)
    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["components"]
    assert cbom["components"][0]["name"] == "https://example.com"
