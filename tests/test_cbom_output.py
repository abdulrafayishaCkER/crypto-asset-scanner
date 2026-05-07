from datetime import datetime, timezone

from crypto_recon.models.asset import Asset, AssetType, Confidence
from crypto_recon.models.evidence import Evidence
from crypto_recon.models.report import Report
from crypto_recon.output.cbom_output import CBOMOutput


def test_cbom_serialization_contains_components():
    report = Report(
        target="example.com",
        scan_type="web",
        start_time=datetime.now(timezone.utc),
    )
    asset = Asset(
        asset_type=AssetType.DEPENDENCY,
        name="requests",
        description="Dependency declared in requirements.txt.",
        confidence=Confidence.MEDIUM,
        evidence=Evidence(path="requirements.txt"),
        metadata={"version": "2.31.0"},
    )
    report.add_asset(asset)

    data = CBOMOutput().to_dict(report)
    assert data["bomFormat"] == "CycloneDX"
    assert len(data["components"]) == 1
