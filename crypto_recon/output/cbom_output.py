"""CycloneDX-style CBOM JSON output."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from crypto_recon import __version__
from crypto_recon.models.asset import Asset, AssetType
from crypto_recon.models.report import Report
from crypto_recon.utils.logger import get_logger

logger = get_logger(__name__)


class CBOMOutput:
    """Serialize report assets into CycloneDX-style CBOM JSON."""

    def write(self, report: Report, filepath: str) -> None:
        content = self.to_string(report)
        try:
            with open(filepath, "w", encoding="utf-8") as fh:
                fh.write(content)
            logger.info("CBOM report saved to %s", filepath)
        except OSError as exc:
            logger.error("Failed to write CBOM report to %s: %s", filepath, exc)

    def to_string(self, report: Report) -> str:
        return json.dumps(self.to_dict(report), indent=2, ensure_ascii=False)

    def to_dict(self, report: Report) -> dict:
        timestamp = (report.end_time or datetime.now(timezone.utc)).isoformat()
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "timestamp": timestamp,
                "tools": [
                    {
                        "vendor": "CryptoRecon",
                        "name": "crypto-recon",
                        "version": __version__,
                    }
                ],
                "component": {
                    "type": "service",
                    "name": report.target,
                    "properties": [
                        {"name": "scan:type", "value": report.scan_type},
                    ],
                },
            },
            "components": [self._asset_component(asset) for asset in report.assets],
        }

    def _asset_component(self, asset: Asset) -> dict:
        component_type = _component_type(asset.asset_type)
        component: dict[str, object] = {
            "type": component_type,
            "name": asset.name,
            "bom-ref": asset.dedup_key(),
            "description": asset.description,
        }
        if asset.fingerprint:
            component["hashes"] = [{"alg": "SHA-256", "content": asset.fingerprint}]

        properties = [
            {"name": "asset:type", "value": asset.asset_type.value},
            {"name": "asset:confidence", "value": asset.confidence.value},
        ]
        for key, value in asset.metadata.items():
            if value is not None:
                properties.append({"name": f"asset:{key}", "value": str(value)})
        for key, value in asset.evidence.to_dict().items():
            properties.append({"name": f"evidence:{key}", "value": str(value)})
        component["properties"] = properties
        return component


def _component_type(asset_type: AssetType) -> str:
    if asset_type == AssetType.DEPENDENCY:
        return "library"
    if asset_type == AssetType.ENDPOINT:
        return "service"
    return "cryptographic-asset"
