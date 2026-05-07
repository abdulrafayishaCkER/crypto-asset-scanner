"""CycloneDX-style CBOM JSON output."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from crypto_recon.models.asset import Asset, AssetType
from crypto_recon.models.report import Report
from crypto_recon.utils.logger import get_logger

logger = get_logger(__name__)


class CBOMOutput:
    """Serialise a report into a CycloneDX-style CBOM JSON document."""

    def write(self, report: Report, filepath: str) -> None:
        content = self.to_string(report)
        try:
            with open(filepath, "w", encoding="utf-8") as fh:
                fh.write(content)
            logger.info("CBOM JSON saved to %s", filepath)
        except OSError as exc:
            logger.error("Failed to write CBOM JSON to %s: %s", filepath, exc)

    def to_string(self, report: Report) -> str:
        return json.dumps(self.to_dict(report), indent=2, ensure_ascii=False)

    def to_dict(self, report: Report) -> dict:
        components: list[dict] = []
        services: list[dict] = []
        for asset in report.assets:
            entry = self._asset_to_component(asset)
            if asset.asset_type in {AssetType.ENDPOINT, AssetType.SERVICE}:
                services.append(entry)
            else:
                components.append(entry)

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "timestamp": (report.end_time or datetime.now(timezone.utc)).isoformat(),
                "component": {
                    "type": "application",
                    "name": report.target,
                    "properties": [
                        {"name": "scanType", "value": report.scan_type},
                    ],
                },
            },
            "components": components,
            "services": services,
            "properties": [
                {"name": "cryptoRecon:totalFindings", "value": str(len(report.findings))},
                {"name": "cryptoRecon:totalAssets", "value": str(len(report.assets))},
            ],
        }

    def _asset_to_component(self, asset: Asset) -> dict:
        component_type = {
            AssetType.CERTIFICATE: "file",
            AssetType.SECRET_REFERENCE: "file",
            AssetType.KEY_REFERENCE: "file",
            AssetType.DEPENDENCY: "library",
            AssetType.TLS_PROTOCOL: "library",
            AssetType.CIPHER_SUITE: "library",
            AssetType.CRYPTO_ALGORITHM: "library",
            AssetType.ENDPOINT: "service",
            AssetType.SERVICE: "service",
        }.get(asset.asset_type, "library")

        properties = [
            {"name": "cryptoRecon:assetType", "value": asset.asset_type.value},
            {"name": "cryptoRecon:confidence", "value": asset.confidence.value},
        ]
        if asset.fingerprint:
            properties.append({"name": "cryptoRecon:fingerprint", "value": asset.fingerprint})
        if asset.evidence:
            properties.append({"name": "cryptoRecon:evidence", "value": asset.evidence.summary()})
        for key, value in asset.metadata.items():
            properties.append({"name": f"cryptoRecon:meta:{key}", "value": str(value)})

        entry = {
            "type": component_type,
            "name": asset.name,
            "description": asset.description,
            "properties": properties,
        }

        version = asset.metadata.get("version")
        if version:
            entry["version"] = str(version)

        return entry
