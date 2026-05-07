"""Dependency manifest scanner for CBOM inventory."""

from __future__ import annotations

import json
import os
import re
from typing import List

from crypto_recon.models.asset import Asset, AssetType, Confidence
from crypto_recon.models.evidence import Evidence
from crypto_recon.models.scan_result import ScanResult
from crypto_recon.utils.logger import get_logger

logger = get_logger(__name__)

_REQ_LINE_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)")


class DependencyScanner:
    """Extract dependency assets from common manifest files."""

    def scan_file(self, filepath: str, content: str) -> ScanResult:
        """Scan a dependency manifest and return assets."""
        filename = os.path.basename(filepath).lower()
        if filename == "requirements.txt":
            return self._scan_requirements(filepath, content)
        if filename == "package.json":
            return self._scan_package_json(filepath, content)
        return ScanResult()

    def _scan_requirements(self, filepath: str, content: str) -> ScanResult:
        assets: List[Asset] = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = _REQ_LINE_RE.match(line)
            if not match:
                continue
            name = match.group(1)
            version = ""
            if "==" in line:
                version = line.split("==", 1)[1].strip()
            evidence = Evidence(path=filepath, details="requirements.txt")
            asset = Asset(
                asset_type=AssetType.DEPENDENCY,
                name=name,
                description="Dependency declared in requirements.txt.",
                confidence=Confidence.MEDIUM,
                evidence=evidence,
                metadata={"version": version} if version else {},
            )
            asset.dedup_key = asset.compute_dedup_key()
            assets.append(asset)
        return ScanResult(assets=assets)

    def _scan_package_json(self, filepath: str, content: str) -> ScanResult:
        assets: List[Asset] = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            logger.debug("Invalid package.json %s: %s", filepath, exc)
            return ScanResult()
        for scope in ("dependencies", "devDependencies", "optionalDependencies"):
            deps = data.get(scope, {})
            if not isinstance(deps, dict):
                continue
            for name, version in deps.items():
                evidence = Evidence(path=filepath, details="package.json")
                asset = Asset(
                    asset_type=AssetType.DEPENDENCY,
                    name=name,
                    description="Dependency declared in package.json.",
                    confidence=Confidence.MEDIUM,
                    evidence=evidence,
                    metadata={"version": str(version), "scope": scope},
                )
                asset.dedup_key = asset.compute_dedup_key()
                assets.append(asset)
        return ScanResult(assets=assets)
