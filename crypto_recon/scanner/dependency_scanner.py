"""Dependency manifest scanner for CBOM assets."""

from __future__ import annotations

import json
import os
from typing import Iterable

from crypto_recon.models.asset import Asset, AssetType, Confidence
from crypto_recon.models.evidence import Evidence
from crypto_recon.models.scan_result import ScanResults
from crypto_recon.utils.logger import get_logger

logger = get_logger(__name__)


class DependencyScanner:
    """Extract dependencies from common manifest files."""

    def scan_file(self, filepath: str) -> ScanResults:
        """Scan a single manifest file for dependencies."""
        basename = os.path.basename(filepath)
        if basename == "requirements.txt":
            return self._scan_requirements(filepath)
        if basename == "package.json":
            return self._scan_package_json(filepath)
        if basename == "pyproject.toml":
            return self._scan_pyproject(filepath)
        return ScanResults()

    def _scan_requirements(self, filepath: str) -> ScanResults:
        results = ScanResults()
        try:
            with open(filepath, "r", encoding="utf-8") as fh:
                lines = fh.readlines()
        except OSError as exc:
            logger.debug("Unable to read requirements file %s: %s", filepath, exc)
            return results

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            name, version = self._split_requirement(stripped)
            results.assets.append(
                Asset(
                    asset_type=AssetType.DEPENDENCY,
                    name=name,
                    description="Python dependency from requirements.txt.",
                    confidence=Confidence.MEDIUM,
                    evidence=Evidence(file_path=filepath, line_number=idx),
                    metadata={"version": version, "source": "requirements.txt"},
                )
            )
        return results

    def _scan_package_json(self, filepath: str) -> ScanResults:
        results = ScanResults()
        try:
            with open(filepath, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            logger.debug("Unable to parse package.json %s: %s", filepath, exc)
            return results

        for scope in ("dependencies", "devDependencies"):
            deps = payload.get(scope, {}) or {}
            for name, version in deps.items():
                results.assets.append(
                    Asset(
                        asset_type=AssetType.DEPENDENCY,
                        name=name,
                        description="Node dependency from package.json.",
                        confidence=Confidence.MEDIUM,
                        evidence=Evidence(file_path=filepath),
                        metadata={"version": version, "source": scope},
                    )
                )
        return results

    def _scan_pyproject(self, filepath: str) -> ScanResults:
        results = ScanResults()
        try:
            import tomllib
        except ImportError:  # pragma: no cover - py3.10 fallback
            try:
                import tomli as tomllib  # type: ignore
            except ImportError:
                return results

        try:
            with open(filepath, "rb") as fh:
                payload = tomllib.load(fh)
        except (OSError, tomllib.TOMLDecodeError) as exc:
            logger.debug("Unable to parse pyproject.toml %s: %s", filepath, exc)
            return results

        deps: Iterable[str] = payload.get("project", {}).get("dependencies", []) or []
        for idx, dep in enumerate(deps, start=1):
            name, version = self._split_requirement(dep)
            results.assets.append(
                Asset(
                    asset_type=AssetType.DEPENDENCY,
                    name=name,
                    description="Python dependency from pyproject.toml.",
                    confidence=Confidence.MEDIUM,
                    evidence=Evidence(file_path=filepath, line_number=idx),
                    metadata={"version": version, "source": "pyproject.toml"},
                )
            )
        return results

    @staticmethod
    def _split_requirement(requirement: str) -> tuple[str, str]:
        for sep in ("==", ">=", "<=", "~=", ">", "<"):
            if sep in requirement:
                name, version = requirement.split(sep, 1)
                return name.strip(), f"{sep}{version.strip()}"
        return requirement.strip(), ""
