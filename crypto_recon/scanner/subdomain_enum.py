"""Subdomain enumeration via crt.sh certificate transparency logs."""

from __future__ import annotations

from typing import List

from crypto_recon.models.asset import Asset, AssetType, Confidence
from crypto_recon.models.evidence import Evidence
from crypto_recon.models.finding import Finding, Severity, Category
from crypto_recon.models.scan_result import ScanResult
from crypto_recon.utils.network import make_request
from crypto_recon.utils.logger import get_logger
from crypto_recon.utils.validators import is_subdomain_of

logger = get_logger(__name__)

_INTERESTING_KEYWORDS = ("dev", "stag", "test", "qa", "uat", "demo", "sandbox", "internal")


def _normalize_subdomain(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if value.startswith("*."):
        value = value[2:]
    return value


def _verify_dns(name: str) -> bool:
    try:
        import dns.resolver
    except ImportError:
        return False
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 4
    resolver.timeout = 2
    try:
        resolver.resolve(name, "A")
        return True
    except Exception:
        try:
            resolver.resolve(name, "AAAA")
            return True
        except Exception:
            return False


class SubdomainEnumerator:
    """Enumerate subdomains using crt.sh certificate transparency data."""

    def enumerate(self, domain: str) -> ScanResult:
        """Query crt.sh for subdomains of *domain*.

        Args:
            domain: Base domain to search (e.g. ``example.com``).

        Returns:
            :class:`ScanResult` with findings and assets.
        """
        findings: List[Finding] = []
        assets: List[Asset] = []
        url = f"https://crt.sh/?q=%25.{domain}&output=json"

        resp = make_request(url, timeout=15)
        if resp is None:
            logger.warning("crt.sh query failed for %s", domain)
            return ScanResult()

        try:
            entries = resp.json()
        except ValueError as exc:
            logger.warning("crt.sh returned non-JSON for %s: %s", domain, exc)
            return ScanResult()

        subdomains: set[str] = set()
        for entry in entries:
            name_value = entry.get("name_value", "")
            for sub in name_value.split("\n"):
                candidate = _normalize_subdomain(sub)
                if not candidate:
                    continue
                if is_subdomain_of(candidate, domain) and candidate not in subdomains:
                    subdomains.add(candidate)

        for sub in sorted(subdomains):
            verified = _verify_dns(sub)
            confidence = Confidence.MEDIUM if verified else Confidence.LOW
            is_interesting = any(kw in sub.lower() for kw in _INTERESTING_KEYWORDS)
            severity = Severity.MEDIUM if is_interesting else Severity.INFO
            description = (
                f"Subdomain {sub!r} appears to be a development/staging environment "
                "and may have reduced security controls."
                if is_interesting
                else f"Subdomain {sub!r} was found via certificate transparency logs."
            )
            evidence = Evidence(
                endpoint=sub,
                url=f"https://{sub}",
                details="verification=dns" if verified else "verification=unverified",
            )
            asset = Asset(
                asset_type=AssetType.ENDPOINT,
                name=sub,
                description="Subdomain discovered via certificate transparency.",
                confidence=confidence,
                evidence=evidence,
                metadata={"source": "crt.sh", "verified": verified},
            )
            asset.dedup_key = asset.compute_dedup_key()
            assets.append(asset)

            findings.append(
                Finding(
                    title=f"Subdomain Discovered: {sub}",
                    description=description,
                    severity=severity,
                    category=Category.SUBDOMAIN,
                    confidence=confidence,
                    evidence=evidence,
                    remediation=(
                        "Review this subdomain's security configuration, especially if it "
                        "is a staging or development environment."
                        if is_interesting
                        else "Maintain an inventory of subdomains and validate ownership."
                    ),
                    url=f"https://{sub}",
                    related_assets=[asset.dedup_key],
                )
            )

        return ScanResult(findings=findings, assets=assets)
