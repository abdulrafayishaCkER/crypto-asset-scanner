"""Subdomain enumeration via crt.sh certificate transparency logs."""

from __future__ import annotations

from typing import List, Optional

from crypto_recon.models.asset import Asset, AssetType, Confidence
from crypto_recon.models.evidence import Evidence
from crypto_recon.models.finding import Finding, Severity, Category
from crypto_recon.models.scan_result import ScanResults
from crypto_recon.utils.network import make_request
from crypto_recon.utils.logger import get_logger

logger = get_logger(__name__)

_INTERESTING_KEYWORDS = ("dev", "stag", "test", "qa", "uat", "demo", "sandbox", "internal")


class SubdomainEnumerator:
    """Enumerate subdomains using crt.sh certificate transparency data."""

    def enumerate(self, domain: str) -> ScanResults:
        """Query crt.sh for subdomains of *domain*.

        Args:
            domain: Base domain to search (e.g. ``example.com``).

        Returns:
            :class:`ScanResults` containing subdomain findings and assets.
        """
        results = ScanResults()
        url = f"https://crt.sh/?q=%25.{domain}&output=json"

        resp = make_request(url, timeout=15)
        if resp is None:
            logger.warning("crt.sh query failed for %s", domain)
            return results

        try:
            entries = resp.json()
        except ValueError as exc:
            logger.warning("crt.sh returned non-JSON for %s: %s", domain, exc)
            return results

        subdomains: set[str] = set()
        for entry in entries:
            name_value = entry.get("name_value", "")
            for sub in name_value.split("\n"):
                normalized = _normalize_subdomain(sub)
                if not normalized:
                    continue
                if _is_subdomain(normalized, domain) and normalized not in subdomains:
                    subdomains.add(normalized)

        for sub in sorted(subdomains):
            dns_verified = _validate_dns(sub)
            confidence = Confidence.MEDIUM if dns_verified else Confidence.LOW
            is_interesting = any(kw in sub.lower() for kw in _INTERESTING_KEYWORDS)
            severity = Severity.MEDIUM if is_interesting else Severity.INFO
            description = (
                f"Subdomain {sub!r} appears to be a development/staging environment "
                "and may have reduced security controls."
                if is_interesting
                else f"Subdomain {sub!r} was found via certificate transparency logs."
            )
            evidence = Evidence(
                url=f"https://{sub}",
                details={"source": "crt.sh", "dns_verified": dns_verified},
            )
            results.assets.append(
                Asset(
                    asset_type=AssetType.ENDPOINT,
                    name=sub,
                    description="Discovered subdomain endpoint.",
                    confidence=confidence,
                    evidence=evidence,
                    metadata={"dns_verified": dns_verified},
                )
            )
            results.findings.append(
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
                        else "Keep an inventory of all subdomains and ensure they are properly secured."
                    ),
                    url=f"https://{sub}",
                )
            )

        return results


def _normalize_subdomain(value: str) -> Optional[str]:
    candidate = value.strip().lower().rstrip(".")
    if candidate.startswith("*."):
        candidate = candidate[2:]
    return candidate or None


def _is_subdomain(candidate: str, domain: str) -> bool:
    domain = domain.lower().rstrip(".")
    return candidate == domain or candidate.endswith(f".{domain}")


def _validate_dns(hostname: str) -> bool:
    try:
        import dns.resolver

        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 5.0
        try:
            resolver.resolve(hostname, "A")
            return True
        except dns.resolver.NoAnswer:
            resolver.resolve(hostname, "AAAA")
            return True
    except Exception:
        return False
    return False
