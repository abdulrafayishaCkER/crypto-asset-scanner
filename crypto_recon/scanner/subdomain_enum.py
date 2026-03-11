"""Subdomain enumeration via crt.sh certificate transparency logs."""

from __future__ import annotations

from typing import List

from crypto_recon.models.finding import Finding, Severity, Category
from crypto_recon.utils.network import make_request
from crypto_recon.utils.logger import get_logger

logger = get_logger(__name__)

_INTERESTING_KEYWORDS = ("dev", "stag", "test", "qa", "uat", "demo", "sandbox", "internal")


class SubdomainEnumerator:
    """Enumerate subdomains using crt.sh certificate transparency data."""

    def enumerate(self, domain: str) -> List[Finding]:
        """Query crt.sh for subdomains of *domain*.

        Args:
            domain: Base domain to search (e.g. ``example.com``).

        Returns:
            List of :class:`Finding` objects, one per discovered subdomain.
        """
        findings: List[Finding] = []
        url = f"https://crt.sh/?q=%25.{domain}&output=json"

        resp = make_request(url, timeout=15)
        if resp is None:
            logger.warning("crt.sh query failed for %s", domain)
            return findings

        try:
            entries = resp.json()
        except ValueError as exc:
            logger.warning("crt.sh returned non-JSON for %s: %s", domain, exc)
            return findings

        subdomains: set[str] = set()
        for entry in entries:
            name_value = entry.get("name_value", "")
            for sub in name_value.split("\n"):
                sub = sub.strip().lstrip("*.")
                if domain in sub and sub not in subdomains:
                    subdomains.add(sub)

        for sub in sorted(subdomains):
            is_interesting = any(kw in sub.lower() for kw in _INTERESTING_KEYWORDS)
            severity = Severity.MEDIUM if is_interesting else Severity.INFO
            description = (
                f"Subdomain {sub!r} appears to be a development/staging environment "
                "and may have reduced security controls."
                if is_interesting
                else f"Subdomain {sub!r} was found via certificate transparency logs."
            )
            findings.append(
                Finding(
                    title=f"Subdomain Discovered: {sub}",
                    description=description,
                    severity=severity,
                    category=Category.SUBDOMAIN,
                    evidence=f"Source: crt.sh | Domain: {sub}",
                    remediation=(
                        "Review this subdomain's security configuration, especially if it "
                        "is a staging or development environment."
                        if is_interesting
                        else "Keep an inventory of all subdomains and ensure they are properly secured."
                    ),
                    url=f"https://{sub}",
                )
            )

        return findings
