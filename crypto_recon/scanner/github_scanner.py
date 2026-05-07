"""GitHub public code search for domain-related leaks."""

from __future__ import annotations

from typing import List

from crypto_recon.models.asset import Confidence
from crypto_recon.models.evidence import Evidence
from crypto_recon.models.finding import Category, Finding, Severity
from crypto_recon.models.scan_result import ScanResults
from crypto_recon.utils.logger import get_logger
from crypto_recon.utils.network import make_request

logger = get_logger(__name__)

_GITHUB_SEARCH_URL = "https://api.github.com/search/code"
_MAX_RESULTS = 10


class GitHubScanner:
    """Search GitHub public repositories for references to a target domain."""

    def __init__(self, token: str | None = None) -> None:
        """Initialise the scanner.

        Args:
            token: Optional GitHub personal access token for higher rate limits.
        """
        self.token = token

    def search(self, domain: str) -> ScanResults:
        """Search GitHub for public code mentioning *domain*.

        Args:
            domain: Domain name to search for.

        Returns:
            :class:`ScanResults` containing GitHub findings.
        """
        findings: List[Finding] = []

        headers: dict = {"Accept": "application/vnd.github.v3+json"}
        if self.token:
            headers["Authorization"] = f"token {self.token}"
        else:
            findings.append(
                Finding(
                    title="GitHub Search Skipped (No Token)",
                    description=(
                        "Set the GITHUB_TOKEN environment variable to enable GitHub "
                        "public code search for domain leaks."
                    ),
                    severity=Severity.INFO,
                    category=Category.GITHUB,
                    confidence=Confidence.LOW,
                    evidence=Evidence(details={"domain": domain}),
                    remediation="Export GITHUB_TOKEN before running the scan.",
                )
            )
            return ScanResults(findings=findings)

        query = f"{domain} in:file"
        resp = make_request(
            _GITHUB_SEARCH_URL,
            params={"q": query, "per_page": _MAX_RESULTS},
            headers=headers,
            timeout=15,
        )

        if resp is None:
            logger.warning("GitHub search request failed for %s", domain)
            return ScanResults(findings=findings)

        if resp.status_code == 403:
            findings.append(
                Finding(
                    title="GitHub API Rate Limit Reached",
                    description="The GitHub API returned 403 – rate limit exceeded.",
                    severity=Severity.INFO,
                    category=Category.GITHUB,
                    confidence=Confidence.LOW,
                    evidence=Evidence(details={"domain": domain}),
                    remediation="Wait before retrying or use an authenticated token.",
                )
            )
            return ScanResults(findings=findings)

        try:
            data = resp.json()
        except ValueError as exc:
            logger.warning("GitHub API returned non-JSON: %s", exc)
            return ScanResults(findings=findings)

        for item in data.get("items", []):
            repo = item.get("repository", {}).get("full_name", "unknown")
            path = item.get("path", "")
            html_url = item.get("html_url", "")
            findings.append(
                Finding(
                    title=f"Domain Reference Found on GitHub: {repo}",
                    description=(
                        f"The domain {domain!r} appears in the public GitHub repository "
                        f"{repo!r} at path {path!r}. This may indicate a leaked secret or "
                        "configuration."
                    ),
                    severity=Severity.MEDIUM,
                    category=Category.GITHUB,
                    confidence=Confidence.MEDIUM,
                    evidence=Evidence(details={"repo": repo, "path": path}),
                    remediation=(
                        "Review the file for sensitive data. If secrets are exposed, "
                        "revoke and rotate them immediately."
                    ),
                    url=html_url,
                )
            )

        return ScanResults(findings=findings)
