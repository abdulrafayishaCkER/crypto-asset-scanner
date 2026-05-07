"""GitHub public code search for domain-related leaks."""

from __future__ import annotations

from typing import Optional, List

from crypto_recon.models.asset import Confidence
from crypto_recon.models.evidence import Evidence
from crypto_recon.models.finding import Finding, Severity, Category
from crypto_recon.models.scan_result import ScanResult
from crypto_recon.utils.network import make_request
from crypto_recon.utils.logger import get_logger

logger = get_logger(__name__)

_GITHUB_SEARCH_URL = "https://api.github.com/search/code"
_MAX_RESULTS = 10


class GitHubScanner:
    """Search GitHub public repositories for references to a target domain."""

    def __init__(self, token: Optional[str] = None) -> None:
        """Initialise the scanner.

        Args:
            token: Optional GitHub personal access token for higher rate limits.
        """
        self.token = token

    def search(self, domain: str) -> ScanResult:
        """Search GitHub for public code mentioning *domain*."""
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
                    remediation="Export GITHUB_TOKEN before running the scan.",
                )
            )
            return ScanResult(findings=findings)

        query = f"{domain} in:file"
        resp = make_request(
            _GITHUB_SEARCH_URL,
            params={"q": query, "per_page": _MAX_RESULTS},
            headers=headers,
            timeout=15,
        )

        if resp is None:
            logger.warning("GitHub search request failed for %s", domain)
            return ScanResult(findings=findings)

        if resp.status_code == 403:
            findings.append(
                Finding(
                    title="GitHub API Rate Limit Reached",
                    description="The GitHub API returned 403 – rate limit exceeded.",
                    severity=Severity.INFO,
                    category=Category.GITHUB,
                    confidence=Confidence.LOW,
                    remediation="Wait before retrying or use an authenticated token.",
                )
            )
            return ScanResult(findings=findings)

        try:
            data = resp.json()
        except ValueError as exc:
            logger.warning("GitHub API returned non-JSON: %s", exc)
            return ScanResult(findings=findings)

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
                    evidence=Evidence(url=html_url, details=f"Repo: {repo} | File: {path}"),
                    remediation=(
                        "Review the file for sensitive data. If secrets are exposed, "
                        "revoke and rotate them immediately."
                    ),
                    url=html_url,
                )
            )

        return ScanResult(findings=findings)
