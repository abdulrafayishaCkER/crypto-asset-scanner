"""Web crawler that discovers exposed paths and API endpoints."""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List
from urllib.parse import urljoin

from crypto_recon.config import EXPOSED_PATHS, COMMON_API_PATHS, HTTP_TIMEOUT, MAX_THREADS
from crypto_recon.models.finding import Finding, Severity, Category
from crypto_recon.scanner.secret_scanner import SecretScanner
from crypto_recon.utils.network import make_request
from crypto_recon.utils.logger import get_logger

logger = get_logger(__name__)

# Status codes that indicate a path is genuinely accessible
_ACCESSIBLE_STATUS = {200, 206}
# Status codes that indicate a redirect (potentially to a real resource)
_REDIRECT_STATUS = {301, 302, 307, 308}

_secret_scanner = SecretScanner()


class WebCrawler:
    """Concurrently probe exposed paths and API endpoints on a web target."""

    def __init__(self, timeout: int = HTTP_TIMEOUT, threads: int = MAX_THREADS) -> None:
        """Initialise the crawler.

        Args:
            timeout: Per-request timeout in seconds.
            threads: Maximum concurrent worker threads.
        """
        self.timeout = timeout
        self.threads = threads

    def crawl(self, target: str, port: int = 443) -> List[Finding]:
        """Check all :data:`~crypto_recon.config.EXPOSED_PATHS` against *target*.

        Also scans accessible responses for embedded secrets.

        Args:
            target: Hostname.
            port: TCP port (default 443).

        Returns:
            List of :class:`Finding` objects.
        """
        base_url = self._base_url(target, port)
        findings: List[Finding] = []

        def check_path(path: str) -> List[Finding]:
            url = urljoin(base_url + "/", path.lstrip("/"))
            resp = make_request(url, method="GET", timeout=self.timeout)
            if resp is None:
                return []

            local_findings: List[Finding] = []
            if resp.status_code in _ACCESSIBLE_STATUS:
                local_findings.append(
                    Finding(
                        title=f"Exposed Sensitive Path: /{path}",
                        description=(
                            f"The path /{path} returned HTTP {resp.status_code}, indicating "
                            "it may be publicly accessible."
                        ),
                        severity=self._path_severity(path),
                        category=Category.FILES,
                        evidence=f"URL: {url} | Status: {resp.status_code} | "
                                 f"Content-Length: {len(resp.content)} bytes",
                        remediation=(
                            "Restrict access to this path via server configuration or "
                            "remove the file if it is not required."
                        ),
                        url=url,
                        cwe="CWE-538",
                    )
                )
                # Scan response body for secrets
                try:
                    secret_hits = _secret_scanner.scan_text(resp.text, source_url=url)
                    local_findings.extend(secret_hits)
                except Exception as exc:
                    logger.debug("Secret scan error for %s: %s", url, exc)

            return local_findings

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_path, p): p for p in EXPOSED_PATHS}
            for future in as_completed(futures):
                try:
                    findings.extend(future.result())
                except Exception as exc:
                    logger.debug("Crawler worker error: %s", exc)

        # Also scan homepage JS for secrets
        findings.extend(self._scan_homepage_js(base_url))

        return findings

    def discover_api_endpoints(self, target: str, port: int = 443) -> List[Finding]:
        """Probe :data:`~crypto_recon.config.COMMON_API_PATHS` for accessible API endpoints.

        Args:
            target: Hostname.
            port: TCP port.

        Returns:
            List of :class:`Finding` objects.
        """
        base_url = self._base_url(target, port)
        findings: List[Finding] = []

        def probe_endpoint(path: str) -> List[Finding]:
            url = urljoin(base_url, path)
            resp = make_request(url, method="HEAD", timeout=self.timeout)
            if resp is None:
                return []
            if resp.status_code < 400:
                return [
                    Finding(
                        title=f"API Endpoint Discovered: {path}",
                        description=f"The API path {path} returned HTTP {resp.status_code}.",
                        severity=Severity.INFO,
                        category=Category.API,
                        evidence=f"URL: {url} | Status: {resp.status_code}",
                        remediation="Ensure API endpoints require proper authentication and authorisation.",
                        url=url,
                    )
                ]
            return []

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(probe_endpoint, p): p for p in COMMON_API_PATHS}
            for future in as_completed(futures):
                try:
                    findings.extend(future.result())
                except Exception as exc:
                    logger.debug("API probe worker error: %s", exc)

        return findings

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _base_url(target: str, port: int) -> str:
        if port == 443:
            return f"https://{target}"
        if port == 80:
            return f"http://{target}"
        return f"https://{target}:{port}"

    @staticmethod
    def _path_severity(path: str) -> Severity:
        """Assign severity based on how sensitive the exposed path is."""
        critical_paths = {
            "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
            "server.key", "privkey.pem",
            ".env", ".env.production", ".env.staging",
            ".git/config", "backup.zip", "backup.tar.gz",
            "backup.sql", "db.sql", "dump.sql",
        }
        high_paths = {
            ".htpasswd", "wp-config.php", ".env.local",
            "applicationHost.config", "web.config",
        }
        if path in critical_paths:
            return Severity.CRITICAL
        if path in high_paths:
            return Severity.HIGH
        return Severity.MEDIUM

    def _scan_homepage_js(self, base_url: str) -> List[Finding]:
        """Fetch the homepage, discover JS files, and scan for secrets."""
        findings: List[Finding] = []
        resp = make_request(base_url, timeout=self.timeout)
        if resp is None:
            return findings

        js_urls: set[str] = set()
        for match in re.findall(
            r'<script[^>]+src=[\'"]([^\'"]+\.js)[\'"]', resp.text, re.IGNORECASE
        ):
            js_urls.add(urljoin(base_url, match))

        for js_url in list(js_urls)[:10]:  # Cap at 10 JS files
            js_resp = make_request(js_url, timeout=self.timeout)
            if js_resp is None:
                continue
            secret_hits = _secret_scanner.scan_text(js_resp.text, source_url=js_url)
            findings.extend(secret_hits)

        return findings
