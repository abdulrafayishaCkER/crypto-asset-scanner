"""Web crawler that discovers exposed paths and API endpoints."""

from __future__ import annotations

import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from urllib.parse import urljoin

from crypto_recon.config import (
    COMMON_API_PATHS,
    EXPOSED_PATHS,
    HTTP_TIMEOUT,
    LOGIN_PAGE_PATTERNS,
    MAX_REQUEST_BUDGET,
    MAX_THREADS,
    RATE_LIMIT_PER_SECOND,
    SOFT_404_PATTERNS,
)
from crypto_recon.models.asset import Asset, AssetType, Confidence
from crypto_recon.models.evidence import Evidence
from crypto_recon.models.finding import Category, Finding, Severity
from crypto_recon.models.scan_result import ScanResults
from crypto_recon.scanner.secret_scanner import SecretScanner
from crypto_recon.utils.logger import get_logger
from crypto_recon.utils.network import make_request

logger = get_logger(__name__)

# Status codes that indicate a path is genuinely accessible
_ACCESSIBLE_STATUS = {200, 206}
# Status codes that indicate a redirect (potentially to a real resource)
_REDIRECT_STATUS = {301, 302, 307, 308}

_secret_scanner = SecretScanner()


class WebCrawler:
    """Concurrently probe exposed paths and API endpoints on a web target."""

    def __init__(
        self,
        timeout: int = HTTP_TIMEOUT,
        threads: int = MAX_THREADS,
        max_requests: int = MAX_REQUEST_BUDGET,
        rate_limit: float = RATE_LIMIT_PER_SECOND,
        user_agent: str | None = None,
    ) -> None:
        """Initialise the crawler.

        Args:
            timeout: Per-request timeout in seconds.
            threads: Maximum concurrent worker threads.
            max_requests: Maximum number of HTTP requests per scan.
            rate_limit: Maximum requests per second.
            user_agent: Optional override for the User-Agent header.
        """
        self.timeout = timeout
        self.threads = threads
        self.max_requests = MAX_REQUEST_BUDGET if max_requests is None else max_requests
        self.rate_limit = RATE_LIMIT_PER_SECOND if rate_limit is None else rate_limit
        self.user_agent = user_agent
        self._controller = _RequestController(self.max_requests, self.rate_limit)

    def crawl(self, target: str, port: int = 443) -> ScanResults:
        """Check all :data:`~crypto_recon.config.EXPOSED_PATHS` against *target*.

        Also scans accessible responses for embedded secrets.

        Args:
            target: Hostname.
            port: TCP port (default 443).

        Returns:
            :class:`ScanResults` with findings and endpoint assets.
        """
        base_url = self._base_url(target, port)
        results = ScanResults()

        def check_path(path: str) -> ScanResults:
            url = urljoin(base_url + "/", path.lstrip("/"))
            resp = self._request(url, method="GET")
            if resp is None:
                return ScanResults()

            local_results = ScanResults()
            if resp.status_code in _ACCESSIBLE_STATUS:
                if self._is_soft_404(resp):
                    return local_results

                is_login = self._is_login_page(resp)
                evidence = Evidence(
                    url=url,
                    details={
                        "status_code": resp.status_code,
                        "content_length": len(resp.content),
                        "login_page": is_login,
                    },
                )

                local_results.assets.append(
                    Asset(
                        asset_type=AssetType.ENDPOINT,
                        name=f"/{path}",
                        description="Discovered web path during crawling.",
                        confidence=Confidence.LOW,
                        evidence=evidence,
                        metadata={"validated": False},
                    )
                )

                if is_login:
                    local_results.findings.append(
                        Finding(
                            title=f"Potentially Protected Path: /{path}",
                            description=(
                                f"The path /{path} returned a login page, suggesting authentication "
                                "may be required. Treat this as a low-confidence discovery."
                            ),
                            severity=Severity.LOW,
                            category=Category.FILES,
                            confidence=Confidence.LOW,
                            evidence=evidence,
                            remediation="Confirm access controls and ensure sensitive paths are protected.",
                            url=url,
                        )
                    )
                else:
                    local_results.findings.append(
                        Finding(
                            title=f"Exposed Sensitive Path: /{path}",
                            description=(
                                f"The path /{path} returned HTTP {resp.status_code}, indicating "
                                "it may be publicly accessible."
                            ),
                            severity=self._path_severity(path),
                            category=Category.FILES,
                            confidence=Confidence.LOW,
                            evidence=evidence,
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
                    local_results.extend(secret_hits)
                except Exception as exc:
                    logger.debug("Secret scan error for %s: %s", url, exc)

            return local_results

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_path, p): p for p in EXPOSED_PATHS}
            for future in as_completed(futures):
                try:
                    results.extend(future.result())
                except Exception as exc:
                    logger.debug("Crawler worker error: %s", exc)

        # Also scan homepage JS for secrets
        results.extend(self._scan_homepage_js(base_url))

        return results

    def discover_api_endpoints(self, target: str, port: int = 443) -> ScanResults:
        """Probe :data:`~crypto_recon.config.COMMON_API_PATHS` for accessible API endpoints.

        Args:
            target: Hostname.
            port: TCP port.

        Returns:
            :class:`ScanResults` with endpoint findings and assets.
        """
        base_url = self._base_url(target, port)
        results = ScanResults()

        def probe_endpoint(path: str) -> ScanResults:
            url = urljoin(base_url, path)
            resp = self._request(url, method="HEAD")
            if resp is None:
                return ScanResults()
            if resp.status_code < 400:
                evidence = Evidence(url=url, details={"status_code": resp.status_code})
                local = ScanResults()
                local.assets.append(
                    Asset(
                        asset_type=AssetType.ENDPOINT,
                        name=path,
                        description="Potential API endpoint discovered.",
                        confidence=Confidence.LOW,
                        evidence=evidence,
                        metadata={"validated": False},
                    )
                )
                local.findings.append(
                    Finding(
                        title=f"API Endpoint Discovered: {path}",
                        description=f"The API path {path} returned HTTP {resp.status_code}.",
                        severity=Severity.INFO,
                        category=Category.API,
                        confidence=Confidence.LOW,
                        evidence=evidence,
                        remediation="Ensure API endpoints require proper authentication and authorisation.",
                        url=url,
                    )
                )
                return local
            return ScanResults()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(probe_endpoint, p): p for p in COMMON_API_PATHS}
            for future in as_completed(futures):
                try:
                    results.extend(future.result())
                except Exception as exc:
                    logger.debug("API probe worker error: %s", exc)

        return results

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

    def _scan_homepage_js(self, base_url: str) -> ScanResults:
        """Fetch the homepage, discover JS files, and scan for secrets."""
        results = ScanResults()
        resp = self._request(base_url)
        if resp is None:
            return results

        js_urls: set[str] = set()
        for match in re.findall(
            r'<script[^>]+src=[\'"]([^\'"]+\.js)[\'"]', resp.text, re.IGNORECASE
        ):
            js_urls.add(urljoin(base_url, match))

        for js_url in list(js_urls)[:10]:  # Cap at 10 JS files
            js_resp = self._request(js_url)
            if js_resp is None:
                continue
            secret_hits = _secret_scanner.scan_text(js_resp.text, source_url=js_url)
            results.extend(secret_hits)

        return results

    def _request(self, url: str, method: str = "GET"):
        if not self._controller.allow():
            return None
        headers = {}
        if self.user_agent:
            headers["User-Agent"] = self.user_agent
        return make_request(url, method=method, timeout=self.timeout, headers=headers)

    @staticmethod
    def _is_soft_404(resp) -> bool:
        if resp.status_code not in _ACCESSIBLE_STATUS:
            return False
        text = resp.text.lower()
        return any(pattern in text for pattern in SOFT_404_PATTERNS)

    @staticmethod
    def _is_login_page(resp) -> bool:
        text = resp.text.lower()
        if "type=\"password\"" in text:
            return True
        return any(pattern in text for pattern in LOGIN_PAGE_PATTERNS)


class _RequestController:
    """Shared request budget and rate limiting for crawler threads."""

    def __init__(self, max_requests: int, rate_limit: float) -> None:
        self.max_requests = max_requests
        self.rate_limit = rate_limit
        self._lock = threading.Lock()
        self._last_request = 0.0
        self._count = 0

    def allow(self) -> bool:
        with self._lock:
            if self.max_requests and self._count >= self.max_requests:
                return False
            wait = 0.0
            if self.rate_limit:
                min_interval = 1.0 / self.rate_limit
                now = time.monotonic()
                delta = now - self._last_request
                if delta < min_interval:
                    wait = min_interval - delta
                self._last_request = now + wait
            self._count += 1
        if wait:
            time.sleep(wait)
        return True
