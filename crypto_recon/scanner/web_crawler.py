"""Web crawler that discovers exposed paths and API endpoints."""

from __future__ import annotations

import hashlib
import re
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from typing import List, Optional, Tuple
from urllib.parse import urljoin

from crypto_recon.config import (
    EXPOSED_PATHS,
    COMMON_API_PATHS,
    HTTP_TIMEOUT,
    MAX_THREADS,
    MAX_REQUESTS,
    REQUESTS_PER_SECOND,
)
from crypto_recon.models.asset import Asset, AssetType, Confidence
from crypto_recon.models.evidence import Evidence
from crypto_recon.models.finding import Finding, Severity, Category
from crypto_recon.models.scan_result import ScanResult
from crypto_recon.scanner.secret_scanner import SecretScanner
from crypto_recon.utils.network import make_request
from crypto_recon.utils.logger import get_logger

logger = get_logger(__name__)

# Status codes that indicate a path is genuinely accessible
_ACCESSIBLE_STATUS = {200, 206}
# Status codes that indicate a redirect (potentially to a real resource)
_REDIRECT_STATUS = {301, 302, 307, 308}

_secret_scanner = SecretScanner()


class RequestBudget:
    def __init__(self, max_requests: int) -> None:
        self.max_requests = max_requests
        self._count = 0
        self._lock = Lock()

    def consume(self) -> bool:
        with self._lock:
            if self._count >= self.max_requests:
                return False
            self._count += 1
            return True


class RateLimiter:
    def __init__(self, requests_per_second: float) -> None:
        self.interval = 1.0 / requests_per_second if requests_per_second > 0 else 0
        self._lock = Lock()
        self._next_time = 0.0

    def wait(self) -> None:
        if self.interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            if now < self._next_time:
                time.sleep(self._next_time - now)
            self._next_time = max(now, self._next_time) + self.interval


class WebCrawler:
    """Concurrently probe exposed paths and API endpoints on a web target."""

    def __init__(
        self,
        timeout: int = HTTP_TIMEOUT,
        threads: int = MAX_THREADS,
        max_requests: int = MAX_REQUESTS,
        requests_per_second: float = REQUESTS_PER_SECOND,
    ) -> None:
        """Initialise the crawler.

        Args:
            timeout: Per-request timeout in seconds.
            threads: Maximum concurrent worker threads.
            max_requests: Overall request budget.
            requests_per_second: Maximum request rate.
        """
        self.timeout = timeout
        self.threads = threads
        self._budget = RequestBudget(max_requests)
        self._rate_limiter = RateLimiter(requests_per_second)

    def crawl(self, target: str, port: int = 443) -> ScanResult:
        """Check all :data:`~crypto_recon.config.EXPOSED_PATHS` against *target*.

        Also scans accessible responses for embedded secrets.
        """
        base_url = self._base_url(target, port)
        result = ScanResult()
        soft_404_sig = self._fetch_soft_404_signature(base_url)

        def check_path(path: str) -> ScanResult:
            url = urljoin(base_url + "/", path.lstrip("/"))
            resp = self._request(url, method="GET")
            if resp is None:
                return ScanResult()

            local = ScanResult()
            if resp.status_code in _ACCESSIBLE_STATUS or resp.status_code in _REDIRECT_STATUS:
                is_soft_404 = self._is_soft_404(resp, soft_404_sig)
                is_login = self._looks_like_login(resp.text)
                validated = resp.status_code in _ACCESSIBLE_STATUS and not is_soft_404 and not is_login
                confidence = Confidence.MEDIUM if validated else Confidence.LOW

                evidence = Evidence(
                    url=url,
                    endpoint=path,
                    details=f"status={resp.status_code}; length={len(resp.content)}",
                )
                asset = Asset(
                    asset_type=AssetType.ENDPOINT,
                    name=f"/{path}",
                    description="Potentially exposed path discovered via HTTP probing.",
                    confidence=confidence,
                    evidence=evidence,
                    metadata={"validated": validated, "soft_404": is_soft_404, "login_like": is_login},
                )
                asset.dedup_key = asset.compute_dedup_key()
                local.assets.append(asset)

                if not is_soft_404:
                    local.findings.append(
                        Finding(
                            title=f"Exposed Sensitive Path: /{path}",
                            description=(
                                f"The path /{path} returned HTTP {resp.status_code}. "
                                "Result confidence is reduced until validated."
                            ),
                            severity=self._path_severity(path),
                            category=Category.FILES,
                            confidence=confidence,
                            evidence=evidence,
                            remediation=(
                                "Restrict access to this path via server configuration or "
                                "remove the file if it is not required."
                            ),
                            url=url,
                            cwe="CWE-538",
                            related_assets=[asset.dedup_key],
                        )
                    )
                # Scan response body for secrets
                try:
                    secret_hits = _secret_scanner.scan_text(resp.text, source_url=url)
                    local.findings.extend(secret_hits.findings)
                    local.assets.extend(secret_hits.assets)
                except Exception as exc:
                    logger.debug("Secret scan error for %s: %s", url, exc)

            return local

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_path, p): p for p in EXPOSED_PATHS}
            for future in as_completed(futures):
                try:
                    result.extend(future.result())
                except Exception as exc:
                    logger.debug("Crawler worker error: %s", exc)

        # Also scan homepage JS for secrets
        result.extend(self._scan_homepage_js(base_url))

        return result

    def discover_api_endpoints(self, target: str, port: int = 443) -> ScanResult:
        """Probe :data:`~crypto_recon.config.COMMON_API_PATHS` for accessible API endpoints."""
        base_url = self._base_url(target, port)
        result = ScanResult()

        def probe_endpoint(path: str) -> ScanResult:
            url = urljoin(base_url, path)
            resp = self._request(url, method="HEAD")
            if resp is None:
                return ScanResult()
            if resp.status_code < 400:
                evidence = Evidence(url=url, endpoint=path, details=f"status={resp.status_code}")
                asset = Asset(
                    asset_type=AssetType.ENDPOINT,
                    name=path,
                    description="Common API endpoint discovered by probing.",
                    confidence=Confidence.LOW,
                    evidence=evidence,
                    metadata={"validated": False},
                )
                asset.dedup_key = asset.compute_dedup_key()
                return ScanResult(
                    findings=[
                        Finding(
                            title=f"API Endpoint Discovered: {path}",
                            description=f"The API path {path} returned HTTP {resp.status_code}.",
                            severity=Severity.INFO,
                            category=Category.API,
                            confidence=Confidence.LOW,
                            evidence=evidence,
                            remediation="Ensure API endpoints require proper authentication and authorisation.",
                            url=url,
                            related_assets=[asset.dedup_key],
                        )
                    ],
                    assets=[asset],
                )
            return ScanResult()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(probe_endpoint, p): p for p in COMMON_API_PATHS}
            for future in as_completed(futures):
                try:
                    result.extend(future.result())
                except Exception as exc:
                    logger.debug("API probe worker error: %s", exc)

        return result

    # ------------------------------------------------------------------ helpers

    def _request(self, url: str, method: str = "GET"):
        if not self._budget.consume():
            logger.debug("Request budget exhausted, skipping %s", url)
            return None
        self._rate_limiter.wait()
        return make_request(url, method=method, timeout=self.timeout)

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

    def _scan_homepage_js(self, base_url: str) -> ScanResult:
        """Fetch the homepage, discover JS files, and scan for secrets."""
        result = ScanResult()
        resp = self._request(base_url, method="GET")
        if resp is None:
            return result

        js_urls: set[str] = set()
        for match in re.findall(
            r'<script[^>]+src=[\'"]([^\'"]+\.js)[\'"]', resp.text, re.IGNORECASE
        ):
            js_urls.add(urljoin(base_url, match))

        for js_url in list(js_urls)[:10]:
            js_resp = self._request(js_url, method="GET")
            if js_resp is None:
                continue
            secret_hits = _secret_scanner.scan_text(js_resp.text, source_url=js_url)
            result.findings.extend(secret_hits.findings)
            result.assets.extend(secret_hits.assets)

        return result

    def _fetch_soft_404_signature(self, base_url: str) -> Optional[Tuple[int, str, int]]:
        random_path = f"/.well-known/cryptorecon-{uuid.uuid4().hex}"
        url = urljoin(base_url, random_path)
        resp = self._request(url, method="GET")
        if resp is None:
            return None
        return (resp.status_code, self._body_hash(resp.text), len(resp.text))

    @staticmethod
    def _body_hash(text: str) -> str:
        normalized = re.sub(r"\s+", " ", text).strip().lower()
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    def _is_soft_404(self, resp, signature: Optional[Tuple[int, str, int]]) -> bool:
        if signature is None:
            return False
        status, sig_hash, length = signature
        if resp.status_code != status:
            return False
        if abs(len(resp.text) - length) > 200:
            return False
        return self._body_hash(resp.text) == sig_hash

    @staticmethod
    def _looks_like_login(text: str) -> bool:
        lower = text.lower()
        if "type=\"password\"" in lower or "name=\"password\"" in lower:
            return True
        if "login" in lower and "<form" in lower:
            return True
        return False
