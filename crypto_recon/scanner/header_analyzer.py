"""HTTP security header analyser."""

from __future__ import annotations

from typing import List

from crypto_recon.models.finding import Finding, Severity, Category
from crypto_recon.utils.network import make_request
from crypto_recon.utils.logger import get_logger

logger = get_logger(__name__)


class HeaderAnalyzer:
    """Analyse HTTP response headers for security issues."""

    def analyze(self, target: str, port: int = 443) -> List[Finding]:
        """Fetch headers from *target* and check for security issues.

        Args:
            target: Hostname.
            port: TCP port (default 443).

        Returns:
            List of :class:`Finding` objects.
        """
        findings: List[Finding] = []
        scheme = "https" if port != 80 else "http"
        url = f"{scheme}://{target}" if port in (80, 443) else f"{scheme}://{target}:{port}"

        resp = make_request(url)
        if resp is None:
            # Try HTTP fallback
            url_http = f"http://{target}" if port in (80, 443) else f"http://{target}:{port}"
            resp = make_request(url_http)

        if resp is None:
            logger.warning("Could not fetch headers from %s", target)
            return findings

        headers = {k.lower(): v for k, v in resp.headers.items()}
        findings.extend(self._check_hsts(headers))
        findings.extend(self._check_csp(headers))
        findings.extend(self._check_x_content_type(headers))
        findings.extend(self._check_x_frame(headers))
        findings.extend(self._check_x_xss(headers))
        findings.extend(self._check_referrer_policy(headers))
        findings.extend(self._check_permissions_policy(headers))
        findings.extend(self._check_corp_coop(headers))
        findings.extend(self._check_cache_control(headers))
        findings.extend(self._check_server_disclosure(headers))
        findings.extend(self._check_x_powered_by(headers))
        return findings

    # ------------------------------------------------------------------ helpers

    def _check_hsts(self, headers: dict) -> List[Finding]:
        findings: List[Finding] = []
        hsts = headers.get("strict-transport-security")
        if not hsts:
            findings.append(
                Finding(
                    title="Missing Strict-Transport-Security Header",
                    description=(
                        "The Strict-Transport-Security (HSTS) header is absent. "
                        "Without it, browsers may connect over HTTP."
                    ),
                    severity=Severity.HIGH,
                    category=Category.HEADERS,
                    remediation=(
                        "Add: Strict-Transport-Security: max-age=31536000; "
                        "includeSubDomains; preload"
                    ),
                    cwe="CWE-319",
                )
            )
        else:
            if "max-age=0" in hsts or "max-age=" not in hsts:
                findings.append(
                    Finding(
                        title="Weak Strict-Transport-Security Header",
                        description="HSTS header is present but misconfigured (zero or missing max-age).",
                        severity=Severity.MEDIUM,
                        category=Category.HEADERS,
                        evidence=f"Header value: {hsts}",
                        remediation="Set max-age to at least 31536000 (1 year).",
                        cwe="CWE-319",
                    )
                )
        return findings

    def _check_csp(self, headers: dict) -> List[Finding]:
        findings: List[Finding] = []
        csp = headers.get("content-security-policy")
        if not csp:
            findings.append(
                Finding(
                    title="Missing Content-Security-Policy Header",
                    description="No CSP header detected. XSS and injection attacks are not mitigated.",
                    severity=Severity.MEDIUM,
                    category=Category.HEADERS,
                    remediation=(
                        "Define a Content-Security-Policy header that restricts "
                        "allowed sources for scripts, styles, and other resources."
                    ),
                    cwe="CWE-693",
                )
            )
        else:
            problems = []
            if "unsafe-inline" in csp:
                problems.append("'unsafe-inline'")
            if "unsafe-eval" in csp:
                problems.append("'unsafe-eval'")
            if problems:
                findings.append(
                    Finding(
                        title="Unsafe Content-Security-Policy Directives",
                        description=f"CSP contains {', '.join(problems)}, weakening XSS protection.",
                        severity=Severity.MEDIUM,
                        category=Category.HEADERS,
                        evidence=f"CSP: {csp[:200]}",
                        remediation="Remove 'unsafe-inline' and 'unsafe-eval' from the CSP.",
                        cwe="CWE-693",
                    )
                )
        return findings

    def _check_x_content_type(self, headers: dict) -> List[Finding]:
        if "x-content-type-options" not in headers:
            return [
                Finding(
                    title="Missing X-Content-Type-Options Header",
                    description="Without this header, browsers may MIME-sniff responses leading to XSS.",
                    severity=Severity.LOW,
                    category=Category.HEADERS,
                    remediation="Add: X-Content-Type-Options: nosniff",
                    cwe="CWE-693",
                )
            ]
        return []

    def _check_x_frame(self, headers: dict) -> List[Finding]:
        if "x-frame-options" not in headers and "content-security-policy" not in headers:
            return [
                Finding(
                    title="Missing X-Frame-Options Header",
                    description="The page may be embedded in iframes, enabling clickjacking attacks.",
                    severity=Severity.MEDIUM,
                    category=Category.HEADERS,
                    remediation="Add: X-Frame-Options: DENY  (or use CSP frame-ancestors directive).",
                    cwe="CWE-1021",
                )
            ]
        return []

    def _check_x_xss(self, headers: dict) -> List[Finding]:
        xss = headers.get("x-xss-protection")
        if xss and xss.strip() == "0":
            return [
                Finding(
                    title="X-XSS-Protection Disabled",
                    description="X-XSS-Protection: 0 explicitly disables the browser XSS auditor.",
                    severity=Severity.LOW,
                    category=Category.HEADERS,
                    evidence=f"Header: X-XSS-Protection: {xss}",
                    remediation=(
                        "Remove the header (modern browsers ignore it) and rely on a "
                        "strong Content-Security-Policy instead."
                    ),
                    cwe="CWE-693",
                )
            ]
        return []

    def _check_referrer_policy(self, headers: dict) -> List[Finding]:
        if "referrer-policy" not in headers:
            return [
                Finding(
                    title="Missing Referrer-Policy Header",
                    description="Without Referrer-Policy, the full URL may be sent as a Referer to third parties.",
                    severity=Severity.LOW,
                    category=Category.HEADERS,
                    remediation="Add: Referrer-Policy: strict-origin-when-cross-origin",
                )
            ]
        return []

    def _check_permissions_policy(self, headers: dict) -> List[Finding]:
        if "permissions-policy" not in headers and "feature-policy" not in headers:
            return [
                Finding(
                    title="Missing Permissions-Policy Header",
                    description="No Permissions-Policy set; browser features are unrestricted.",
                    severity=Severity.LOW,
                    category=Category.HEADERS,
                    remediation="Add a Permissions-Policy header restricting unused browser APIs.",
                )
            ]
        return []

    def _check_corp_coop(self, headers: dict) -> List[Finding]:
        findings: List[Finding] = []
        if "cross-origin-resource-policy" not in headers:
            findings.append(
                Finding(
                    title="Missing Cross-Origin-Resource-Policy Header",
                    description="CORP not set; resources may be read cross-origin (Spectre).",
                    severity=Severity.LOW,
                    category=Category.HEADERS,
                    remediation="Add: Cross-Origin-Resource-Policy: same-origin",
                )
            )
        if "cross-origin-opener-policy" not in headers:
            findings.append(
                Finding(
                    title="Missing Cross-Origin-Opener-Policy Header",
                    description="COOP not set; the browsing context may be shared cross-origin.",
                    severity=Severity.LOW,
                    category=Category.HEADERS,
                    remediation="Add: Cross-Origin-Opener-Policy: same-origin",
                )
            )
        return findings

    def _check_cache_control(self, headers: dict) -> List[Finding]:
        findings: List[Finding] = []
        cc = headers.get("cache-control", "")
        if not cc:
            findings.append(
                Finding(
                    title="Missing Cache-Control Header",
                    description="No Cache-Control header; sensitive responses may be cached.",
                    severity=Severity.LOW,
                    category=Category.HEADERS,
                    remediation="Add: Cache-Control: no-store for sensitive pages.",
                )
            )
        return findings

    def _check_server_disclosure(self, headers: dict) -> List[Finding]:
        server = headers.get("server", "")
        if server and any(c.isdigit() for c in server):
            return [
                Finding(
                    title="Server Version Disclosure",
                    description="The Server header reveals software version information.",
                    severity=Severity.LOW,
                    category=Category.HEADERS,
                    evidence=f"Server: {server}",
                    remediation="Configure the server to return a generic or empty Server header.",
                    cwe="CWE-200",
                )
            ]
        return []

    def _check_x_powered_by(self, headers: dict) -> List[Finding]:
        xpb = headers.get("x-powered-by", "")
        if xpb:
            return [
                Finding(
                    title="X-Powered-By Information Disclosure",
                    description="The X-Powered-By header reveals backend technology.",
                    severity=Severity.LOW,
                    category=Category.HEADERS,
                    evidence=f"X-Powered-By: {xpb}",
                    remediation="Remove the X-Powered-By header from server responses.",
                    cwe="CWE-200",
                )
            ]
        return []
