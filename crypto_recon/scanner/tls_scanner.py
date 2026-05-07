"""TLS protocol and cipher suite scanner using sslyze."""

from __future__ import annotations

from crypto_recon.config import WEAK_CIPHER_KEYWORDS
from crypto_recon.models.asset import Asset, AssetType, Confidence
from crypto_recon.models.evidence import Evidence
from crypto_recon.models.finding import Category, Finding, Severity
from crypto_recon.models.scan_result import ScanResults
from crypto_recon.utils.logger import get_logger

logger = get_logger(__name__)

# Mapping of deprecated / insecure TLS versions.
_DEPRECATED_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}


def _classify_cipher(name: str) -> str:
    """Classify a cipher suite name as strong/acceptable/weak/insecure."""
    upper = name.upper()
    for kw in WEAK_CIPHER_KEYWORDS:
        if kw.upper() in upper:
            return "insecure"
    if "CHACHA20" in upper or "GCM" in upper or "ECDHE" in upper:
        return "strong"
    if "CBC" in upper:
        return "acceptable"
    return "weak"


class TLSScanner:
    """Enumerate TLS protocol support, cipher suites, and common vulnerabilities."""

    def __init__(self, timeout: int = 10) -> None:
        """Initialise the scanner.

        Args:
            timeout: Network timeout in seconds.
        """
        self.timeout = timeout

    def scan(self, target: str, port: int = 443) -> ScanResults:
        """Scan *target*:*port* and return a list of TLS-related findings.

        Args:
            target: Hostname or IP address.
            port: TCP port (default 443).

        Returns:
            :class:`ScanResults` with TLS findings and assets.
        """
        results = ScanResults()
        try:
            from sslyze import (
                ScanCommandAttemptStatusEnum,
                Scanner,
                ServerNetworkLocation,
                ServerScanRequest,
            )
        except ImportError:
            logger.warning("sslyze not installed; skipping TLS scan.")
            return results

        try:
            scanner = Scanner()
            scan_request = ServerScanRequest(
                server_location=ServerNetworkLocation(hostname=target, port=port)
            )
            scanner.queue_scans([scan_request])
            scan_results = list(scanner.get_results())
        except Exception as exc:
            logger.error("sslyze scan failed for %s:%d – %s", target, port, exc)
            return results

        if not scan_results:
            return results

        server_scan = scan_results[0]
        if server_scan.scan_status.name == "ERROR_NO_CONNECTIVITY":
            results.findings.append(
                Finding(
                    title="TLS Connectivity Failed",
                    description=f"Could not connect to {target}:{port} over TLS.",
                    severity=Severity.HIGH,
                    category=Category.TLS,
                    confidence=Confidence.HIGH,
                    evidence=Evidence(endpoint=f"{target}:{port}", details={"port": port}),
                    remediation="Verify the host is reachable and TLS is enabled.",
                )
            )
            return results

        scan_res = server_scan.scan_result
        protocol_map = [
            ("ssl_2_0_cipher_suites", "SSLv2"),
            ("ssl_3_0_cipher_suites", "SSLv3"),
            ("tls_1_0_cipher_suites", "TLSv1.0"),
            ("tls_1_1_cipher_suites", "TLSv1.1"),
            ("tls_1_2_cipher_suites", "TLSv1.2"),
            ("tls_1_3_cipher_suites", "TLSv1.3"),
        ]

        try:
            status_enum = ScanCommandAttemptStatusEnum
        except Exception:
            return results

        for attr_name, label in protocol_map:
            attempt = getattr(scan_res, attr_name, None)
            if attempt is None or attempt.status != status_enum.COMPLETED:
                continue

            suites = [c.cipher_suite.name for c in attempt.result.accepted_cipher_suites]
            if not suites:
                continue

            # Flag deprecated protocols
            if label in _DEPRECATED_PROTOCOLS:
                severity = Severity.CRITICAL if label in {"SSLv2", "SSLv3"} else Severity.HIGH
            results.assets.append(
                Asset(
                    asset_type=AssetType.TLS_PROTOCOL,
                    name=label,
                    description="Supported TLS protocol version.",
                    confidence=Confidence.HIGH,
                    evidence=Evidence(endpoint=f"{target}:{port}"),
                    metadata={"cipher_suites": suites[:20]},
                )
            )

            for suite in suites:
                classification = _classify_cipher(suite)
                results.assets.append(
                    Asset(
                        asset_type=AssetType.TLS_CIPHER_SUITE,
                        name=suite,
                        description=f"TLS cipher suite ({classification}).",
                        confidence=Confidence.HIGH,
                        evidence=Evidence(endpoint=f"{target}:{port}", details={"protocol": label}),
                        metadata={"classification": classification, "protocol": label},
                    )
                )

            if label in _DEPRECATED_PROTOCOLS:
                results.findings.append(
                Finding(
                    title=f"Deprecated Protocol Supported: {label}",
                    description=(
                        f"The server accepts connections using {label}, which is "
                        "cryptographically broken and must not be used."
                    ),
                    severity=severity,
                    category=Category.TLS,
                    confidence=Confidence.HIGH,
                    evidence=Evidence(
                        endpoint=f"{target}:{port}",
                        details={"protocol": label, "sample_ciphers": suites[:5]},
                    ),
                    remediation=(
                        "Disable all protocol versions below TLS 1.2. "
                        "Configure the server to support only TLS 1.2 and TLS 1.3."
                    ),
                    cwe="CWE-326",
                )
            )

            # Flag individual weak/insecure ciphers
            weak_suites = [s for s in suites if _classify_cipher(s) in {"weak", "insecure"}]
            if weak_suites:
                results.findings.append(
                    Finding(
                        title=f"Weak Cipher Suites in {label}",
                        description=(
                            f"The server offers {len(weak_suites)} weak or insecure cipher "
                            f"suite(s) under {label}."
                        ),
                        severity=Severity.HIGH,
                        category=Category.TLS,
                        confidence=Confidence.HIGH,
                        evidence=Evidence(
                            endpoint=f"{target}:{port}",
                            details={"protocol": label, "weak_suites": weak_suites[:10]},
                        ),
                        remediation=(
                            "Remove all RC4, 3DES, DES, NULL, EXPORT, and anonymous cipher "
                            "suites. Prefer ECDHE+AESGCM and ChaCha20-Poly1305."
                        ),
                        cwe="CWE-327",
                    )
                )

        # Heartbleed check
        hb_attempt = getattr(scan_res, "heartbleed", None)
        if hb_attempt and hb_attempt.status == status_enum.COMPLETED:
            if hb_attempt.result.is_vulnerable_to_heartbleed:
                results.findings.append(
                    Finding(
                        title="Heartbleed Vulnerability (CVE-2014-0160)",
                        description=(
                            "The server is vulnerable to Heartbleed, allowing an attacker "
                            "to read arbitrary server memory including private keys."
                        ),
                        severity=Severity.CRITICAL,
                        category=Category.TLS,
                        confidence=Confidence.HIGH,
                        evidence=Evidence(endpoint=f"{target}:{port}"),
                        remediation="Update OpenSSL to 1.0.1g or later immediately.",
                        cve="CVE-2014-0160",
                        cwe="CWE-125",
                    )
                )

        return results
