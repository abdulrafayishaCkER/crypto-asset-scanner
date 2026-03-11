"""Certificate chain analysis."""

from __future__ import annotations

import datetime
from typing import List

from crypto_recon.models.finding import Finding, Severity, Category
from crypto_recon.utils.logger import get_logger

logger = get_logger(__name__)

_EXPIRY_CRITICAL_DAYS = 0
_EXPIRY_HIGH_DAYS = 30


class CertAnalyzer:
    """Analyse the TLS certificate chain returned by sslyze."""

    def analyze(self, target: str, port: int = 443) -> List[Finding]:
        """Fetch and analyse the certificate chain for *target*:*port*.

        Args:
            target: Hostname.
            port: TCP port (default 443).

        Returns:
            List of :class:`Finding` objects.
        """
        findings: List[Finding] = []
        try:
            from sslyze import (
                Scanner,
                ServerScanRequest,
                ServerNetworkLocation,
                ScanCommandAttemptStatusEnum,
            )
        except ImportError:
            logger.warning("sslyze not installed; skipping certificate analysis.")
            return findings

        try:
            scanner = Scanner()
            req = ServerScanRequest(
                server_location=ServerNetworkLocation(hostname=target, port=port)
            )
            scanner.queue_scans([req])
            results = list(scanner.get_results())
        except Exception as exc:
            logger.error("Certificate analysis failed for %s:%d – %s", target, port, exc)
            return findings

        if not results:
            return findings

        server_scan = results[0]
        if server_scan.scan_status.name == "ERROR_NO_CONNECTIVITY":
            return findings

        scan_res = server_scan.scan_result
        cert_attempt = getattr(scan_res, "certificate_info", None)
        if not cert_attempt or cert_attempt.status != ScanCommandAttemptStatusEnum.COMPLETED:
            return findings

        deployments = cert_attempt.result.certificate_deployments
        if not deployments:
            return findings

        chain = deployments[0].received_certificate_chain
        now = datetime.datetime.now(datetime.timezone.utc)

        for cert in chain:
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()

            # Expiry
            try:
                not_after = cert.not_valid_after_utc
                days_left = (not_after - now).days
                if days_left < _EXPIRY_CRITICAL_DAYS:
                    findings.append(
                        Finding(
                            title="Certificate Expired",
                            description=f"Certificate for {subject} expired {abs(days_left)} day(s) ago.",
                            severity=Severity.CRITICAL,
                            category=Category.CERTIFICATE,
                            evidence=f"Not valid after: {not_after.isoformat()}",
                            remediation="Renew the TLS certificate immediately.",
                            cwe="CWE-298",
                        )
                    )
                elif days_left < _EXPIRY_HIGH_DAYS:
                    findings.append(
                        Finding(
                            title="Certificate Expiring Soon",
                            description=f"Certificate for {subject} expires in {days_left} day(s).",
                            severity=Severity.HIGH,
                            category=Category.CERTIFICATE,
                            evidence=f"Not valid after: {not_after.isoformat()}",
                            remediation="Schedule certificate renewal before expiry.",
                            cwe="CWE-298",
                        )
                    )
            except AttributeError:
                logger.debug("Could not read certificate validity dates.")

            # Self-signed
            if subject == issuer:
                findings.append(
                    Finding(
                        title="Self-Signed Certificate",
                        description="The certificate is self-signed and will not be trusted by browsers.",
                        severity=Severity.HIGH,
                        category=Category.CERTIFICATE,
                        evidence=f"Subject == Issuer: {subject}",
                        remediation=(
                            "Replace the self-signed certificate with one issued by a "
                            "trusted public Certificate Authority."
                        ),
                        cwe="CWE-295",
                    )
                )

            # Weak key size
            try:
                pub_key = cert.public_key()
                key_size = getattr(pub_key, "key_size", None)
                if key_size is not None and key_size < 2048:
                    findings.append(
                        Finding(
                            title="Weak Certificate Key Size",
                            description=(
                                f"Certificate uses a {key_size}-bit key, which is below the "
                                "recommended minimum of 2048 bits."
                            ),
                            severity=Severity.HIGH,
                            category=Category.CERTIFICATE,
                            evidence=f"Key size: {key_size} bits; Subject: {subject}",
                            remediation="Reissue the certificate with at least a 2048-bit RSA key or P-256 EC key.",
                            cwe="CWE-326",
                        )
                    )
            except Exception as exc:
                logger.debug("Could not inspect public key: %s", exc)

        # Forward secrecy indicator
        try:
            leaf_cert_deployment = deployments[0]
            if not leaf_cert_deployment.leaf_certificate_subject_matches_hostname:
                findings.append(
                    Finding(
                        title="Certificate Hostname Mismatch",
                        description="The certificate subject/SAN does not match the target hostname.",
                        severity=Severity.HIGH,
                        category=Category.CERTIFICATE,
                        evidence=f"Target: {target}",
                        remediation=(
                            "Obtain a certificate that includes the target hostname in the "
                            "Subject Alternative Names (SAN) extension."
                        ),
                        cwe="CWE-295",
                    )
                )
        except AttributeError:
            pass

        # OCSP stapling
        try:
            ocsp = getattr(cert_attempt.result, "ocsp_response", None)
            if ocsp is None:
                findings.append(
                    Finding(
                        title="OCSP Stapling Not Configured",
                        description="OCSP stapling is not enabled, which can slow TLS handshakes.",
                        severity=Severity.LOW,
                        category=Category.CERTIFICATE,
                        evidence="No OCSP response stapled",
                        remediation="Enable OCSP stapling on the web server.",
                    )
                )
        except Exception:
            pass

        return findings
