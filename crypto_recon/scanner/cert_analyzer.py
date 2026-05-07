"""Certificate chain analysis."""

from __future__ import annotations

import datetime
from typing import List

from crypto_recon.models.asset import Asset, AssetType, Confidence
from crypto_recon.models.evidence import Evidence
from crypto_recon.models.finding import Finding, Severity, Category
from crypto_recon.models.scan_result import ScanResult
from crypto_recon.utils.logger import get_logger

logger = get_logger(__name__)

_EXPIRY_CRITICAL_DAYS = 0
_EXPIRY_HIGH_DAYS = 30


class CertAnalyzer:
    """Analyse the TLS certificate chain returned by sslyze."""

    @staticmethod
    def extract_certificate_details(cert) -> dict:
        """Extract structured certificate metadata."""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes

        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        signature_algo = ""
        if getattr(cert, "signature_hash_algorithm", None) is not None:
            signature_algo = cert.signature_hash_algorithm.name
        else:
            signature_algo = cert.signature_algorithm_oid.dotted_string

        sans: list[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = san_ext.value.get_values_for_type(x509.DNSName)
        except Exception:
            sans = []

        not_before = getattr(cert, "not_valid_before_utc", cert.not_valid_before)
        not_after = getattr(cert, "not_valid_after_utc", cert.not_valid_after)

        return {
            "subject": subject,
            "issuer": issuer,
            "fingerprint": fingerprint,
            "signature_algorithm": signature_algo,
            "sans": sans,
            "valid_from": not_before,
            "valid_to": not_after,
        }

    def analyze(self, target: str, port: int = 443) -> ScanResult:
        """Fetch and analyse the certificate chain for *target*:*port*.

        Args:
            target: Hostname.
            port: TCP port (default 443).

        Returns:
            :class:`ScanResult` with certificate assets and findings.
        """
        findings: List[Finding] = []
        assets: List[Asset] = []
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes
            from sslyze import (
                Scanner,
                ServerScanRequest,
                ServerNetworkLocation,
                ScanCommandAttemptStatusEnum,
            )
        except ImportError:
            logger.warning("sslyze/cryptography not installed; skipping certificate analysis.")
            return ScanResult()

        try:
            scanner = Scanner()
            req = ServerScanRequest(
                server_location=ServerNetworkLocation(hostname=target, port=port)
            )
            scanner.queue_scans([req])
            results = list(scanner.get_results())
        except Exception as exc:
            logger.error("Certificate analysis failed for %s:%d – %s", target, port, exc)
            return ScanResult()

        if not results:
            return ScanResult()

        server_scan = results[0]
        if server_scan.scan_status.name == "ERROR_NO_CONNECTIVITY":
            return ScanResult()

        scan_res = server_scan.scan_result
        cert_attempt = getattr(scan_res, "certificate_info", None)
        if not cert_attempt or cert_attempt.status != ScanCommandAttemptStatusEnum.COMPLETED:
            return ScanResult()

        deployments = cert_attempt.result.certificate_deployments
        if not deployments:
            return ScanResult()

        chain = deployments[0].received_certificate_chain
        now = datetime.datetime.now(datetime.timezone.utc)
        endpoint = f"{target}:{port}"

        for index, cert in enumerate(chain):
            position = (
                "leaf"
                if index == 0
                else "root"
                if index == len(chain) - 1
                else "intermediate"
            )
            details = self.extract_certificate_details(cert)
            subject = details["subject"]
            issuer = details["issuer"]
            fingerprint = details["fingerprint"]
            signature_algo = details["signature_algorithm"]
            sans = details["sans"]
            not_before = details["valid_from"]
            not_after = details["valid_to"]

            asset = Asset(
                asset_type=AssetType.CERTIFICATE,
                name=subject or f"{target} certificate",
                description=f"Certificate in {position} position of TLS chain for {endpoint}.",
                confidence=Confidence.HIGH,
                evidence=Evidence(
                    endpoint=endpoint,
                    fingerprint=f"sha256:{fingerprint}",
                    details=f"chain_position={position}",
                ),
                fingerprint=f"sha256:{fingerprint}",
                metadata={
                    "subject": subject,
                    "issuer": issuer,
                    "sans": sans,
                    "valid_from": not_before.isoformat(),
                    "valid_to": not_after.isoformat(),
                    "signature_algorithm": signature_algo,
                    "chain_position": position,
                },
            )
            asset.dedup_key = asset.compute_dedup_key()
            assets.append(asset)

            algo_asset = Asset(
                asset_type=AssetType.CRYPTO_ALGORITHM,
                name=signature_algo or "unknown-signature-algorithm",
                description="Certificate signature algorithm.",
                confidence=Confidence.MEDIUM,
                evidence=Evidence(endpoint=endpoint, fingerprint=f"sha256:{fingerprint}"),
                metadata={"certificate_subject": subject},
            )
            algo_asset.dedup_key = algo_asset.compute_dedup_key()
            assets.append(algo_asset)

            # Expiry checks
            days_left = (not_after - now).days
            if index == 0:
                if days_left < _EXPIRY_CRITICAL_DAYS:
                    findings.append(
                        Finding(
                            title="Leaf Certificate Expired",
                            description=f"Leaf certificate expired {abs(days_left)} day(s) ago.",
                            severity=Severity.CRITICAL,
                            category=Category.CERTIFICATE,
                            confidence=Confidence.HIGH,
                            evidence=Evidence(
                                endpoint=endpoint,
                                fingerprint=f"sha256:{fingerprint}",
                                details=f"Not valid after: {not_after.isoformat()}",
                            ),
                            remediation="Renew the TLS certificate immediately.",
                            cwe="CWE-298",
                            related_assets=[asset.dedup_key],
                        )
                    )
                elif days_left < _EXPIRY_HIGH_DAYS:
                    findings.append(
                        Finding(
                            title="Leaf Certificate Expiring Soon",
                            description=f"Leaf certificate expires in {days_left} day(s).",
                            severity=Severity.HIGH,
                            category=Category.CERTIFICATE,
                            confidence=Confidence.HIGH,
                            evidence=Evidence(
                                endpoint=endpoint,
                                fingerprint=f"sha256:{fingerprint}",
                                details=f"Not valid after: {not_after.isoformat()}",
                            ),
                            remediation="Schedule certificate renewal before expiry.",
                            cwe="CWE-298",
                            related_assets=[asset.dedup_key],
                        )
                    )
            else:
                if days_left < _EXPIRY_CRITICAL_DAYS:
                    findings.append(
                        Finding(
                            title=f"{position.title()} Certificate Expired",
                            description=f"{position.title()} certificate expired {abs(days_left)} day(s) ago.",
                            severity=Severity.MEDIUM,
                            category=Category.CERTIFICATE,
                            confidence=Confidence.MEDIUM,
                            evidence=Evidence(
                                endpoint=endpoint,
                                fingerprint=f"sha256:{fingerprint}",
                                details=f"Not valid after: {not_after.isoformat()}",
                            ),
                            remediation="Replace the expired certificate in the chain.",
                            related_assets=[asset.dedup_key],
                        )
                    )

            # Self-signed leaf only
            if index == 0 and subject == issuer:
                findings.append(
                    Finding(
                        title="Self-Signed Leaf Certificate",
                        description="The leaf certificate is self-signed and will not be trusted by browsers.",
                        severity=Severity.HIGH,
                        category=Category.CERTIFICATE,
                        confidence=Confidence.HIGH,
                        evidence=Evidence(
                            endpoint=endpoint,
                            fingerprint=f"sha256:{fingerprint}",
                            details="Subject == Issuer",
                        ),
                        remediation=(
                            "Replace the self-signed certificate with one issued by a "
                            "trusted public Certificate Authority."
                        ),
                        cwe="CWE-295",
                        related_assets=[asset.dedup_key],
                    )
                )

            # Weak key size (leaf only)
            if index == 0:
                try:
                    pub_key = cert.public_key()
                    key_size = getattr(pub_key, "key_size", None)
                    if key_size is not None and key_size < 2048:
                        findings.append(
                            Finding(
                                title="Weak Leaf Certificate Key Size",
                                description=(
                                    f"Leaf certificate uses a {key_size}-bit key, below the "
                                    "recommended minimum of 2048 bits."
                                ),
                                severity=Severity.HIGH,
                                category=Category.CERTIFICATE,
                                confidence=Confidence.HIGH,
                                evidence=Evidence(
                                    endpoint=endpoint,
                                    fingerprint=f"sha256:{fingerprint}",
                                    details=f"Key size: {key_size} bits",
                                ),
                                remediation=(
                                    "Reissue the certificate with at least a 2048-bit RSA key or P-256 EC key."
                                ),
                                cwe="CWE-326",
                                related_assets=[asset.dedup_key],
                            )
                        )
                except Exception as exc:
                    logger.debug("Could not inspect public key: %s", exc)

        # Hostname mismatch (leaf deployment)
        try:
            leaf_cert_deployment = deployments[0]
            if not leaf_cert_deployment.leaf_certificate_subject_matches_hostname:
                leaf_asset = assets[0] if assets else None
                related = [leaf_asset.dedup_key] if leaf_asset else []
                findings.append(
                    Finding(
                        title="Certificate Hostname Mismatch",
                        description="The certificate subject/SAN does not match the target hostname.",
                        severity=Severity.HIGH,
                        category=Category.CERTIFICATE,
                        confidence=Confidence.HIGH,
                        evidence=Evidence(endpoint=endpoint, details=f"Target: {target}"),
                        remediation=(
                            "Obtain a certificate that includes the target hostname in the "
                            "Subject Alternative Names (SAN) extension."
                        ),
                        cwe="CWE-295",
                        related_assets=related,
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
                        confidence=Confidence.MEDIUM,
                        evidence=Evidence(endpoint=endpoint, details="No OCSP response stapled"),
                        remediation="Enable OCSP stapling on the web server.",
                    )
                )
        except Exception:
            pass

        return ScanResult(findings=findings, assets=assets)
