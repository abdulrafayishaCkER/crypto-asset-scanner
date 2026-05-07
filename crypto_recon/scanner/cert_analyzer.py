"""Certificate chain analysis."""

from __future__ import annotations

import datetime
import hashlib

from crypto_recon.models.asset import Asset, AssetType, Confidence
from crypto_recon.models.evidence import Evidence
from crypto_recon.models.finding import Category, Finding, Severity
from crypto_recon.models.scan_result import ScanResults
from crypto_recon.utils.logger import get_logger

logger = get_logger(__name__)

_EXPIRY_CRITICAL_DAYS = 0
_EXPIRY_HIGH_DAYS = 30


class CertAnalyzer:
    """Analyse the TLS certificate chain returned by sslyze."""

    def analyze(self, target: str, port: int = 443) -> ScanResults:
        """Fetch and analyse the certificate chain for *target*:*port*.

        Args:
            target: Hostname.
            port: TCP port (default 443).

        Returns:
            :class:`ScanResults` containing certificate findings and assets.
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
            logger.warning("sslyze not installed; skipping certificate analysis.")
            return results

        try:
            scanner = Scanner()
            req = ServerScanRequest(
                server_location=ServerNetworkLocation(hostname=target, port=port)
            )
            scanner.queue_scans([req])
            results = list(scanner.get_results())
        except Exception as exc:
            logger.error("Certificate analysis failed for %s:%d – %s", target, port, exc)
            return results

        if not results:
            return results

        server_scan = results[0]
        if server_scan.scan_status.name == "ERROR_NO_CONNECTIVITY":
            return results

        scan_res = server_scan.scan_result
        cert_attempt = getattr(scan_res, "certificate_info", None)
        if not cert_attempt or cert_attempt.status != ScanCommandAttemptStatusEnum.COMPLETED:
            return results

        deployments = cert_attempt.result.certificate_deployments
        if not deployments:
            return results

        chain = deployments[0].received_certificate_chain
        now = datetime.datetime.now(datetime.timezone.utc)

        for idx, cert in enumerate(chain):
            asset, evidence, metadata, not_after = _build_certificate_asset(cert, idx, target, port)
            subject = metadata["subject"]
            issuer = metadata["issuer"]
            fingerprint = metadata["fingerprint"]
            signature_alg = metadata["signature_algorithm"]
            results.assets.append(asset)

            if signature_alg and signature_alg != "unknown":
                results.assets.append(
                    Asset(
                        asset_type=AssetType.CRYPTO_ALGORITHM,
                        name=signature_alg,
                        description="Certificate signature algorithm.",
                        confidence=Confidence.HIGH,
                        evidence=evidence,
                        metadata={"usage": "certificate_signature"},
                    )
                )

            # Expiry
            try:
                if not_after is None:
                    raise AttributeError
                days_left = (not_after - now).days
                if days_left < _EXPIRY_CRITICAL_DAYS:
                    results.findings.append(
                        Finding(
                            title="Certificate Expired",
                            description=f"Certificate for {subject} expired {abs(days_left)} day(s) ago.",
                            severity=Severity.CRITICAL,
                            category=Category.CERTIFICATE,
                            confidence=Confidence.HIGH,
                            evidence=evidence,
                            remediation="Renew the TLS certificate immediately.",
                            cwe="CWE-298",
                        )
                    )
                elif days_left < _EXPIRY_HIGH_DAYS:
                    results.findings.append(
                        Finding(
                            title="Certificate Expiring Soon",
                            description=f"Certificate for {subject} expires in {days_left} day(s).",
                            severity=Severity.HIGH,
                            category=Category.CERTIFICATE,
                            confidence=Confidence.HIGH,
                            evidence=evidence,
                            remediation="Schedule certificate renewal before expiry.",
                            cwe="CWE-298",
                        )
                    )
            except AttributeError:
                logger.debug("Could not read certificate validity dates.")

            # Self-signed
            if subject == issuer:
                results.findings.append(
                    Finding(
                        title="Self-Signed Certificate",
                        description="The certificate is self-signed and will not be trusted by browsers.",
                        severity=Severity.HIGH,
                        category=Category.CERTIFICATE,
                        confidence=Confidence.MEDIUM,
                        evidence=evidence,
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
                    results.findings.append(
                        Finding(
                            title="Weak Certificate Key Size",
                            description=(
                                f"Certificate uses a {key_size}-bit key, which is below the "
                                "recommended minimum of 2048 bits."
                            ),
                            severity=Severity.HIGH,
                            category=Category.CERTIFICATE,
                            confidence=Confidence.HIGH,
                        evidence=Evidence(
                            endpoint=f"{target}:{port}",
                            certificate_fingerprint=fingerprint,
                            details={"key_size": key_size, "chain_position": idx},
                        ),
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
                results.findings.append(
                    Finding(
                        title="Certificate Hostname Mismatch",
                        description="The certificate subject/SAN does not match the target hostname.",
                        severity=Severity.HIGH,
                        category=Category.CERTIFICATE,
                        confidence=Confidence.HIGH,
                        evidence=Evidence(
                            endpoint=f"{target}:{port}",
                            details={"target": target, "chain_position": 0},
                        ),
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
                results.findings.append(
                    Finding(
                        title="OCSP Stapling Not Configured",
                        description="OCSP stapling is not enabled, which can slow TLS handshakes.",
                        severity=Severity.LOW,
                        category=Category.CERTIFICATE,
                        confidence=Confidence.MEDIUM,
                        evidence=Evidence(endpoint=f"{target}:{port}"),
                        remediation="Enable OCSP stapling on the web server.",
                    )
                )
        except Exception:
            pass

        return results


def _certificate_fingerprint(cert) -> str:
    """Return SHA-256 fingerprint for a certificate."""
    try:
        from cryptography.hazmat.primitives import hashes
        return cert.fingerprint(hashes.SHA256()).hex()
    except Exception:
        try:
            from cryptography.hazmat.primitives.serialization import Encoding
            der = cert.public_bytes(Encoding.DER)
            return hashlib.sha256(der).hexdigest()
        except Exception:
            return ""


def _extract_sans(cert) -> list[str]:
    """Extract DNS Subject Alternative Names from a certificate."""
    try:
        from cryptography import x509
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return ext.value.get_values_for_type(x509.DNSName)
    except Exception:
        return []


def _build_certificate_asset(
    cert, chain_position: int, target: str, port: int
) -> tuple[Asset, Evidence, dict, datetime.datetime | None]:
    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()
    fingerprint = _certificate_fingerprint(cert)
    sans = _extract_sans(cert)
    signature_alg = getattr(getattr(cert, "signature_hash_algorithm", None), "name", "unknown")
    not_before = getattr(cert, "not_valid_before_utc", None)
    not_after = getattr(cert, "not_valid_after_utc", None)

    evidence = Evidence(
        endpoint=f"{target}:{port}",
        certificate_fingerprint=fingerprint,
        details={"chain_position": chain_position, "subject": subject, "issuer": issuer},
    )
    metadata = {
        "issuer": issuer,
        "subject": subject,
        "sans": sans,
        "valid_from": not_before.isoformat() if not_before else None,
        "valid_to": not_after.isoformat() if not_after else None,
        "signature_algorithm": signature_alg,
        "chain_position": chain_position,
        "fingerprint": fingerprint,
    }
    asset = Asset(
        asset_type=AssetType.CERTIFICATE,
        name=subject,
        description="TLS certificate observed in server chain.",
        confidence=Confidence.HIGH,
        evidence=evidence,
        fingerprint=fingerprint,
        metadata=metadata,
    )
    return asset, evidence, metadata, not_after
