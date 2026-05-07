"""DNS security analyser (SPF, DMARC, DKIM, CAA, zone transfer, DNSSEC)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import List

from crypto_recon.config import DKIM_SELECTORS
from crypto_recon.models.asset import Confidence
from crypto_recon.models.evidence import Evidence
from crypto_recon.models.finding import Finding, Severity, Category
from crypto_recon.models.scan_result import ScanResult
from crypto_recon.utils.logger import get_logger

logger = get_logger(__name__)


class DNSError(Enum):
    NXDOMAIN = "NXDOMAIN"
    TIMEOUT = "TIMEOUT"
    SERVFAIL = "SERVFAIL"
    NO_ANSWER = "NO_ANSWER"
    UNKNOWN = "UNKNOWN"


@dataclass
class DNSQueryResult:
    records: list
    error: DNSError | None = None


class DNSAnalyzer:
    """Perform DNS-based security checks against a domain."""

    def analyze(self, domain: str) -> ScanResult:
        """Analyse DNS configuration of *domain*.

        Args:
            domain: Domain name to inspect.

        Returns:
            :class:`ScanResult` containing DNS-related findings.
        """
        try:
            import dns.resolver
            import dns.query
            import dns.zone
            import dns.exception
        except ImportError:
            logger.warning("dnspython not installed; skipping DNS analysis.")
            return ScanResult()

        self._dns = dns
        findings: List[Finding] = []
        findings.extend(self._check_spf(domain))
        findings.extend(self._check_dmarc(domain))
        findings.extend(self._check_dkim(domain))
        findings.extend(self._check_caa(domain))
        findings.extend(self._check_mx(domain))
        findings.extend(self._check_zone_transfer(domain))
        findings.extend(self._check_dnssec(domain))
        return ScanResult(findings=findings)

    # ------------------------------------------------------------------ helpers

    def _resolve(self, qname: str, rdtype: str) -> DNSQueryResult:
        """Attempt DNS resolution; return records or error classification."""
        dns = self._dns
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5
        resolver.timeout = 2
        try:
            return DNSQueryResult(records=list(resolver.resolve(qname, rdtype)))
        except dns.resolver.NXDOMAIN:
            return DNSQueryResult(records=[], error=DNSError.NXDOMAIN)
        except dns.resolver.NoAnswer:
            return DNSQueryResult(records=[], error=DNSError.NO_ANSWER)
        except dns.resolver.Timeout:
            return DNSQueryResult(records=[], error=DNSError.TIMEOUT)
        except dns.resolver.NoNameservers:
            return DNSQueryResult(records=[], error=DNSError.SERVFAIL)
        except dns.exception.DNSException:
            return DNSQueryResult(records=[], error=DNSError.UNKNOWN)

    def _error_finding(self, title: str, domain: str, error: DNSError, rdtype: str) -> Finding:
        return Finding(
            title=title,
            description=(
                f"DNS lookup for {rdtype} records failed with {error.value}. "
                "This may indicate a DNS outage or a misconfigured zone."
            ),
            severity=Severity.LOW,
            category=Category.DNS,
            confidence=Confidence.LOW,
            evidence=Evidence(endpoint=domain, details=f"error={error.value}"),
            remediation="Validate authoritative DNS configuration and retry the scan.",
        )

    def _check_spf(self, domain: str) -> List[Finding]:
        findings: List[Finding] = []
        result = self._resolve(domain, "TXT")
        if result.error:
            return [self._error_finding("SPF Lookup Failed", domain, result.error, "TXT")]

        spf_records = [r.to_text() for r in result.records if "v=spf1" in r.to_text()]

        if not spf_records:
            findings.append(
                Finding(
                    title="Missing SPF Record",
                    description="No SPF TXT record found. Attackers can spoof email from this domain.",
                    severity=Severity.MEDIUM,
                    category=Category.DNS,
                    confidence=Confidence.MEDIUM,
                    evidence=Evidence(endpoint=domain, details="TXT lookup returned no SPF record"),
                    remediation=(
                        "Publish an SPF record listing authorised mail senders, "
                        "ending with -all or ~all."
                    ),
                    cwe="CWE-345",
                )
            )
        else:
            for spf in spf_records:
                if "+all" in spf:
                    findings.append(
                        Finding(
                            title="SPF Record Uses +all (Permissive)",
                            description=(
                                "The SPF record ends with +all, meaning ANY server is authorised "
                                "to send mail on behalf of this domain."
                            ),
                            severity=Severity.HIGH,
                            category=Category.DNS,
                            confidence=Confidence.HIGH,
                            evidence=Evidence(endpoint=domain, details=f"SPF: {spf}"),
                            remediation="Change +all to -all or ~all to restrict mail senders.",
                            cwe="CWE-345",
                        )
                    )
        return findings

    def _check_dmarc(self, domain: str) -> List[Finding]:
        findings: List[Finding] = []
        dmarc_domain = f"_dmarc.{domain}"
        result = self._resolve(dmarc_domain, "TXT")
        if result.error:
            return [
                self._error_finding("DMARC Lookup Failed", dmarc_domain, result.error, "TXT")
            ]

        dmarc_records = [r.to_text() for r in result.records if "v=DMARC1" in r.to_text()]

        if not dmarc_records:
            findings.append(
                Finding(
                    title="Missing DMARC Record",
                    description="No DMARC policy found. Email spoofing is not prevented at the policy level.",
                    severity=Severity.MEDIUM,
                    category=Category.DNS,
                    confidence=Confidence.MEDIUM,
                    evidence=Evidence(endpoint=domain, details=f"Checked: {dmarc_domain}"),
                    remediation=(
                        "Publish a DMARC record at _dmarc.{domain} with at least p=quarantine."
                    ),
                    cwe="CWE-345",
                )
            )
        else:
            for dmarc in dmarc_records:
                if "p=none" in dmarc:
                    findings.append(
                        Finding(
                            title="DMARC Policy Set to 'none' (Monitor Only)",
                            description=(
                                "The DMARC policy is p=none, meaning spoofed emails are not "
                                "rejected or quarantined."
                            ),
                            severity=Severity.LOW,
                            category=Category.DNS,
                            confidence=Confidence.MEDIUM,
                            evidence=Evidence(endpoint=domain, details=f"DMARC: {dmarc}"),
                            remediation="Upgrade the DMARC policy to p=quarantine or p=reject.",
                            cwe="CWE-345",
                        )
                    )
        return findings

    def _check_dkim(self, domain: str) -> List[Finding]:
        findings: List[Finding] = []
        attempted: dict[str, str] = {}
        found_any = False

        for selector in DKIM_SELECTORS:
            dkim_domain = f"{selector}._domainkey.{domain}"
            result = self._resolve(dkim_domain, "TXT")
            if result.records:
                found_any = True
                break
            attempted[selector] = result.error.value if result.error else "NO_RECORD"

        if not found_any:
            findings.append(
                Finding(
                    title="DKIM Records Not Found for Common Selectors",
                    description=(
                        "No DKIM TXT records were found for common selectors. "
                        "This does not confirm DKIM is absent; selectors may be custom."
                    ),
                    severity=Severity.LOW,
                    category=Category.DNS,
                    confidence=Confidence.LOW,
                    evidence=Evidence(
                        endpoint=domain,
                        details=f"Checked selectors: {', '.join(list(attempted.keys())[:5])}…",
                        metadata={"selector_results": attempted},
                    ),
                    remediation=(
                        "Verify DKIM configuration with your mail provider and publish "
                        "the public key as a TXT record at <selector>._domainkey.<domain>."
                    ),
                )
            )
        return findings

    def _check_caa(self, domain: str) -> List[Finding]:
        result = self._resolve(domain, "CAA")
        if result.error:
            return [self._error_finding("CAA Lookup Failed", domain, result.error, "CAA")]
        if not result.records:
            return [
                Finding(
                    title="Missing CAA Record",
                    description=(
                        "No CAA record found. Any Certificate Authority can issue certificates "
                        "for this domain."
                    ),
                    severity=Severity.LOW,
                    category=Category.DNS,
                    confidence=Confidence.MEDIUM,
                    evidence=Evidence(endpoint=domain),
                    remediation=(
                        "Publish a CAA record listing only the CA(s) authorised to issue "
                        "certificates for this domain."
                    ),
                )
            ]
        return []

    def _check_mx(self, domain: str) -> List[Finding]:
        result = self._resolve(domain, "MX")
        if result.error:
            return [self._error_finding("MX Lookup Failed", domain, result.error, "MX")]
        if result.records:
            mx_list = ", ".join(r.exchange.to_text() for r in result.records)
            return [
                Finding(
                    title="MX Records Discovered",
                    description=f"Mail servers found for {domain}.",
                    severity=Severity.INFO,
                    category=Category.DNS,
                    confidence=Confidence.MEDIUM,
                    evidence=Evidence(endpoint=domain, details=f"MX records: {mx_list}"),
                    remediation="Ensure mail servers are properly secured and patched.",
                )
            ]
        return []

    def _check_zone_transfer(self, domain: str) -> List[Finding]:
        findings: List[Finding] = []
        result = self._resolve(domain, "NS")
        if result.error:
            return [self._error_finding("NS Lookup Failed", domain, result.error, "NS")]
        dns = self._dns
        for ns_record in result.records:
            ns = ns_record.target.to_text().rstrip(".")
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, lifetime=5))
                if zone:
                    findings.append(
                        Finding(
                            title="DNS Zone Transfer Allowed (AXFR)",
                            description=(
                                f"The nameserver {ns!r} allowed an AXFR zone transfer. "
                                "This exposes all DNS records to any requester."
                            ),
                            severity=Severity.CRITICAL,
                            category=Category.DNS,
                            confidence=Confidence.HIGH,
                            evidence=Evidence(endpoint=domain, details=f"Zone transfer succeeded from: {ns}"),
                            remediation=(
                                "Restrict AXFR requests to authorised secondary name servers only."
                            ),
                            cwe="CWE-200",
                        )
                    )
            except Exception:
                pass
        return findings

    def _check_dnssec(self, domain: str) -> List[Finding]:
        result = self._resolve(domain, "DNSKEY")
        if result.error:
            return [self._error_finding("DNSSEC Lookup Failed", domain, result.error, "DNSKEY")]
        if not result.records:
            return [
                Finding(
                    title="DNSSEC Not Configured",
                    description="No DNSKEY records found. DNS responses are not cryptographically validated.",
                    severity=Severity.INFO,
                    category=Category.DNS,
                    confidence=Confidence.MEDIUM,
                    evidence=Evidence(endpoint=domain),
                    remediation="Enable DNSSEC signing at your DNS registrar and authoritative nameserver.",
                )
            ]
        return []
