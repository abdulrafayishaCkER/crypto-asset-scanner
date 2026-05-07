"""DNS security analyser (SPF, DMARC, DKIM, CAA, zone transfer, DNSSEC)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import List

from crypto_recon.config import DKIM_SELECTORS
from crypto_recon.models.asset import Confidence
from crypto_recon.models.evidence import Evidence
from crypto_recon.models.finding import Category, Finding, Severity
from crypto_recon.models.scan_result import ScanResults
from crypto_recon.utils.logger import get_logger

logger = get_logger(__name__)


class DNSAnalyzer:
    """Perform DNS-based security checks against a domain."""

    def analyze(self, domain: str) -> ScanResults:
        """Analyse DNS configuration of *domain*.

        Args:
            domain: Domain name to inspect.

        Returns:
            :class:`ScanResults` containing DNS findings.
        """
        try:
            import dns.exception
            import dns.query
            import dns.resolver
            import dns.zone
        except ImportError:
            logger.warning("dnspython not installed; skipping DNS analysis.")
            return ScanResults()

        results = ScanResults()
        results.add_findings(self._check_spf(domain, dns))
        results.add_findings(self._check_dmarc(domain, dns))
        results.add_findings(self._check_dkim(domain, dns))
        results.add_findings(self._check_caa(domain, dns))
        results.add_findings(self._check_mx(domain, dns))
        results.add_findings(self._check_zone_transfer(domain, dns))
        results.add_findings(self._check_dnssec(domain, dns))
        return results

    # ------------------------------------------------------------------ helpers

    def _resolve(self, dns_module, qname: str, rdtype: str) -> DNSLookupResult:
        """Attempt DNS resolution; return records plus error classification."""
        resolver = dns_module.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 5.0
        try:
            return DNSLookupResult(list(resolver.resolve(qname, rdtype)))
        except dns_module.resolver.NXDOMAIN:
            return DNSLookupResult([], DNSError.NXDOMAIN)
        except dns_module.resolver.NoAnswer:
            return DNSLookupResult([], DNSError.NOANSWER)
        except dns_module.resolver.Timeout:
            return DNSLookupResult([], DNSError.TIMEOUT)
        except dns_module.resolver.NoNameservers:
            return DNSLookupResult([], DNSError.SERVFAIL)
        except Exception:
            return DNSLookupResult([], DNSError.UNKNOWN)

    @staticmethod
    def _dns_error_finding(label: str, qname: str, error: DNSError) -> Finding:
        return Finding(
            title=f"DNS Lookup Failed ({label})",
            description=f"DNS lookup for {label} records failed with {error.value}.",
            severity=Severity.LOW,
            category=Category.DNS,
            confidence=Confidence.LOW,
            evidence=Evidence(details={"query": qname, "error": error.value}),
            remediation="Verify authoritative DNS servers and retry the scan.",
        )

    def _check_spf(self, domain: str, dns) -> List[Finding]:
        findings: List[Finding] = []
        result = self._resolve(dns, domain, "TXT")
        if result.error and result.error != DNSError.NOANSWER:
            return [self._dns_error_finding("SPF", domain, result.error)]

        spf_records = [r.to_text() for r in result.records if "v=spf1" in r.to_text()]

        if not spf_records:
            findings.append(
                Finding(
                    title="Missing SPF Record",
                    description="No SPF TXT record found. Attackers can spoof email from this domain.",
                    severity=Severity.MEDIUM,
                    category=Category.DNS,
                    confidence=Confidence.MEDIUM,
                    evidence=Evidence(details={"domain": domain, "lookup_error": result.error.value if result.error else None}),
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
                    evidence=Evidence(details={"spf": spf}),
                    remediation="Change +all to -all or ~all to restrict mail senders.",
                    cwe="CWE-345",
                )
            )
        return findings

    def _check_dmarc(self, domain: str, dns) -> List[Finding]:
        findings: List[Finding] = []
        dmarc_domain = f"_dmarc.{domain}"
        result = self._resolve(dns, dmarc_domain, "TXT")
        if result.error and result.error != DNSError.NOANSWER:
            return [self._dns_error_finding("DMARC", dmarc_domain, result.error)]

        dmarc_records = [r.to_text() for r in result.records if "v=DMARC1" in r.to_text()]

        if not dmarc_records:
            findings.append(
                Finding(
                    title="Missing DMARC Record",
                    description="No DMARC policy found. Email spoofing is not prevented at the policy level.",
                    severity=Severity.MEDIUM,
                    category=Category.DNS,
                    confidence=Confidence.MEDIUM,
                    evidence=Evidence(details={"domain": dmarc_domain, "lookup_error": result.error.value if result.error else None}),
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
                    evidence=Evidence(details={"dmarc": dmarc}),
                    remediation="Upgrade the DMARC policy to p=quarantine or p=reject.",
                    cwe="CWE-345",
                )
            )
        return findings

    def _check_dkim(self, domain: str, dns) -> List[Finding]:
        findings: List[Finding] = []
        found_any = False
        errors: list[str] = []

        for selector in DKIM_SELECTORS:
            dkim_domain = f"{selector}._domainkey.{domain}"
            result = self._resolve(dns, dkim_domain, "TXT")
            if result.error and result.error != DNSError.NOANSWER:
                errors.append(f"{selector}:{result.error.value}")
                continue
            if result.records:
                found_any = True
                break

        if not found_any:
            findings.append(
                Finding(
                    title="DKIM Records Not Found for Common Selectors",
                    description=(
                        "No DKIM TXT records were found for common selectors. "
                        "This does not guarantee DKIM is absent, but indicates it was not "
                        "located with the default selector guesses."
                    ),
                    severity=Severity.LOW,
                    category=Category.DNS,
                    confidence=Confidence.LOW,
                    evidence=Evidence(details={"selectors": DKIM_SELECTORS, "lookup_errors": errors}),
                    remediation=(
                        "Configure DKIM signing for your mail platform and publish "
                        "the public key as a TXT record at <selector>._domainkey.<domain>."
                    ),
                )
            )
        return findings

    def _check_caa(self, domain: str, dns) -> List[Finding]:
        result = self._resolve(dns, domain, "CAA")
        if result.error and result.error != DNSError.NOANSWER:
            return [self._dns_error_finding("CAA", domain, result.error)]
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
                    evidence=Evidence(details={"domain": domain, "lookup_error": result.error.value if result.error else None}),
                    remediation=(
                        "Publish a CAA record listing only the CA(s) authorised to issue "
                        "certificates for this domain."
                    ),
                )
            ]
        return []

    def _check_mx(self, domain: str, dns) -> List[Finding]:
        result = self._resolve(dns, domain, "MX")
        if result.error and result.error != DNSError.NOANSWER:
            return [self._dns_error_finding("MX", domain, result.error)]
        if result.records:
            mx_list = ", ".join(r.exchange.to_text() for r in result.records)
            return [
                Finding(
                    title="MX Records Discovered",
                    description=f"Mail servers found for {domain}.",
                    severity=Severity.INFO,
                    category=Category.DNS,
                    confidence=Confidence.HIGH,
                    evidence=Evidence(details={"mx_records": mx_list}),
                    remediation="Ensure mail servers are properly secured and patched.",
                )
            ]
        return []

    def _check_zone_transfer(self, domain: str, dns) -> List[Finding]:
        findings: List[Finding] = []
        result = self._resolve(dns, domain, "NS")
        if result.error and result.error != DNSError.NOANSWER:
            return [self._dns_error_finding("NS", domain, result.error)]

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
                            evidence=Evidence(details={"nameserver": ns}),
                            remediation=(
                                "Restrict AXFR requests to authorised secondary name servers only."
                            ),
                            cwe="CWE-200",
                        )
                    )
            except Exception:
                pass
        return findings

    def _check_dnssec(self, domain: str, dns) -> List[Finding]:
        result = self._resolve(dns, domain, "DNSKEY")
        if result.error and result.error != DNSError.NOANSWER:
            return [self._dns_error_finding("DNSSEC", domain, result.error)]
        if not result.records:
            return [
                Finding(
                    title="DNSSEC Not Configured",
                    description="No DNSKEY records found. DNS responses are not cryptographically validated.",
                    severity=Severity.INFO,
                    category=Category.DNS,
                    confidence=Confidence.MEDIUM,
                    evidence=Evidence(details={"domain": domain, "lookup_error": result.error.value if result.error else None}),
                    remediation="Enable DNSSEC signing at your DNS registrar and authoritative nameserver.",
                )
            ]
        return []


class DNSError(Enum):
    """DNS error types for classification."""

    NXDOMAIN = "nxdomain"
    TIMEOUT = "timeout"
    SERVFAIL = "servfail"
    NOANSWER = "noanswer"
    UNKNOWN = "unknown"


@dataclass
class DNSLookupResult:
    """DNS lookup results with error classification."""

    records: list
    error: DNSError | None = None
