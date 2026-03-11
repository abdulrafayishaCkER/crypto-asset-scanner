"""DNS security analyser (SPF, DMARC, DKIM, CAA, zone transfer, DNSSEC)."""

from __future__ import annotations

from typing import List

from crypto_recon.config import DKIM_SELECTORS
from crypto_recon.models.finding import Finding, Severity, Category
from crypto_recon.utils.logger import get_logger

logger = get_logger(__name__)


class DNSAnalyzer:
    """Perform DNS-based security checks against a domain."""

    def analyze(self, domain: str) -> List[Finding]:
        """Analyse DNS configuration of *domain*.

        Args:
            domain: Domain name to inspect.

        Returns:
            List of :class:`Finding` objects.
        """
        try:
            import dns.resolver
            import dns.query
            import dns.zone
            import dns.exception
        except ImportError:
            logger.warning("dnspython not installed; skipping DNS analysis.")
            return []

        findings: List[Finding] = []
        findings.extend(self._check_spf(domain, dns))
        findings.extend(self._check_dmarc(domain, dns))
        findings.extend(self._check_dkim(domain, dns))
        findings.extend(self._check_caa(domain, dns))
        findings.extend(self._check_mx(domain, dns))
        findings.extend(self._check_zone_transfer(domain, dns))
        findings.extend(self._check_dnssec(domain, dns))
        return findings

    # ------------------------------------------------------------------ helpers

    def _resolve(self, dns_module, qname: str, rdtype: str) -> list:
        """Attempt DNS resolution; return empty list on failure."""
        try:
            return list(dns_module.resolver.resolve(qname, rdtype))
        except Exception:
            return []

    def _check_spf(self, domain: str, dns) -> List[Finding]:
        findings: List[Finding] = []
        records = self._resolve(dns, domain, "TXT")
        spf_records = [r.to_text() for r in records if "v=spf1" in r.to_text()]

        if not spf_records:
            findings.append(
                Finding(
                    title="Missing SPF Record",
                    description="No SPF TXT record found. Attackers can spoof email from this domain.",
                    severity=Severity.MEDIUM,
                    category=Category.DNS,
                    evidence=f"Domain: {domain}",
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
                            evidence=f"SPF: {spf}",
                            remediation="Change +all to -all or ~all to restrict mail senders.",
                            cwe="CWE-345",
                        )
                    )
        return findings

    def _check_dmarc(self, domain: str, dns) -> List[Finding]:
        findings: List[Finding] = []
        dmarc_domain = f"_dmarc.{domain}"
        records = self._resolve(dns, dmarc_domain, "TXT")
        dmarc_records = [r.to_text() for r in records if "v=DMARC1" in r.to_text()]

        if not dmarc_records:
            findings.append(
                Finding(
                    title="Missing DMARC Record",
                    description="No DMARC policy found. Email spoofing is not prevented at the policy level.",
                    severity=Severity.MEDIUM,
                    category=Category.DNS,
                    evidence=f"Checked: {dmarc_domain}",
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
                            evidence=f"DMARC: {dmarc}",
                            remediation="Upgrade the DMARC policy to p=quarantine or p=reject.",
                            cwe="CWE-345",
                        )
                    )
        return findings

    def _check_dkim(self, domain: str, dns) -> List[Finding]:
        findings: List[Finding] = []
        found_any = False

        for selector in DKIM_SELECTORS:
            dkim_domain = f"{selector}._domainkey.{domain}"
            records = self._resolve(dns, dkim_domain, "TXT")
            if records:
                found_any = True
                break

        if not found_any:
            findings.append(
                Finding(
                    title="No DKIM Record Found",
                    description=(
                        "No DKIM TXT records were found for common selectors. "
                        "Outbound mail may not be cryptographically signed."
                    ),
                    severity=Severity.LOW,
                    category=Category.DNS,
                    evidence=f"Checked selectors: {', '.join(DKIM_SELECTORS[:5])}…",
                    remediation=(
                        "Configure DKIM signing for your mail platform and publish "
                        "the public key as a TXT record at <selector>._domainkey.<domain>."
                    ),
                )
            )
        return findings

    def _check_caa(self, domain: str, dns) -> List[Finding]:
        records = self._resolve(dns, domain, "CAA")
        if not records:
            return [
                Finding(
                    title="Missing CAA Record",
                    description=(
                        "No CAA record found. Any Certificate Authority can issue certificates "
                        "for this domain."
                    ),
                    severity=Severity.LOW,
                    category=Category.DNS,
                    evidence=f"Domain: {domain}",
                    remediation=(
                        "Publish a CAA record listing only the CA(s) authorised to issue "
                        "certificates for this domain."
                    ),
                )
            ]
        return []

    def _check_mx(self, domain: str, dns) -> List[Finding]:
        records = self._resolve(dns, domain, "MX")
        if records:
            mx_list = ", ".join(r.exchange.to_text() for r in records)
            return [
                Finding(
                    title="MX Records Discovered",
                    description=f"Mail servers found for {domain}.",
                    severity=Severity.INFO,
                    category=Category.DNS,
                    evidence=f"MX records: {mx_list}",
                    remediation="Ensure mail servers are properly secured and patched.",
                )
            ]
        return []

    def _check_zone_transfer(self, domain: str, dns) -> List[Finding]:
        findings: List[Finding] = []
        ns_records = self._resolve(dns, domain, "NS")
        for ns_record in ns_records:
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
                            evidence=f"Zone transfer succeeded from: {ns}",
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
        records = self._resolve(dns, domain, "DNSKEY")
        if not records:
            return [
                Finding(
                    title="DNSSEC Not Configured",
                    description="No DNSKEY records found. DNS responses are not cryptographically validated.",
                    severity=Severity.INFO,
                    category=Category.DNS,
                    evidence=f"Domain: {domain}",
                    remediation="Enable DNSSEC signing at your DNS registrar and authoritative nameserver.",
                )
            ]
        return []
