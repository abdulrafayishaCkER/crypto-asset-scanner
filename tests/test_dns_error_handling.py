from crypto_recon.scanner.dns_analyzer import DNSAnalyzer, DNSQueryResult, DNSError


def test_dns_error_handling_reports_error():
    analyzer = DNSAnalyzer()

    def fake_resolve(qname: str, rdtype: str) -> DNSQueryResult:
        return DNSQueryResult(records=[], error=DNSError.NXDOMAIN)

    analyzer._resolve = fake_resolve  # type: ignore[method-assign]
    findings = analyzer._check_spf("example.com")

    assert findings
    assert "NXDOMAIN" in findings[0].evidence.summary()
