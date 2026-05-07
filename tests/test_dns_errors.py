import pytest

from crypto_recon.scanner.dns_analyzer import DNSAnalyzer, DNSError


class _DummyResolver:
    def __init__(self, exc: Exception) -> None:
        self._exc = exc
        self.timeout = 0
        self.lifetime = 0

    def resolve(self, _qname, _rdtype):
        raise self._exc


class _DummyResolverModule:
    class NXDOMAIN(Exception):
        pass

    class NoAnswer(Exception):
        pass

    class Timeout(Exception):
        pass

    class NoNameservers(Exception):
        pass

    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    def Resolver(self):
        return _DummyResolver(self._exc)


class _DummyDNSModule:
    def __init__(self, exc: Exception) -> None:
        self.resolver = _DummyResolverModule(exc)


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (_DummyResolverModule.NXDOMAIN(), DNSError.NXDOMAIN),
        (_DummyResolverModule.NoAnswer(), DNSError.NOANSWER),
        (_DummyResolverModule.Timeout(), DNSError.TIMEOUT),
        (_DummyResolverModule.NoNameservers(), DNSError.SERVFAIL),
    ],
)
def test_dns_error_classification(exc: Exception, expected: DNSError) -> None:
    analyzer = DNSAnalyzer()
    dummy_dns = _DummyDNSModule(exc)
    result = analyzer._resolve(dummy_dns, "example.com", "TXT")
    assert result.error == expected
