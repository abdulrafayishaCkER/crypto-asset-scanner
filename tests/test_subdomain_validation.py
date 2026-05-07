from crypto_recon.scanner.subdomain_enum import _is_subdomain, _normalize_subdomain


def test_subdomain_suffix_validation() -> None:
    domain = "example.com"
    assert _is_subdomain("sub.example.com", domain)
    assert _is_subdomain("example.com", domain)
    assert not _is_subdomain("badexample.com", domain)
    assert _normalize_subdomain("*.Example.COM.") == "example.com"
