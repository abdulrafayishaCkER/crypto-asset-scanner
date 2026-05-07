from crypto_recon.utils.validators import is_subdomain_of


def test_strict_suffix_validation():
    assert is_subdomain_of("api.example.com", "example.com")
    assert is_subdomain_of("example.com", "example.com")
    assert not is_subdomain_of("example.com.evil.com", "example.com")
