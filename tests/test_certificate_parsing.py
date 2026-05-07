from datetime import datetime, timezone, timedelta

from crypto_recon.scanner.cert_analyzer import _build_certificate_asset


class _FakeName:
    def __init__(self, value: str) -> None:
        self._value = value

    def rfc4514_string(self) -> str:
        return self._value


class _FakeSigAlg:
    name = "sha256"


class _FakePublicKey:
    key_size = 2048


class _FakeExtensions:
    def get_extension_for_class(self, _cls):
        raise Exception("No SANs")


class _FakeCert:
    subject = _FakeName("CN=example.com")
    issuer = _FakeName("CN=Example CA")
    not_valid_before_utc = datetime.now(timezone.utc) - timedelta(days=1)
    not_valid_after_utc = datetime.now(timezone.utc) + timedelta(days=30)
    signature_hash_algorithm = _FakeSigAlg()
    extensions = _FakeExtensions()

    def public_key(self):
        return _FakePublicKey()

    def public_bytes(self, _encoding):
        return b"fake-cert-bytes"


def test_certificate_parsing() -> None:
    asset, evidence, metadata, not_after = _build_certificate_asset(_FakeCert(), 0, "example.com", 443)
    assert metadata["subject"] == "CN=example.com"
    assert metadata["issuer"] == "CN=Example CA"
    assert asset.fingerprint
    assert evidence.certificate_fingerprint == asset.fingerprint
    assert not_after is not None
