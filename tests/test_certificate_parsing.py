from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from crypto_recon.scanner.cert_analyzer import CertAnalyzer


def _build_certificate() -> x509.Certificate:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    return cert


def test_certificate_parsing_extracts_fields():
    cert = _build_certificate()
    details = CertAnalyzer.extract_certificate_details(cert)

    assert "example.com" in details["subject"]
    assert details["signature_algorithm"]
    assert "example.com" in details["sans"]
