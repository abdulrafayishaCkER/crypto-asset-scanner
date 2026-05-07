from crypto_recon.utils.redaction import fingerprint_secret, redact_secret


def test_redact_secret() -> None:
    secret = "supersecretvalue1234"
    redacted = redact_secret(secret)
    assert secret not in redacted
    assert redacted.startswith(secret[:4])
    assert redacted.endswith(secret[-4:])
    assert "***" in redacted
    assert len(fingerprint_secret(secret)) == 64
