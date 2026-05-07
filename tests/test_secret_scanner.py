from crypto_recon.scanner.secret_scanner import SecretScanner


def test_secret_redaction_and_hash():
    secret = "AKIA1234567890ABCDEF"
    text = f"export AWS_KEY={secret}\n"
    result = SecretScanner().scan_text(text, source_path="/tmp/example.env")

    assert len(result.assets) == 1
    asset = result.assets[0]
    assert asset.fingerprint.startswith("sha256:")
    assert secret not in asset.evidence.summary()
    assert "AKIA" in asset.evidence.snippet


def test_multiple_secret_matches():
    secret1 = "AKIA1234567890ABCDEF"
    secret2 = "AKIAAAAAAAAAAAAAAAA"
    text = f"{secret1}\n{secret2}\n"
    result = SecretScanner().scan_text(text)

    assert len(result.assets) == 2
    assert len(result.findings) == 2
