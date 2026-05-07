from crypto_recon.scanner.secret_scanner import SecretScanner


def test_multiple_secret_matches() -> None:
    scanner = SecretScanner()
    text = "AKIA1234567890ABCDE1 some text AKIA1234567890ABCDE2"
    results = scanner.scan_text(text, source_url="secrets.txt")
    assert len(results.findings) == 2
    assert len(results.assets) == 2
    for finding in results.findings:
        redacted = finding.evidence.details.get("redacted", "")
        assert redacted
        assert "***" in redacted
