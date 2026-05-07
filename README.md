# CryptoRecon

```
   ______                 __
  / ____/___  ____  _____/ /_____  ____ ___  ___  ____ ___
 / /   / __ \/ __ \/ ___/ __/ __ \/ __ `__ \/ _ \/ __ `__ \
/ /___/ /_/ / / / (__  ) /_/ /_/ / / / / / /  __/ / / / / /
\____/\____/_/ /_/____/\__/\____/_/ /_/ /_/\___/_/ /_/ /_/

          CryptoRecon v2.1 – Cryptographic Asset & CBOM Discovery
```

![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)

**CryptoRecon** is a production-ready cryptographic asset inventory and CBOM discovery tool. It performs security reconnaissance against web targets and local filesystems, building a structured inventory of cryptographic assets (certificates, TLS protocols/ciphers, secrets, dependencies, endpoints) alongside security findings.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
  - [CLI Reference](#cli-reference)
  - [Web Scan Examples](#web-scan-examples)
  - [Local Scan Examples](#local-scan-examples)
  - [Interactive Mode](#interactive-mode)
- [Configuration](#configuration)
- [Secret Patterns Detected](#secret-patterns-detected)
- [Security Headers Checked](#security-headers-checked)
- [Exposed Paths Checked](#exposed-paths-checked)
- [Output Formats](#output-formats)
- [Legal Disclaimer](#legal-disclaimer)
- [Contributing](#contributing)
- [License](#license)

---

## Features

### CBOM & Asset Inventory
- Normalised cryptographic asset model (certificates, TLS protocols, cipher suites, algorithms)
- Redacted secret references with hash fingerprints (no raw secrets stored)
- Dependency/library discovery from manifests (`requirements.txt`, `package.json`)
- Endpoint/service inventory with confidence levels
- CycloneDX-style CBOM JSON export

### TLS & Certificate Analysis
- Enumerate SSL/TLS protocol versions (SSLv2 → TLS 1.3)
- Detect deprecated protocols (SSLv2, SSLv3, TLS 1.0/1.1)
- Classify cipher suites (strong / acceptable / weak / insecure)
- Check for Heartbleed (CVE-2014-0160)
- Certificate expiry (expired = CRITICAL, ≤ 30 days = HIGH)
- Self-signed certificates
- Weak key sizes (< 2048-bit RSA)
- Certificate hostname mismatch
- OCSP stapling status

### HTTP Security Headers
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP) — including `unsafe-inline`/`unsafe-eval` detection
- X-Content-Type-Options
- X-Frame-Options / CSP `frame-ancestors`
- Referrer-Policy
- Permissions-Policy
- Cross-Origin-Resource-Policy / Cross-Origin-Opener-Policy
- Cache-Control misconfiguration
- Server / X-Powered-By information disclosure

### Secret Detection (40+ Patterns)
- Redacts secret values and stores only fingerprints for safety
- Cloud provider API keys (AWS, GCP, Azure, DigitalOcean)
- Payment processor keys (Stripe live/test)
- Source control tokens (GitHub, GitLab)
- Communication platform tokens (Slack, Discord, Twilio, SendGrid, Mailgun)
- Private key material (RSA, EC, OpenSSH, PGP)
- Database connection strings (MongoDB, PostgreSQL, MySQL, Redis)
- JWT tokens, Basic Auth in URLs
- Firebase, Heroku, npm, PyPI tokens
- Generic password/secret patterns

### Web Reconnaissance
- Concurrent probing of 70+ exposed paths (`.env`, `.git/config`, SSH keys, backups, …)
- Automatic secret scanning of accessible responses
- Homepage JavaScript secret detection
- API endpoint discovery (35+ common paths)
- Request budget, rate limiting, and soft-404/login detection to reduce false positives

### DNS Security
- SPF record presence and `+all` weakness
- DMARC policy (`p=none` detection)
- DKIM common selector probing
- CAA record check
- DNS zone transfer (AXFR) attempt — CRITICAL if successful
- DNSSEC validation

### Subdomain Enumeration
- Certificate Transparency log queries (crt.sh)
- Automatic flagging of dev/staging/test subdomains

### GitHub Leak Detection
- Public code search via GitHub API
- Domain-specific leak discovery

### Local Filesystem Scanning
- Recursive directory walking
- Matches all 40+ secret patterns in source code, config files, and scripts
- Skips binary, vendor, and generated directories with configurable size limits

### Reporting
- Rich colour-coded terminal output
- JSON report export
- Self-contained HTML report with collapsible findings
- CycloneDX-style CBOM JSON export

---

## What CBOM Discovery Means
CBOM discovery is the process of building a structured inventory of cryptographic assets (certificates,
protocols, cipher suites, secret references, and crypto-bearing dependencies) so you can track where
cryptography lives, assess exposure, and feed downstream compliance or risk tooling. CryptoRecon
captures assets separately from security findings to keep inventory and risk distinct.

## Architecture

```
crypto_recon/
├── __init__.py          # Version / package metadata
├── __main__.py          # python -m crypto_recon entry point
├── cli.py               # CLI parser + scan orchestration
├── config.py            # All constants and regex patterns
├── scanner/
 │   ├── tls_scanner.py       # TLS protocol & cipher enumeration (sslyze)
 │   ├── cert_analyzer.py     # Certificate chain analysis
 │   ├── header_analyzer.py
 │   ├── secret_scanner.py
 │   ├── dependency_scanner.py
 │   ├── web_crawler.py       # Concurrent exposed-path probing
 │   ├── subdomain_enum.py
 │   ├── dns_analyzer.py
 │   └── github_scanner.py
├── models/
 │   ├── asset.py         # CBOM asset model
 │   ├── evidence.py      # Safe evidence structure
 │   ├── finding.py       # Finding dataclass + Severity/Category enums
 │   ├── report.py        # Report dataclass
 │   └── scan_result.py   # Findings/assets bundle
├── output/
│   ├── console.py       # Rich terminal output
 │   ├── json_output.py
 │   ├── html_output.py
 │   └── cbom_output.py
└── utils/
    ├── logger.py
    ├── network.py       # make_request, check_connectivity, extract_domain
    └── validators.py    # Input validation
```

---

## Installation

### From Source (recommended)

```bash
git clone https://github.com/abdulrafayishaCkER/crypto-asset-scanner.git
cd crypto-asset-scanner

python -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate

pip install -r requirements.txt
pip install -e .
```

### Quick pip install

```bash
pip install crypto-recon
```

---

## Usage

### CLI Reference

```
cryptorecon scan web <target> [options]
cryptorecon scan local <path> [options]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--port INT` | TLS/HTTPS port | `443` |
| `--output FORMAT` | `console` \| `json` \| `html` \| `cbom` | `console` |
| `--report FILE` | Save report to file | — |
| `--timeout INT` | HTTP timeout (seconds) | `10` |
| `--threads INT` | Concurrent worker threads | `5` |
| `--severity LEVEL` | Minimum severity to display | `info` |
| `--deep` | Enable additional deep checks | off |
| `--github-token TOKEN` | GitHub API token | `$GITHUB_TOKEN` |
| `--no-color` | Disable colour output | off |
| `-v / --verbose` | Enable debug logging | off |
| `-q / --quiet` | Minimal output | off |

### Web Scan Examples

```bash
# Basic web scan (console output)
cryptorecon scan web example.com

# Scan on a non-standard port
cryptorecon scan web api.example.com --port 8443

# HTML report
cryptorecon scan web example.com --output html --report report.html

# JSON report with verbose logging
cryptorecon scan web example.com --output json --report findings.json -v

# CBOM export (CycloneDX-style JSON)
cryptorecon scan web example.com --output cbom --report cbom.json

# Show only HIGH and above
cryptorecon scan web example.com --severity high

# Deep scan with GitHub token
export GITHUB_TOKEN=ghp_yourtoken
cryptorecon scan web example.com --deep
```

Example console output:

```
🔴 CRITICAL  tls         Deprecated Protocol Supported: SSLv3
🟠 HIGH      certificate  Certificate Expiring Soon (7 days)
🟠 HIGH      headers      Missing Strict-Transport-Security Header
🟡 MEDIUM    dns          Missing DMARC Record
🔵 LOW       headers      Missing Referrer-Policy Header
⚪ INFO      subdomain    Subdomain Discovered: www.example.com
```

### Local Scan Examples

```bash
# Scan a single directory
cryptorecon scan local /srv/app

# Scan with JSON report
cryptorecon scan local /home/user/projects --output json --report secrets.json

# Non-recursive scan
cryptorecon scan local /etc --output console
```

### Interactive Mode

Run without arguments to launch the original interactive menu:

```bash
cryptorecon
# or
python -m crypto_recon
```

---

## Configuration

All constants live in `crypto_recon/config.py`:

| Constant | Default | Description |
|----------|---------|-------------|
| `HTTP_TIMEOUT` | `10` | Per-request timeout (seconds) |
| `MAX_THREADS` | `5` | ThreadPoolExecutor workers |
| `MAX_CRAWL_DEPTH` | `2` | Crawler recursion depth |
| `USER_AGENT` | `CryptoRecon/2.1 CBOM Scanner` | HTTP User-Agent |
| `MAX_REQUESTS` | `200` | Max HTTP requests per crawl instance |
| `REQUESTS_PER_SECOND` | `5.0` | Rate limit for crawler requests |
| `MAX_FILE_SIZE_BYTES` | `1000000` | Max local file size for scanning |
| `SKIP_DIR_NAMES` | `[...]` | Directories skipped during local scan |

To customise at runtime, set environment variables or edit `config.py`.

---

## Secret Patterns Detected

| Pattern Name | Example Match |
|---|---|
| AWS Access Key | `AKIA…` (20 chars) |
| AWS Secret Key | Contextual match near `aws_secret` |
| Google API Key | `AIza…` |
| Google OAuth Client | `….apps.googleusercontent.com` |
| Stripe Live Secret | `sk_live_…` |
| Stripe Live Publishable | `pk_live_…` |
| Stripe Test | `sk_test_…` |
| GitHub Token | `ghp_…` |
| GitHub OAuth | `gho_…` |
| GitHub User Token | `ghu_…` |
| GitHub Server Token | `ghs_…` |
| GitHub Refresh Token | `ghr_…` |
| GitLab Token | `glpat-…` |
| Slack Bot Token | `xoxb-…` |
| Slack User Token | `xoxp-…` |
| Slack Webhook | `https://hooks.slack.com/services/…` |
| Discord Token | `M…` / `N…` pattern |
| Discord Webhook | `https://discord.com/api/webhooks/…` |
| Twilio SID | `AC…` |
| Twilio Auth Token | `SK…` |
| SendGrid API Key | `SG.…` |
| Mailgun API Key | `key-…` |
| Firebase FCM | `AAAA…:…` |
| Heroku API Key | UUID-format |
| DigitalOcean Token | `dop_v1_…` |
| Azure Storage Connection | `DefaultEndpointsProtocol=…` |
| RSA Private Key | `-----BEGIN RSA PRIVATE KEY-----` |
| EC Private Key | `-----BEGIN EC PRIVATE KEY-----` |
| OpenSSH Private Key | `-----BEGIN OPENSSH PRIVATE KEY-----` |
| PGP Private Key Block | `-----BEGIN PGP PRIVATE KEY BLOCK-----` |
| JWT Token | `eyJ….eyJ….…` |
| Basic Auth in URL | `https://user:pass@host` |
| MongoDB URI | `mongodb://…` / `mongodb+srv://…` |
| PostgreSQL URI | `postgres://…` |
| MySQL URI | `mysql://…` |
| Redis URI | `redis://…` |
| npm Token | `npm_…` |
| PyPI Token | `pypi-…` |
| Generic Password/Secret | `password = "…"` / `api_key: "…"` |

---

## Security Headers Checked

| Header | Missing Severity |
|--------|-----------------|
| `Strict-Transport-Security` | HIGH |
| `Content-Security-Policy` | MEDIUM |
| `X-Content-Type-Options` | LOW |
| `X-Frame-Options` | MEDIUM |
| `X-XSS-Protection` (disabled) | LOW |
| `Referrer-Policy` | LOW |
| `Permissions-Policy` | LOW |
| `Cross-Origin-Resource-Policy` | LOW |
| `Cross-Origin-Opener-Policy` | LOW |
| `Cache-Control` | LOW |
| `Server` (version disclosure) | LOW |
| `X-Powered-By` | LOW |

---

## Exposed Paths Checked

`.env`, `.env.local`, `.env.production`, `.env.staging`, `.env.development`, `.env.test`, `.env.backup`, `.env.example`, `.git/config`, `.git/HEAD`, `.gitignore`, `.svn/entries`, `.svn/wc.db`, `.hg/hgrc`, `wp-config.php`, `configuration.php`, `.htaccess`, `.htpasswd`, `web.config`, `applicationHost.config`, `phpinfo.php`, `info.php`, `server-status`, `server-info`, `elmah.axd`, `trace.axd`, `robots.txt`, `sitemap.xml`, `crossdomain.xml`, `clientaccesspolicy.xml`, `.well-known/security.txt`, `package.json`, `composer.json`, `Gemfile`, `backup.zip`, `backup.tar.gz`, `backup.sql`, `db.sql`, `dump.sql`, `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`, `server.key`, `server.pem`, `privkey.pem`, `fullchain.pem`, `cert.pem`, `docker-compose.yml`, `Dockerfile`, `swagger.json`, `swagger.yaml`, `openapi.json`, `api/docs`, `api/swagger`, `graphql`, `actuator/health`, `actuator/env`, `_debug`, `debug`, `console`, `.DS_Store`, `Thumbs.db`, `error_log`, `error.log`, `debug.log`, `access.log`

---

## Output Formats

### Console (default)
Rich, colour-coded terminal table with severity icons and a summary panel.

### JSON
Machine-readable report including findings and the full asset inventory with safe evidence.

```bash
cryptorecon scan web example.com --output json --report scan.json
```

### HTML
Self-contained single-file report with:
- Executive summary cards (finding counts by severity)
- Collapsible finding details
- Colour-coded severity badges
- Evidence and remediation for each finding
- Professional dark-themed styling

```bash
cryptorecon scan web example.com --output html --report report.html
```

### CBOM (CycloneDX-style JSON)
Structured asset inventory suitable for ingestion into SBOM/CBOM tooling.

```bash
cryptorecon scan web example.com --output cbom --report cbom.json
```

---

## CBOM Discovery Notes
- Assets and findings are separate: assets describe what was discovered, findings describe risk.
- Secrets are always redacted in output; only fingerprints/hashes are stored.
- Endpoint discoveries are marked low confidence until validated.

## Safety Notes
- Never commit CBOM outputs containing sensitive infrastructure details to public repos.
- Rotate credentials immediately if secret references are detected.
- Use authorised scopes and rate limits to avoid impacting production systems.

## Limitations
- Certificate transparency results remain unverified until DNS validation succeeds.
- Dependency parsing is limited to `requirements.txt` and `package.json`.
- Soft-404/login heuristics reduce false positives but can miss edge cases.

## Production Roadmap
- Add repository-wide dependency graph ingestion (lockfiles, SCA feeds).
- Integrate PKI chain validation and revocation status checks.
- Add pluggable asset exporters (CSV, CycloneDX components/services split).

---

## Legal Disclaimer

> **CryptoRecon is provided for authorised security testing and research only.**
>
> You must have explicit written permission from the system owner before scanning any target. Unauthorised use may violate the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act (CMA), and equivalent laws in your jurisdiction. The authors accept no responsibility or liability for misuse of this tool.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on submitting bug reports, feature requests, and pull requests.

---

## License

This project is licensed under the [MIT License](LICENSE).
