# 🔐 CryptoRecon – Cryptographic Asset & Secret Discovery Tool
CryptoRecon is a Python-based tool designed to **analyze web applications and local file systems** for cryptographic secrets, TLS vulnerabilities, and configuration leaks.


## 🚀 Features

### 🌐 Website Scanning
- 🔍 Enumerate TLS versions, cipher suites using `sslyze`
- 📜 Analyze certificate chains:
  - Expired certs
  - Weak key sizes
  - Self-signed certs
  - SAN mismatches
- 🛡️ Detect Heartbleed vulnerability
- 📁 Discover exposed secrets in `.env`, `.pem`, `.key`, `.git/config`, etc.
- 🔑 Extract API keys, JWTs, and tokens from JS files
- 📡 Subdomain discovery via `crt.sh`
- 🔎 Search public GitHub repos for leaked references

### 💻 Local File Scanning
- 🧠 Regex-based scan for:
  - PEM / PGP keys
  - Hardcoded `username:password`
  - JWTs, API keys in local code
  - `.env` files and backups

---
