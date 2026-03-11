# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 2.x     | ✅ Yes             |
| 1.x     | ❌ No (EOL)        |

---

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities via GitHub Issues.**

If you discover a security vulnerability in CryptoRecon, please disclose it responsibly by emailing:

**security@cryptorecon.example.com**

Include in your report:

1. A description of the vulnerability.
2. Steps to reproduce the issue.
3. The potential impact.
4. Any suggested fix (optional).

You will receive an acknowledgement within **48 hours** and a resolution timeline within **7 days**.

---

## Scope

The following are in scope for responsible disclosure:

- Remote code execution in the scanner modules.
- Authentication bypass in any authenticated feature.
- Injection vulnerabilities (command injection, path traversal) in input handling.
- Unsafe deserialization.

The following are **out of scope**:

- Findings that require physical access to the machine running CryptoRecon.
- Denial-of-service against scanned targets (by design, scanning generates requests).
- Social engineering of maintainers.

---

## Security Best Practices for Users

- **Do not run CryptoRecon against targets you do not own or have explicit written permission to scan.**
- Run with a dedicated low-privilege account.
- Store GitHub tokens in environment variables, not on the command line.
- Review generated reports carefully before sharing; they may contain sensitive data.

---

## Legal Disclaimer

CryptoRecon is provided for **authorised security testing only**. Unauthorised scanning of systems may violate laws including the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act (CMA), and equivalent legislation in your jurisdiction. The authors accept no liability for misuse.
