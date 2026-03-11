# Contributing to CryptoRecon

Thank you for your interest in contributing! This document outlines how to participate in the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Coding Standards](#coding-standards)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Reporting Bugs](#reporting-bugs)

---

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for all contributors.

---

## Getting Started

1. **Fork** the repository.
2. **Clone** your fork:
   ```bash
   git clone https://github.com/<your-username>/crypto-asset-scanner.git
   cd crypto-asset-scanner
   ```
3. Create a **virtual environment** and install dependencies:
   ```bash
   python -m venv .venv
   source .venv/bin/activate   # Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   pip install -e ".[dev]"
   ```

---

## Development Setup

```bash
# Install development dependencies
pip install flake8 mypy pytest pytest-cov

# Run linter
flake8 crypto_recon/

# Run type checker
mypy crypto_recon/

# Run tests
pytest --cov=crypto_recon tests/
```

---

## How to Contribute

### Adding a New Scanner Module

1. Create your module in `crypto_recon/scanner/your_scanner.py`.
2. Implement a class with a `scan()` or `analyze()` method that returns `List[Finding]`.
3. Add appropriate type hints and a class-level docstring.
4. Export your class from `crypto_recon/scanner/__init__.py`.
5. Integrate it into `cli.py` `run_web_scan()` or `run_local_scan()`.

### Adding New Secret Patterns

Add patterns to `SECRET_PATTERNS` in `crypto_recon/config.py`. Use named groups where applicable and test against real (sanitised) examples.

### Adding New Exposed Paths

Append to `EXPOSED_PATHS` or `COMMON_API_PATHS` in `crypto_recon/config.py`. Keep them alphabetically grouped by category.

---

## Coding Standards

- **Python 3.9+** – use built-in generics (`list[str]` not `List[str]` from typing where possible).
- **Type hints** on all public functions and methods.
- **Docstrings** on all classes and public methods (Google style).
- **No bare `except:`** – catch specific exceptions.
- **No raw `print()`** for logic output – use `logging` or `ConsoleOutput`.
- **ThreadPoolExecutor** for I/O-bound concurrency.
- Line length: 100 characters maximum.
- Format code with `black` (recommended).

---

## Submitting a Pull Request

1. Create a feature branch: `git checkout -b feature/your-feature`.
2. Make your changes and commit with descriptive messages.
3. Push to your fork and open a PR against `main`.
4. Ensure your PR description explains *what* and *why*.
5. Link any related issues.

---

## Reporting Bugs

Please open a GitHub Issue with:

- **Description** of the bug.
- **Steps to reproduce**.
- **Expected behaviour**.
- **Actual behaviour**.
- Python version and OS.

For **security vulnerabilities**, see [SECURITY.md](SECURITY.md) instead.
