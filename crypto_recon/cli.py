"""Command-line interface for CryptoRecon."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from datetime import datetime, timezone

from crypto_recon import __version__
from crypto_recon.models.finding import Severity
from crypto_recon.models.report import Report
from crypto_recon.utils.logger import get_logger
from crypto_recon.utils.validators import validate_directory, validate_port, validate_target

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Severity ordering for filter comparisons
# ---------------------------------------------------------------------------
_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


def _severity_gte(finding_sev: Severity, min_sev: Severity) -> bool:
    """Return True if *finding_sev* is at least as severe as *min_sev*."""
    return _SEVERITY_ORDER.index(finding_sev) <= _SEVERITY_ORDER.index(min_sev)


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def create_parser() -> argparse.ArgumentParser:
    """Build and return the top-level argument parser."""
    parser = argparse.ArgumentParser(
        prog="cryptorecon",
        description="CryptoRecon – CBOM Discovery & Cryptographic Asset Inventory Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  cryptorecon scan web example.com\n"
            "  cryptorecon scan web example.com --port 8443 --output html --report report.html\n"
            "  cryptorecon scan local /srv/app --recursive\n"
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"CryptoRecon {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command")

    # ---- scan sub-command --------------------------------------------------
    scan_parser = subparsers.add_parser("scan", help="Run a scan")
    scan_subparsers = scan_parser.add_subparsers(dest="scan_type")

    # scan web
    web_parser = scan_subparsers.add_parser("web", help="Scan a web target")
    web_parser.add_argument("target", help="Hostname or IP address (e.g. example.com)")
    web_parser.add_argument("--port", type=int, default=443, help="TLS/HTTPS port (default: 443)")
    _add_common_options(web_parser)

    # scan local
    local_parser = scan_subparsers.add_parser("local", help="Scan local filesystem")
    local_parser.add_argument("path", help="Directory path to scan")
    local_parser.add_argument(
        "--recursive", action="store_true", help="Recursively scan subdirectories"
    )
    local_parser.add_argument(
        "--max-file-size",
        type=int,
        default=None,
        help="Maximum file size to scan in bytes (default: config)",
    )
    _add_common_options(local_parser)

    return parser


def _add_common_options(p: argparse.ArgumentParser) -> None:
    """Attach shared options to a sub-command parser."""
    p.add_argument(
        "--output",
        choices=["console", "json", "html", "cbom"],
        default="console",
        help="Output format (default: console)",
    )
    p.add_argument("--report", metavar="FILE", help="Save report to FILE")
    p.add_argument("--timeout", type=int, default=10, help="HTTP timeout in seconds (default: 10)")
    p.add_argument("--threads", type=int, default=5, help="Concurrent threads (default: 5)")
    p.add_argument("--no-color", action="store_true", help="Disable coloured output")
    p.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    p.add_argument("--quiet", "-q", action="store_true", help="Minimal output")
    p.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low", "info"],
        default="info",
        help="Minimum severity level to display (default: info)",
    )
    p.add_argument("--deep", action="store_true", help="Enable deep scanning (more checks)")
    p.add_argument("--github-token", metavar="TOKEN", help="GitHub API token for code search")
    p.add_argument(
        "--max-requests",
        type=int,
        default=None,
        help="Maximum HTTP request budget for web crawling (default: config)",
    )
    p.add_argument(
        "--rate-limit",
        type=float,
        default=None,
        help="Max HTTP requests per second for web crawling (default: config)",
    )


# ---------------------------------------------------------------------------
# Scan orchestration
# ---------------------------------------------------------------------------

def run_web_scan(
    target: str,
    port: int = 443,
    timeout: int = 10,
    threads: int = 5,
    deep: bool = False,
    github_token: str | None = None,
    max_requests: int | None = None,
    rate_limit: float | None = None,
    quiet: bool = False,
) -> Report:
    """Orchestrate a full web target scan and return a :class:`Report`.

    Args:
        target: Validated hostname.
        port: TCP port.
        timeout: HTTP timeout.
        threads: Concurrent worker threads.
        deep: Whether to run additional deep checks.
        github_token: Optional GitHub API token.
        quiet: Suppress progress output.

    Returns:
        Completed :class:`Report`.
    """
    from crypto_recon.output.console import ConsoleOutput
    from crypto_recon.scanner import (
        CertAnalyzer,
        DNSAnalyzer,
        GitHubScanner,
        HeaderAnalyzer,
        SubdomainEnumerator,
        TLSScanner,
        WebCrawler,
    )

    console = ConsoleOutput()
    report = Report(
        target=target,
        scan_type="web",
        start_time=datetime.now(timezone.utc),
        metadata={"port": port, "deep": deep},
    )

    crawler = WebCrawler(
        timeout=timeout,
        threads=threads,
        max_requests=max_requests,
        rate_limit=rate_limit,
    )

    steps = [
        ("TLS Configuration", lambda: TLSScanner(timeout=timeout).scan(target, port)),
        ("Certificate Chain", lambda: CertAnalyzer().analyze(target, port)),
        ("Security Headers", lambda: HeaderAnalyzer().analyze(target, port)),
        ("Exposed Paths & Secrets", lambda: crawler.crawl(target, port)),
        ("API Endpoints", lambda: crawler.discover_api_endpoints(target, port)),
        ("Subdomain Enumeration", lambda: SubdomainEnumerator().enumerate(_base_domain(target))),
        ("DNS Analysis", lambda: DNSAnalyzer().analyze(_base_domain(target))),
        ("GitHub Code Search", lambda: GitHubScanner(token=github_token or os.getenv("GITHUB_TOKEN")).search(target)),
    ]

    if quiet:
        for _, fn in steps:
            try:
                report.extend_results(fn())
            except Exception as exc:
                logger.error("Scan step failed: %s", exc)
    else:
        with console.create_progress() as progress:
            task = progress.add_task("Scanning…", total=len(steps))
            for name, fn in steps:
                progress.update(task, description=f"[cyan]{name}[/cyan]…")
                try:
                    report.extend_results(fn())
                except Exception as exc:
                    logger.error("Step %r failed: %s", name, exc)
                progress.advance(task)

    report.end_time = datetime.now(timezone.utc)
    return report


def run_local_scan(
    path: str,
    recursive: bool = True,
    max_file_size: int | None = None,
    quiet: bool = False,
) -> Report:
    """Orchestrate a local filesystem scan.

    Args:
        path: Validated directory path.
        recursive: Whether to recurse into sub-directories.
        quiet: Suppress progress output.

    Returns:
        Completed :class:`Report`.
    """
    from crypto_recon.output.console import ConsoleOutput
    from crypto_recon.scanner.dependency_scanner import DependencyScanner
    from crypto_recon.scanner.secret_scanner import SecretScanner

    console = ConsoleOutput()
    scanner = SecretScanner(max_file_size=max_file_size)
    dependency_scanner = DependencyScanner()
    report = Report(
        target=path,
        scan_type="local",
        start_time=datetime.now(timezone.utc),
        metadata={"recursive": recursive},
    )

    files: list[str] = []
    from crypto_recon.config import SKIP_DIRS

    for dirpath, dirnames, filenames in os.walk(path, onerror=None):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            files.append(os.path.join(dirpath, fname))
        if not recursive:
            dirnames.clear()

    if quiet:
        for fp in files:
            report.extend_results(scanner.scan_file(fp))
            report.extend_results(dependency_scanner.scan_file(fp))
    else:
        with console.create_progress() as progress:
            task = progress.add_task("[cyan]Scanning files…[/cyan]", total=len(files))
            for fp in files:
                try:
                    report.extend_results(scanner.scan_file(fp))
                    report.extend_results(dependency_scanner.scan_file(fp))
                except Exception as exc:
                    logger.debug("Error scanning %s: %s", fp, exc)
                progress.advance(task)

    report.end_time = datetime.now(timezone.utc)
    return report


# ---------------------------------------------------------------------------
# Report output
# ---------------------------------------------------------------------------

def _output_report(
    report: Report,
    fmt: str,
    report_file: str | None,
    min_severity: Severity,
    no_color: bool,
    quiet: bool,
) -> None:
    """Render and optionally save *report* in the chosen format."""
    from crypto_recon.output.cbom_output import CBOMOutput
    from crypto_recon.output.console import ConsoleOutput
    from crypto_recon.output.html_output import HTMLOutput
    from crypto_recon.output.json_output import JSONOutput

    # Filter findings by minimum severity
    filtered = [f for f in report.findings if _severity_gte(f.severity, min_severity)]

    if fmt == "console":
        out = ConsoleOutput(no_color=no_color)
        if not quiet:
            out.print_findings(filtered)
            out.print_assets(report.assets)
        out.print_summary(report)

    elif fmt == "json":
        # Temporarily narrow findings for output
        original = report.findings
        report.findings = filtered
        jo = JSONOutput()
        if report_file:
            jo.write(report, report_file)
        else:
            print(jo.to_string(report))
        report.findings = original

    elif fmt == "html":
        original = report.findings
        report.findings = filtered
        ho = HTMLOutput()
        dest = report_file or f"cryptorecon_{report.target.replace('.', '_')}.html"
        ho.write(report, dest)
        report.findings = original
        print(f"HTML report written to: {dest}")
    elif fmt == "cbom":
        co = CBOMOutput()
        if report_file:
            co.write(report, report_file)
        else:
            print(co.to_string(report))

    # Always save to file if requested and format isn't already writing it
    if report_file and fmt == "console":
        # Default to JSON when format is console but a file is requested
        jo = JSONOutput()
        jo.write(report, report_file)


# ---------------------------------------------------------------------------
# Interactive menu (backward compatibility)
# ---------------------------------------------------------------------------

def _interactive_menu() -> None:
    """Launch the original interactive menu."""
    from crypto_recon.output.console import ConsoleOutput

    ConsoleOutput().print_banner()

    while True:
        print("\nWhat would you like to do?")
        print("  1) Scan an external website")
        print("  2) Scan local directories for cryptographic assets")
        print("  3) Exit")
        choice = input("Enter choice [1-3]: ").strip()

        if choice == "1":
            _interactive_web_scan()
        elif choice == "2":
            _interactive_local_scan()
        elif choice == "3":
            print("\nGoodbye!\n")
            sys.exit(0)
        else:
            print("[!] Invalid choice. Please enter 1, 2, or 3.\n")


def _interactive_web_scan() -> None:
    """Interactive web scan flow."""
    print("\n--- WEBSITE SCAN ---")
    raw_target = input("Enter hostname or IP to scan (e.g., example.com): ").strip()
    if not raw_target:
        print("[!] No target specified. Aborting.")
        return

    try:
        target = validate_target(raw_target)
    except ValueError as exc:
        print(f"[!] Invalid target: {exc}")
        return

    port_input = input("Enter port (default 443) or press Enter: ").strip()
    try:
        port = validate_port(port_input) if port_input else 443
    except ValueError as exc:
        print(f"[!] Invalid port: {exc}")
        return

    print(f"\n[*] Scanning {target}:{port} …\n")
    report = run_web_scan(target, port=port)

    from crypto_recon.output.console import ConsoleOutput

    out = ConsoleOutput()
    out.print_findings(report.findings)
    out.print_summary(report)


def _interactive_local_scan() -> None:
    """Interactive local directory scan flow."""
    print("\n--- LOCAL DIRECTORY SCAN ---")
    dirs: list[str] = []
    print("Enter one directory path per line. Blank line to start scanning.")
    while True:
        d = input("Directory path: ").strip()
        if not d:
            break
        try:
            dirs.append(validate_directory(d))
        except ValueError as exc:
            print(f"[!] {exc}")

    if not dirs:
        print("[!] No directories provided. Aborting.")
        return

    from crypto_recon.output.console import ConsoleOutput

    out = ConsoleOutput()
    for directory in dirs:
        print(f"\n[*] Scanning {directory} …")
        report = run_local_scan(directory)
        out.print_findings(report.findings)
        out.print_summary(report)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Main entry point for the ``cryptorecon`` CLI."""
    parser = create_parser()
    args = parser.parse_args()

    # Configure log level
    level = logging.WARNING
    if hasattr(args, "verbose") and args.verbose:
        level = logging.DEBUG
    elif hasattr(args, "quiet") and args.quiet:
        level = logging.ERROR
    logging.basicConfig(level=level)

    # No sub-command → interactive mode
    if not args.command:
        try:
            _interactive_menu()
        except KeyboardInterrupt:
            print("\n[!] Interrupted.")
            sys.exit(0)
        return

    if args.command == "scan":
        if not args.scan_type:
            parser.print_help()
            sys.exit(1)

        if not hasattr(args, "verbose"):
            args.verbose = False
        if not hasattr(args, "quiet"):
            args.quiet = False
        if not hasattr(args, "no_color"):
            args.no_color = False

        min_sev = Severity(args.severity)

        try:
            if args.scan_type == "web":
                target = validate_target(args.target)
                port = validate_port(args.port)

                from crypto_recon.output.console import ConsoleOutput
                if not args.quiet:
                    ConsoleOutput(no_color=args.no_color).print_banner()

                report = run_web_scan(
                    target,
                    port=port,
                    timeout=args.timeout,
                    threads=args.threads,
                    deep=getattr(args, "deep", False),
                    github_token=getattr(args, "github_token", None),
                    max_requests=getattr(args, "max_requests", None),
                    rate_limit=getattr(args, "rate_limit", None),
                    quiet=args.quiet,
                )

            elif args.scan_type == "local":
                path = validate_directory(args.path)

                from crypto_recon.output.console import ConsoleOutput
                if not args.quiet:
                    ConsoleOutput(no_color=args.no_color).print_banner()

                report = run_local_scan(
                    path,
                    recursive=getattr(args, "recursive", True),
                    max_file_size=getattr(args, "max_file_size", None),
                    quiet=args.quiet,
                )
            else:
                parser.print_help()
                sys.exit(1)

            _output_report(
                report,
                fmt=args.output,
                report_file=getattr(args, "report", None),
                min_severity=min_sev,
                no_color=args.no_color,
                quiet=args.quiet,
            )

        except ValueError as exc:
            print(f"[!] Input error: {exc}", file=sys.stderr)
            sys.exit(1)
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user.")
            sys.exit(0)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _base_domain(target: str) -> str:
    """Extract the registrable domain (last two labels) from a hostname."""
    parts = target.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return target
