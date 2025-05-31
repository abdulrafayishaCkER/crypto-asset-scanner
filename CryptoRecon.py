#!/usr/bin/env python3
import os
import re
import sys
import json
import time
import requests
import urllib3
import socket
import ssl
import datetime
from sslyze import (
    Scanner,
    ServerScanRequest,
    ServerNetworkLocation,
    ScanCommandAttemptStatusEnum
)
from urllib.parse import urljoin, urlparse

# Disable InsecureRequestWarning from requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# -----------------------------
# Regex patterns for “local_scan”
# -----------------------------
PEM_CERT_PATTERN = re.compile(r"-----BEGIN CERTIFICATE-----")
PEM_KEY_PATTERN  = re.compile(r"-----BEGIN (?:RSA|EC|ENCRYPTED) PRIVATE KEY-----")
PGP_MESSAGE_PATTERN = re.compile(r"-----BEGIN PGP (?:PUBLIC )?KEY BLOCK-----|-----BEGIN PGP MESSAGE-----")
# Naïve “username:password”–style token (10+ chars before/after colon)
USERNAME_PASSWORD_PATTERN = re.compile(r"[A-Za-z0-9_\-]{10,}:[A-Za-z0-9_\-]{10,}")  
# JS/HTML secret pattern (simple heuristic for API keys/JWTs)
API_KEY_PATTERN = re.compile(r"(?:AKIA|AIza|sk_live_|pk_live_)[A-Za-z0-9_\-]{16,}")
JWT_PATTERN = re.compile(r"eyJ[0-9A-Za-z\-_]+\.[0-9A-Za-z\-_]+\.[0-9A-Za-z\-_]+")

# Timeout for HTTP requests (in seconds)
HTTP_TIMEOUT = 5

# -------------------------------
# Common weak cipher substring list
# -------------------------------
WEAK_CIPHER_KEYWORDS = ["RC4", "3DES", "DES", "NULL", "MD5"]

# --------------------------------------------
# Function: get_subdomains_via_crtsh(domain)
# --------------------------------------------
def get_subdomains_via_crtsh(domain):
    """
    Query crt.sh for certificate transparency entries for `domain` and extract subdomains.
    Uses the JSON output endpoint: https://crt.sh/?q=%25{domain}%25&output=json
    Returns a sorted, unique list of subdomains.
    """
    url = f"https://crt.sh/?q=%25{domain}%25&output=json"
    try:
        resp = requests.get(url, timeout=HTTP_TIMEOUT)
        if resp.status_code != 200:
            return []
        entries = resp.json()
        subdomains = set()
        for entry in entries:
            name_value = entry.get("name_value", "")
            for sub in name_value.split("\n"):
                if domain in sub:
                    subdomains.add(sub.strip())
        return sorted(subdomains)
    except Exception:
        return []

# --------------------------------------------
# Function: check_cert_misconfig(certs, target)
# --------------------------------------------
def check_cert_misconfig(chain_list, target):
    """
    Given a parsed certificate chain and a target, check for:
      - Expired certificates
      - Self-signed (subject == issuer)
      - SAN mismatch (target not in subject/issuer)
      - Weak algorithms (key size < 2048 or name includes weak keywords)
    Returns a dict of flags.
    """
    findings = {
        "expired": False,
        "self_signed": False,
        "san_mismatch": False,
        "weak_key": False
    }
    # Make 'now' an offset‐aware UTC datetime, so it can be compared with ISO‐parsed cert times:
    now = datetime.datetime.now(datetime.timezone.utc)

    for cert in chain_list:
        # 1) Expiration
        not_after_str = cert.get("not_after")
        if not_after_str:
            # Remove trailing "Z", if present, before parsing
            # e.g. "2025-07-17T09:57:27+00:00Z" → "2025-07-17T09:57:27+00:00"
            not_after = datetime.datetime.fromisoformat(not_after_str.rstrip("Z"))
            if not_after < now:
                findings["expired"] = True

        # 2) Self-signed
        if cert.get("subject") == cert.get("issuer"):
            findings["self_signed"] = True

        # 3) SAN mismatch: naive: check if target appears in subject string
        subj = cert.get("subject", "")
        if target not in subj:
            findings["san_mismatch"] = True

        # 4) Weak key size or algorithm
        key_type = cert.get("key_type", "")
        key_size = cert.get("key_size", 0)
        if key_size and key_size < 2048:
            findings["weak_key"] = True
        for kw in WEAK_CIPHER_KEYWORDS:
            if kw in key_type:
                findings["weak_key"] = True

    return findings

# --------------------------------------------
# Function: website_scan(target, tcp_port=443)
# --------------------------------------------
def website_scan(target, tcp_port=443):
    """
    1) Use sslyze to scan the TLS configuration of `target:tcp_port`
       - Enumerate TLS versions + cipher suites
       - Fetch certificate chain details
       - Check Heartbleed
    2) Check certificate misconfiguration (expired, self-signed, SAN mismatch, weak key)
    3) Fetch HTTP headers from https://target
    4) Perform a lightweight crawl to look for exposed .pem/.key/.env files
    5) Crawl HTML/JS for leaked tokens (API keys, JWTs)
    6) Discover common API endpoints (/api/, /auth/, /token)
    7) Enumerate subdomains via crt.sh, flag staging/dev subdomains
    8) Search public GitHub for references to target domain
    Returns a dict summarizing everything found.
    """
    result = {
        "target": target,
        "tls_scan": {},
        "cert_misconfig": {},
        "http_headers": {},
        "found_files": [],
        "leaked_secrets": [],
        "api_endpoints": [],
        "subdomains": [],
        "staging_dev_subs": [],
        "github_leaks": []
    }

    # --- Part 1: TLS enumeration via sslyze ---
    scanner = Scanner()
    scan_request = ServerScanRequest(
        server_location=ServerNetworkLocation(hostname=target, port=tcp_port)
    )
    scanner.queue_scans([scan_request])
    scan_results = list(scanner.get_results())
    if not scan_results:
        result["tls_scan"]["error"] = "sslyze returned no result"
    else:
        server_scan = scan_results[0]
        if server_scan.scan_status == 'ERROR_NO_CONNECTIVITY':
            result["tls_scan"]["error"] = f"No connectivity to port {tcp_port}/tcp"
        else:
            scan_res = server_scan.scan_result
            offered = {}
            chain_list = []
            for attr_name, label in [
                ('ssl_2_0_cipher_suites', 'SSLv2'),
                ('ssl_3_0_cipher_suites', 'SSLv3'),
                ('tls_1_0_cipher_suites', 'TLSv1.0'),
                ('tls_1_1_cipher_suites', 'TLSv1.1'),
                ('tls_1_2_cipher_suites', 'TLSv1.2'),
                ('tls_1_3_cipher_suites', 'TLSv1.3'),
            ]:
                attempt = getattr(scan_res, attr_name, None)
                if attempt and attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                    suites = [cipher.cipher_suite.name for cipher in attempt.result.accepted_cipher_suites]
                    offered[label] = {
                        'offered': bool(suites),
                        'cipher_suites': suites
                    }
            result["tls_scan"]["offered_protocols"] = offered

            # Certificate chain details
            cert_attempt = scan_res.certificate_info
            if cert_attempt and cert_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                deployments = cert_attempt.result.certificate_deployments
                if deployments:
                    chain = deployments[0].received_certificate_chain
                    for cert in chain:
                        cert_entry = {
                            "subject": cert.subject.rfc4514_string(),
                            "issuer": cert.issuer.rfc4514_string(),
                            "not_before": cert.not_valid_before_utc.isoformat() + "Z",
                            "not_after": cert.not_valid_after_utc.isoformat() + "Z",
                            "key_type": cert.public_key().__class__.__name__,
                            "key_size": cert.public_key().key_size
                        }
                        chain_list.append(cert_entry)
            result["tls_scan"]["certificate_chain"] = chain_list

            # Heartbleed check
            hb = getattr(scan_res, 'heartbleed', None)
            if hb and hb.status == ScanCommandAttemptStatusEnum.COMPLETED:
                result["tls_scan"]["heartbleed_vulnerable"] = hb.result.is_vulnerable_to_heartbleed
            else:
                result["tls_scan"]["heartbleed_vulnerable"] = None

            # Check misconfiguration
            result["cert_misconfig"] = check_cert_misconfig(chain_list, target)

    # --- Part 2: HTTP headers (HTTPS GET) ---
    homepage_html = ""
    try:
        resp = requests.get(f"https://{target}", timeout=HTTP_TIMEOUT, verify=False)
        result["http_headers"] = dict(resp.headers)
        homepage_html = resp.text
    except Exception as e:
        result["http_headers"] = {"error": str(e)}

    # --- Part 3: Lightweight "web crawl" for exposed .pem/.key/.env files ---
    to_check = [
        "id_rsa", "id_dsa",
        "server.pem", "server.key", "privkey.pem", "fullchain.pem",
        ".env", ".env.local", "config.json",
        ".git/config", ".svn/entries", "backup.zip"
    ]
    for fname in to_check:
        url = urljoin(f"https://{target}/", fname)
        try:
            r = requests.get(url, timeout=HTTP_TIMEOUT, allow_redirects=True, verify=False)
            if r.status_code == 200 and (b"-----BEGIN" in r.content or b"KEY" in r.content or b"SECRET" in r.content):
                snippet = r.content[:200].replace(b"\n", b"\\n").decode('utf-8', errors='ignore')
                result["found_files"].append({
                    "url": url,
                    "status_code": r.status_code,
                    "snippet": snippet
                })
        except Exception:
            pass

    # --- Part 4: Crawl HTML/JS for leaked tokens (API keys, JWTs) ---
    js_urls = set()
    # Simple regex to find <script src="...js">
    for match in re.findall(r"<script[^>]+src=[\'\"]([^\'\"]+\.js)[\'\"]", homepage_html, re.IGNORECASE):
        js_urls.add(urljoin(f"https://{target}", match))
    # Fetch each JS and scan for secrets
    for js_url in js_urls:
        try:
            r = requests.get(js_url, timeout=HTTP_TIMEOUT, verify=False)
            content = r.text
            for pattern, label in [(API_KEY_PATTERN, "API_KEY"), (JWT_PATTERN, "JWT_TOKEN")]:
                for m in pattern.findall(content):
                    result["leaked_secrets"].append({
                        "url": js_url,
                        "type": label,
                        "snippet": m[:100]
                    })
        except Exception:
            pass

    # --- Part 5: Discover common API endpoints ---
    common_apis = ["/api/", "/api/v1/", "/auth", "/token"]
    for endpoint in common_apis:
        url = urljoin(f"https://{target}", endpoint)
        try:
            r = requests.head(url, timeout=HTTP_TIMEOUT, allow_redirects=True, verify=False)
            if r.status_code < 400:
                result["api_endpoints"].append({"endpoint": endpoint, "status": r.status_code})
        except Exception:
            pass

    # --- Part 6: Subdomain enumeration via crt.sh ---
    base_domain = target.split(".")[-2] + "." + target.split(".")[-1] if "." in target else target
    subs = get_subdomains_via_crtsh(base_domain)
    result["subdomains"] = subs
    for sub in subs:
        if "dev" in sub.lower() or "stag" in sub.lower():
            result["staging_dev_subs"].append(sub)

    # --- Part 7: Public GitHub code search for domain leaks (optional) ---
    github_token = os.getenv("GITHUB_TOKEN")
    if github_token:
        headers = {"Authorization": f"token {github_token}"}
        query = f"{target} in:file"
        gh_url = f"https://api.github.com/search/code?q={query}&per_page=5"
        try:
            r = requests.get(gh_url, headers=headers, timeout=HTTP_TIMEOUT)
            if r.status_code == 200:
                data = r.json()
                for item in data.get("items", []):
                    result["github_leaks"].append({
                        "repo": item.get("repository", {}).get("full_name"),
                        "path": item.get("path"),
                        "url": item.get("html_url")
                    })
        except Exception:
            pass
    else:
        result["github_leaks"].append({"warning": "Set GITHUB_TOKEN env var for GitHub search"})

    return result

# --------------------------------------------
# Function: local_scan(list_of_directories)
# --------------------------------------------

def local_scan(directories):
    """
    Recursively walk each given directory. Whenever any file is readable,
    scan its first few KB for PEM/KEY/PGP markers or naive tokens.
    Return a list of:
        { "path": full_path, "matches": [list_of_patterns], "snippet": first_200_chars }
    """
    findings = []
    for root in directories:
        if not os.path.isdir(root):
            print(f"[!] Warning: {root} is not a directory or not accessible.")
            continue

        for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
            for fname in filenames:
                fullpath = os.path.join(dirpath, fname)
                try:
                    with open(fullpath, 'rb') as f:
                        data = f.read(4096)  # read up to 4 KB for pattern checks
                except Exception:
                    continue

                text = data.decode('utf-8', errors='ignore')
                entry = {"path": fullpath, "matches": []}

                if PEM_CERT_PATTERN.search(text):
                    entry["matches"].append("PEM_Certificate")
                if PEM_KEY_PATTERN.search(text):
                    entry["matches"].append("PEM_PrivateKey")
                if PGP_MESSAGE_PATTERN.search(text):
                    entry["matches"].append("PGP_Marker")
                if USERNAME_PASSWORD_PATTERN.search(text):
                    entry["matches"].append("POSSIBLE_TOKEN")
                if API_KEY_PATTERN.search(text):
                    entry["matches"].append("LOCAL_API_KEY")
                if JWT_PATTERN.search(text):
                    entry["matches"].append("LOCAL_JWT_TOKEN")

                if entry["matches"]:
                    snippet = text[:200].replace("\n", "\\n")
                    entry["snippet"] = snippet
                    findings.append(entry)

    return findings

# --------------------------------------------
# Main: Menu + User Input
# --------------------------------------------

# Main & ANSI-colored banner
# --------------------------------------------

def print_banner():
    CYAN = "\033[96m"
    RESET = "\033[0m"
    banner = rf"""{CYAN}
   ______                 __                                
  / ____/___  ____  _____/ /_____  ____ ___  ___  ____ ___ 
 / /   / __ \/ __ \/ ___/ __/ __ \/ __ `__ \/ _ \/ __ `__ \
/ /___/ /_/ / / / (__  ) /_/ /_/ / / / / / /  __/ / / / / /
\____/\____/_/ /_/____/\__/\____/_/ /_/ /_/\___/_/ /_/ /_/ 
                                                            
                 CryptoRecon v1.0 - by kali㉿project
{RESET}"""
    print(banner)


def main_menu():
    print("\nWhat would you like to do?")
    print("  1) Scan an external website (extended checks)")
    print("  2) Scan local directories for cryptographic assets")
    print("  3) Exit")
    choice = input("Enter choice [1-3]: ").strip()
    return choice

def do_website_scan_flow():
    print("\n--- WEBSITE SCAN ---")
    target = input("Enter hostname or IP to scan (e.g., example.com): ").strip()
    if not target:
        print("[!] No target specified. Aborting website scan.\n")
        return

    port_input = input("Enter port (default is 443) or press Enter: ").strip()
    port = 443
    if port_input.isdigit():
        port = int(port_input)

    print(f"\n[*] Starting extended TLS & HTTP scan for {target}:{port} … (this may take 30–60 seconds)\n")
    summary = website_scan(target, tcp_port=port)

    # Pretty-print JSON summary
    print(json.dumps(summary, indent=2, sort_keys=True))

def do_local_scan_flow():
    print("\n--- LOCAL DIRECTORY SCAN ---")
    dirs = []
    print("Enter one directory path per line. When done, enter a blank line.")
    while True:
        d = input("Directory path: ").strip()
        if not d:
            break
        dirs.append(d)

    if not dirs:
        print("[!] No directories provided. Aborting local scan.\n")
        return

    print("\n[*] Scanning local directories for cryptographic asset patterns …\n")
    findings = local_scan(dirs)

    if not findings:
        print("[-] No cryptographic markers found in the specified paths.")
    else:
        for idx, f in enumerate(findings, start=1):
            print(f"\n[{idx}] Path: {f['path']}")
            print(f"     Matches: {', '.join(f['matches'])}")
            snippet = f.get("snippet", "")
            if snippet:
                print(f"     Snippet (first ~200 chars):\n       {snippet}\n")

    print(f"\n[*] Local scan complete. Total findings: {len(findings)}")

if __name__ == "__main__":
    print_banner()
    while True:
        choice = main_menu()
        if choice == '1':
            do_website_scan_flow()
        elif choice == '2':
            do_local_scan_flow()
        elif choice == '3':
            print("\nGoodbye!\n")
            sys.exit(0)
        else:
            print("[!] Invalid choice. Please enter 1, 2, or 3.\n")
