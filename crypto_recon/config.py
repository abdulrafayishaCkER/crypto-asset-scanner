"""Central configuration and constants for CryptoRecon."""

from __future__ import annotations

HTTP_TIMEOUT: int = 10
MAX_THREADS: int = 5
MAX_CRAWL_DEPTH: int = 2
USER_AGENT: str = "CryptoRecon/2.1 CBOM Scanner"
MAX_REQUEST_BUDGET: int = 200
RATE_LIMIT_PER_SECOND: float = 5.0

MAX_FILE_SIZE_BYTES: int = 5 * 1024 * 1024
MAX_FILE_READ_BYTES: int = 5 * 1024 * 1024

SKIP_DIRS: list[str] = [
    ".git",
    ".hg",
    ".svn",
    ".tox",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "vendor",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
]

SOFT_404_PATTERNS: list[str] = [
    "page not found",
    "not found",
    "404",
    "does not exist",
    "error 404",
]

LOGIN_PAGE_PATTERNS: list[str] = [
    "login",
    "sign in",
    "signin",
    "log in",
    "authentication required",
]

WEAK_CIPHER_KEYWORDS: list[str] = ["RC4", "3DES", "DES", "NULL", "MD5", "EXPORT", "anon"]

EXPOSED_PATHS: list[str] = [
    # Environment files
    ".env",
    ".env.local",
    ".env.production",
    ".env.staging",
    ".env.development",
    ".env.test",
    ".env.backup",
    ".env.example",
    # Version control
    ".git/config",
    ".git/HEAD",
    ".gitignore",
    ".svn/entries",
    ".svn/wc.db",
    ".hg/hgrc",
    # CMS / framework configs
    "wp-config.php",
    "configuration.php",
    ".htaccess",
    ".htpasswd",
    "web.config",
    "applicationHost.config",
    "phpinfo.php",
    "info.php",
    # Server info
    "server-status",
    "server-info",
    "elmah.axd",
    "trace.axd",
    # Well-known / metadata
    "robots.txt",
    "sitemap.xml",
    "crossdomain.xml",
    "clientaccesspolicy.xml",
    ".well-known/security.txt",
    # Dependency manifests
    "package.json",
    "composer.json",
    "Gemfile",
    # Archive / database dumps
    "backup.zip",
    "backup.tar.gz",
    "backup.sql",
    "db.sql",
    "dump.sql",
    # SSH keys
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    # TLS / PKI material
    "server.key",
    "server.pem",
    "privkey.pem",
    "fullchain.pem",
    "cert.pem",
    # Container / IaC
    "docker-compose.yml",
    "Dockerfile",
    # API docs
    "swagger.json",
    "swagger.yaml",
    "openapi.json",
    "api/docs",
    "api/swagger",
    "graphql",
    # Spring Boot actuators
    "actuator/health",
    "actuator/env",
    # Debug / consoles
    "_debug",
    "debug",
    "console",
    # OS artefacts
    ".DS_Store",
    "Thumbs.db",
    # Log files
    "error_log",
    "error.log",
    "debug.log",
    "access.log",
]

COMMON_API_PATHS: list[str] = [
    "/api/",
    "/api/v1/",
    "/api/v2/",
    "/api/v3/",
    "/auth",
    "/auth/login",
    "/auth/logout",
    "/auth/register",
    "/token",
    "/oauth/token",
    "/oauth2/token",
    "/login",
    "/logout",
    "/register",
    "/signup",
    "/admin",
    "/admin/login",
    "/dashboard",
    "/user",
    "/users",
    "/profile",
    "/account",
    "/settings",
    "/config",
    "/health",
    "/healthz",
    "/status",
    "/metrics",
    "/version",
    "/info",
    "/docs",
    "/swagger",
    "/redoc",
    "/graphql",
    "/api/graphql",
]

SECRET_PATTERNS: dict[str, str] = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws.{0,20}secret.{0,20}['\"]([A-Za-z0-9/+=]{40})['\"]",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Google OAuth": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "Stripe Live Secret": r"sk_live_[0-9a-zA-Z]{24}",
    "Stripe Live Publishable": r"pk_live_[0-9a-zA-Z]{24}",
    "Stripe Test": r"sk_test_[0-9a-zA-Z]{24}",
    "GitHub Token": r"ghp_[A-Za-z0-9]{36}",
    "GitHub OAuth": r"gho_[A-Za-z0-9]{36}",
    "GitHub User Token": r"ghu_[A-Za-z0-9]{36}",
    "GitHub Server Token": r"ghs_[A-Za-z0-9]{36}",
    "GitHub Refresh Token": r"ghr_[A-Za-z0-9]{76}",
    "GitLab Token": r"glpat-[0-9a-zA-Z\-_]{20}",
    "Slack Bot Token": r"xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}",
    "Slack User Token": r"xoxp-[0-9]{11}-[0-9]{11}-[0-9]{12}-[0-9a-zA-Z]{32}",
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
    "Discord Token": r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}",
    "Discord Webhook": r"https://discord(?:app)?\.com/api/webhooks/[0-9]{18}/[A-Za-z0-9_-]{68}",
    "Twilio SID": r"AC[a-zA-Z0-9]{32}",
    "Twilio Auth Token": r"SK[a-zA-Z0-9]{32}",
    "SendGrid API Key": r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}",
    "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
    "Firebase Cloud Messaging": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
    "Heroku API Key": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    "DigitalOcean Token": r"dop_v1_[a-zA-Z0-9]{64}",
    "Azure Storage Connection": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}",
    "RSA Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
    "EC Private Key": r"-----BEGIN EC PRIVATE KEY-----",
    "OpenSSH Private Key": r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "PGP Private Key Block": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "JWT Token": r"eyJ[0-9A-Za-z\-_]+\.[0-9A-Za-z\-_]+\.[0-9A-Za-z\-_]+",
    "Basic Auth in URL": r"https?://[^:@/\s]+:[^:@/\s]+@[^/\s]+",
    "MongoDB URI": r"mongodb(?:\+srv)?://[^\s<>\"'`]+",
    "PostgreSQL URI": r"postgres(?:ql)?://[^\s<>\"'`]+",
    "MySQL URI": r"mysql://[^\s<>\"'`]+",
    "Redis URI": r"redis://[^\s<>\"'`]+",
    "npm Token": r"npm_[A-Za-z0-9]{36}",
    "PyPI Token": r"pypi-[A-Za-z0-9_-]{50,}",
    "Generic Password/Secret": r"(?i)(?:password|passwd|pwd|secret|token|api_key|apikey)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
}

SECURITY_HEADERS: list[str] = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cache-Control",
    "Server",
    "X-Powered-By",
]

DKIM_SELECTORS: list[str] = [
    "default",
    "google",
    "mail",
    "dkim",
    "k1",
    "k2",
    "selector1",
    "selector2",
    "smtp",
    "email",
    "mandrill",
    "mailchimp",
    "sendgrid",
    "postmark",
    "amazonses",
]
