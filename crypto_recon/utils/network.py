"""Network utility helpers."""

from __future__ import annotations

import socket
from typing import Optional
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from crypto_recon.utils.logger import get_logger

logger = get_logger(__name__)


def make_request(
    url: str,
    method: str = "GET",
    timeout: int = 10,
    verify: bool = False,
    **kwargs,
) -> Optional[requests.Response]:
    """Perform an HTTP request, returning the response or *None* on failure.

    Args:
        url: Target URL.
        method: HTTP method (GET, HEAD, POST, …).
        timeout: Request timeout in seconds.
        verify: Whether to verify TLS certificates.
        **kwargs: Additional keyword arguments forwarded to :func:`requests.request`.

    Returns:
        :class:`requests.Response` on success, ``None`` on any error.
    """
    try:
        headers = kwargs.pop("headers", {})
        if "User-Agent" not in headers:
            from crypto_recon.config import USER_AGENT
            headers["User-Agent"] = USER_AGENT
        return requests.request(
            method,
            url,
            timeout=timeout,
            verify=verify,
            headers=headers,
            allow_redirects=True,
            **kwargs,
        )
    except requests.exceptions.SSLError as exc:
        logger.debug("SSL error for %s: %s", url, exc)
    except requests.exceptions.ConnectionError as exc:
        logger.debug("Connection error for %s: %s", url, exc)
    except requests.exceptions.Timeout:
        logger.debug("Timeout for %s", url)
    except requests.exceptions.RequestException as exc:
        logger.debug("Request error for %s: %s", url, exc)
    return None


def check_connectivity(host: str, port: int = 443, timeout: int = 5) -> bool:
    """Check TCP connectivity to *host*:*port*.

    Args:
        host: Hostname or IP address.
        port: TCP port number.
        timeout: Connection timeout in seconds.

    Returns:
        ``True`` if the port is reachable, ``False`` otherwise.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, socket.error, OSError):
        return False


def extract_domain(url_or_host: str) -> str:
    """Return the bare hostname/domain from a URL or a plain hostname.

    Args:
        url_or_host: A URL like ``https://example.com/path`` or just ``example.com``.

    Returns:
        The hostname component, e.g. ``example.com``.
    """
    if "://" in url_or_host:
        return urlparse(url_or_host).hostname or url_or_host
    return url_or_host.split(":")[0].strip("/")
