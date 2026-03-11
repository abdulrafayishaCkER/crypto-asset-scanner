"""Input validation helpers."""

from __future__ import annotations

import os
import re
from typing import Any


def validate_target(target: str) -> str:
    """Strip protocols and trailing slashes, validate target format.

    Args:
        target: Hostname, IP address, or URL.

    Returns:
        Cleaned hostname or IP string.

    Raises:
        ValueError: If the target is empty or contains invalid characters.
    """
    for prefix in ("https://", "http://"):
        if target.startswith(prefix):
            target = target[len(prefix):]
    target = target.rstrip("/").split("/")[0].strip()

    if not target:
        raise ValueError("Target must not be empty.")

    if not re.match(r"^[A-Za-z0-9._\[\]:-]+$", target):
        raise ValueError(f"Target contains invalid characters: {target!r}")

    return target


def validate_port(port: Any) -> int:
    """Coerce and validate a TCP port number.

    Args:
        port: Value to validate; may be ``str`` or ``int``.

    Returns:
        Validated port as an integer in the range 1–65535.

    Raises:
        ValueError: If the port is outside the valid range.
    """
    try:
        port_int = int(port)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid port value: {port!r}") from exc

    if not 1 <= port_int <= 65535:
        raise ValueError(f"Port must be between 1 and 65535, got {port_int}.")

    return port_int


def validate_directory(path: str) -> str:
    """Resolve and validate that *path* is an accessible directory.

    Args:
        path: Filesystem path.

    Returns:
        Absolute, resolved path string.

    Raises:
        ValueError: If the path does not exist or is not a directory.
    """
    resolved = os.path.realpath(path)
    if not os.path.exists(resolved):
        raise ValueError(f"Path does not exist: {resolved!r}")
    if not os.path.isdir(resolved):
        raise ValueError(f"Path is not a directory: {resolved!r}")
    return resolved
