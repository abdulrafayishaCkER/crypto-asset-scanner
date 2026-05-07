"""Evidence model for safe, structured scan output."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Evidence:
    """Structured, safe evidence for findings and assets."""

    path: Optional[str] = None
    line: Optional[int] = None
    url: Optional[str] = None
    endpoint: Optional[str] = None
    fingerprint: Optional[str] = None
    snippet: Optional[str] = None
    details: Optional[str] = None
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialise evidence to a dictionary, omitting empty fields."""
        data = {
            "path": self.path,
            "line": self.line,
            "url": self.url,
            "endpoint": self.endpoint,
            "fingerprint": self.fingerprint,
            "snippet": self.snippet,
            "details": self.details,
            "metadata": self.metadata or None,
        }
        return {k: v for k, v in data.items() if v not in (None, "", {}, [])}

    def summary(self) -> str:
        """Return a compact evidence summary string."""
        parts: list[str] = []
        if self.path:
            if self.line is not None:
                parts.append(f"{self.path}:{self.line}")
            else:
                parts.append(self.path)
        if self.url:
            parts.append(self.url)
        if self.endpoint:
            parts.append(f"endpoint={self.endpoint}")
        if self.fingerprint:
            parts.append(f"fingerprint={self.fingerprint}")
        if self.snippet:
            parts.append(f"snippet={self.snippet}")
        if self.details:
            parts.append(self.details)
        if self.metadata:
            parts.append(
                "metadata="
                + ", ".join(f"{k}={v}" for k, v in sorted(self.metadata.items()))
            )
        return " | ".join(parts)
