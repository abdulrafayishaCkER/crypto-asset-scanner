"""Structured, safe evidence attached to findings and assets."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class Evidence:
    """Represent safe evidence without storing raw secrets."""

    file_path: Optional[str] = None
    line_number: Optional[int] = None
    url: Optional[str] = None
    endpoint: Optional[str] = None
    certificate_fingerprint: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize evidence into a JSON-friendly dictionary."""
        data: dict[str, Any] = {}
        if self.file_path:
            data["file_path"] = self.file_path
        if self.line_number is not None:
            data["line_number"] = self.line_number
        if self.url:
            data["url"] = self.url
        if self.endpoint:
            data["endpoint"] = self.endpoint
        if self.certificate_fingerprint:
            data["certificate_fingerprint"] = self.certificate_fingerprint
        if self.details:
            data["details"] = self.details
        return data

    def summary(self) -> str:
        """Return a concise human-readable evidence summary."""
        parts: list[str] = []
        if self.file_path:
            if self.line_number is not None:
                parts.append(f"{self.file_path}:{self.line_number}")
            else:
                parts.append(self.file_path)
        if self.url:
            parts.append(self.url)
        if self.endpoint:
            parts.append(self.endpoint)
        if self.certificate_fingerprint:
            parts.append(f"cert:{self.certificate_fingerprint}")
        if not parts and self.details:
            parts.append(", ".join(f"{k}={v}" for k, v in self.details.items()))
        return " | ".join(parts)
