"""Data models for findings and reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
from typing import Optional, List

from crypto_recon.models.asset import Confidence
from crypto_recon.models.evidence import Evidence


class Severity(Enum):
    """Finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(Enum):
    """Finding category types."""

    TLS = "tls"
    CERTIFICATE = "certificate"
    HEADERS = "headers"
    SECRETS = "secrets"
    FILES = "files"
    DNS = "dns"
    API = "api"
    SUBDOMAIN = "subdomain"
    GITHUB = "github"
    LOCAL = "local"


@dataclass
class Finding:
    """Represents a single security finding."""

    title: str
    description: str
    severity: Severity
    category: Category
    confidence: Confidence = Confidence.MEDIUM
    evidence: Optional[Evidence] = None
    remediation: str = ""
    cwe: str = ""
    cve: str = ""
    url: str = ""
    related_assets: List[str] = field(default_factory=list)
    dedup_key: str = ""

    def compute_dedup_key(self) -> str:
        """Compute a stable deduplication key."""
        base = "|".join(
            [
                self.title,
                self.category.value,
                self.severity.value,
                self.url or "",
                self.evidence.summary() if self.evidence else "",
                ",".join(sorted(self.related_assets)),
            ]
        )
        return hashlib.sha256(base.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict:
        """Serialize the finding to a plain dictionary."""
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "confidence": self.confidence.value,
            "evidence": self.evidence.to_dict() if self.evidence else {},
            "evidence_summary": self.evidence.summary() if self.evidence else "",
            "remediation": self.remediation,
            "cwe": self.cwe,
            "cve": self.cve,
            "url": self.url,
            "related_assets": self.related_assets,
            "dedup_key": self.dedup_key,
        }
