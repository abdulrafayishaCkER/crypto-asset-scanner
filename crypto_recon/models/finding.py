"""Data models for findings and reports."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

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
    evidence: Evidence = field(default_factory=Evidence)
    remediation: str = ""
    cwe: str = ""
    cve: str = ""
    url: str = ""

    def dedup_key(self) -> str:
        """Return a stable deduplication key for this finding."""
        payload = {
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category.value,
            "evidence": self.evidence.to_dict(),
            "url": self.url,
        }
        encoded = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def to_dict(self) -> dict:
        """Serialize the finding to a plain dictionary."""
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "confidence": self.confidence.value,
            "evidence": self.evidence.to_dict(),
            "remediation": self.remediation,
            "cwe": self.cwe,
            "cve": self.cve,
            "url": self.url,
            "dedup_key": self.dedup_key(),
        }
