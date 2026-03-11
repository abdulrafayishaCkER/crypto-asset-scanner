"""Data models for findings and reports."""

from __future__ import annotations

from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List


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
    evidence: str = ""
    remediation: str = ""
    cwe: str = ""
    cve: str = ""
    url: str = ""

    def to_dict(self) -> dict:
        """Serialize the finding to a plain dictionary."""
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cwe": self.cwe,
            "cve": self.cve,
            "url": self.url,
        }
