"""Asset model for CBOM inventory output."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from crypto_recon.models.evidence import Evidence


class Confidence(Enum):
    """Confidence level for findings and assets."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AssetType(Enum):
    """Supported cryptographic asset categories."""

    CERTIFICATE = "certificate"
    TLS_PROTOCOL = "tls_protocol"
    CIPHER_SUITE = "cipher_suite"
    CRYPTO_ALGORITHM = "crypto_algorithm"
    SECRET_REFERENCE = "secret_reference"
    KEY_REFERENCE = "key_reference"
    DEPENDENCY = "dependency"
    ENDPOINT = "endpoint"
    SERVICE = "service"


@dataclass
class Asset:
    """Represents a cryptographic asset discovered during a scan."""

    asset_type: AssetType
    name: str
    description: str
    confidence: Confidence = Confidence.MEDIUM
    evidence: Optional[Evidence] = None
    fingerprint: str = ""
    metadata: dict = field(default_factory=dict)
    dedup_key: str = ""

    def compute_dedup_key(self) -> str:
        """Compute a stable deduplication key."""
        base = "|".join(
            [
                self.asset_type.value,
                self.name,
                self.fingerprint or "",
                self.evidence.summary() if self.evidence else "",
                self.metadata.get("version", ""),
            ]
        )
        return hashlib.sha256(base.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict:
        """Serialise the asset to a plain dictionary."""
        return {
            "asset_id": self.dedup_key,
            "asset_type": self.asset_type.value,
            "name": self.name,
            "description": self.description,
            "confidence": self.confidence.value,
            "fingerprint": self.fingerprint or None,
            "evidence": self.evidence.to_dict() if self.evidence else {},
            "metadata": self.metadata,
        }
