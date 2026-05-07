"""Asset models for CBOM discovery."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict

from crypto_recon.models.evidence import Evidence


class AssetType(Enum):
    """Supported CBOM asset categories."""

    CERTIFICATE = "certificate"
    TLS_PROTOCOL = "tls_protocol"
    TLS_CIPHER_SUITE = "tls_cipher_suite"
    CRYPTO_ALGORITHM = "crypto_algorithm"
    SECRET_REFERENCE = "secret_reference"
    DEPENDENCY = "dependency"
    ENDPOINT = "endpoint"


class Confidence(Enum):
    """Confidence levels for assets and findings."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Asset:
    """Represents a discovered cryptographic or service asset."""

    asset_type: AssetType
    name: str
    description: str = ""
    confidence: Confidence = Confidence.MEDIUM
    evidence: Evidence = field(default_factory=Evidence)
    fingerprint: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def dedup_key(self) -> str:
        """Return a stable deduplication key for this asset."""
        payload = {
            "asset_type": self.asset_type.value,
            "name": self.name,
            "fingerprint": self.fingerprint,
            "evidence": self.evidence.to_dict(),
        }
        encoded = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def to_dict(self) -> dict:
        """Serialize the asset to a plain dictionary."""
        data: dict[str, Any] = {
            "asset_type": self.asset_type.value,
            "name": self.name,
            "description": self.description,
            "confidence": self.confidence.value,
            "evidence": self.evidence.to_dict(),
            "fingerprint": self.fingerprint,
            "metadata": self.metadata,
            "dedup_key": self.dedup_key(),
        }
        return data
