"""Secret reference helpers."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class SecretCandidate:
    secret_kind: str
    raw_value: str
    redacted_value: str
    source_hint: str | None = None


@dataclass(frozen=True)
class SecretRefData:
    secret_kind: str
    redacted_value: str
    fingerprint: str
    source_hint: str | None = None


def build_secret_ref(candidate: SecretCandidate) -> SecretRefData:
    """Create secret reference data from an in-memory secret candidate."""
    fingerprint = hashlib.sha256(candidate.raw_value.encode("utf-8")).hexdigest()
    return SecretRefData(
        secret_kind=candidate.secret_kind,
        redacted_value=candidate.redacted_value,
        fingerprint=fingerprint,
        source_hint=candidate.source_hint,
    )
