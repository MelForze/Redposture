"""Typed results for the Airflow audit module."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class AirflowDetection:
    status: str  # confirmed | probable | not_airflow | transport_failure
    api_generation: str | None = None  # "v1" (Airflow 2.x) | "v2" (Airflow 3.x)
    version: str | None = None
    api_endpoint: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AnonymousResult:
    reachable: bool
    auth_required: bool | None = None
    role: str = "unknown"  # none | viewer | op | admin | unknown


@dataclass(frozen=True)
class CredentialResult:
    state: str  # valid | valid_but_restricted | invalid | transient_failure | verification_unavailable
    username: str | None = None
    error_code: str | None = None
    bearer_token: str | None = None  # 3.x JWT, kept in-memory only (never serialized)


@dataclass(frozen=True)
class RoleCapability:
    role: str = "unknown"  # none | viewer | op | admin | unknown
    evidence: dict[str, Any] = field(default_factory=dict)


__all__ = ["AirflowDetection", "AnonymousResult", "CredentialResult", "RoleCapability"]
