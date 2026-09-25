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
    dags_allowed: bool | None = None
    auth_method: str | None = None  # native | sso
    sso_provider: str | None = None
    sso_protocol: str | None = None
    sso_evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class CredentialResult:
    state: str  # valid | valid_but_restricted | invalid | transient_failure | verification_unavailable
    username: str | None = None
    error_code: str | None = None
    bearer_token: str | None = None  # 3.x JWT, kept in-memory only (never serialized)


@dataclass(frozen=True)
class ResourceAccess:
    status: str  # allowed | denied | unknown
    count: int | None = None
    http_status: int | None = None
    error: str | None = None


@dataclass(frozen=True)
class AirflowCapabilities:
    dags: ResourceAccess
    keys: ResourceAccess
    connections: ResourceAccess


__all__ = ["AirflowCapabilities", "AirflowDetection", "AnonymousResult", "CredentialResult", "ResourceAccess"]
