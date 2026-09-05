from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class MinioDetection:
    status: str  # confirmed | probable | not_minio | transport_failure
    api_endpoint: str | None = None
    console_endpoint: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AnonymousResult:
    api_reachable: bool
    classification: str
    buckets: tuple[str, ...] = ()
    read_probe: str | None = None


@dataclass(frozen=True)
class CredentialResult:
    state: str  # valid | invalid | valid_but_restricted | verification_unavailable | transient_failure
    access_key: str | None = None
    error_code: str | None = None


@dataclass(frozen=True)
class AdminCapability:
    capability: str  # confirmed | partial | not_confirmed | unknown
    identity_kind: str = "unknown"  # root | delegated_admin | s3_user | unknown
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PermissionSummary:
    list_buckets: str = "unknown"
    list_objects: str = "unknown"
    read_objects: str = "unknown"
    write_objects: str = "unknown"
    delete_objects: str = "unknown"
    admin_plane: str = "unknown"
