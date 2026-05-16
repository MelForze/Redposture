"""Typed audit result models shared by staged modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class StageTrace:
    stage_name: str
    attempt: int = 1
    duration_ms: int = 0
    result: str = "ok"
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage_name": self.stage_name,
            "attempt": int(self.attempt),
            "duration_ms": int(max(0, self.duration_ms)),
            "result": self.result,
            "error": self.error,
        }


@dataclass(frozen=True)
class CredentialAttempt:
    username: str | None = None
    password: str | None = None
    token: str | None = None
    ok: bool | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "password": self.password,
            "token": self.token,
            "ok": self.ok,
            "error": self.error,
        }


@dataclass(frozen=True)
class CapabilitySet:
    values: dict[str, bool | None] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = dict(self.values)
        if self.error:
            payload["error"] = self.error
        return payload


@dataclass(frozen=True)
class AuditRecord:
    host: str
    port: int
    service: str
    status: str
    auth_required: bool | None = None
    stages: tuple[StageTrace, ...] = ()
    credentials: tuple[CredentialAttempt, ...] = ()
    capabilities: CapabilitySet | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "host": self.host,
            "port": int(self.port),
            "service": self.service,
            "status": self.status,
            "auth_required": self.auth_required,
        }
        if self.stages:
            payload["stages"] = [stage.to_dict() for stage in self.stages]
        if self.credentials:
            payload["credential_attempts"] = [credential.to_dict() for credential in self.credentials]
        if self.capabilities is not None:
            payload["capabilities"] = self.capabilities.to_dict()
        payload.update(self.extra)
        return payload


__all__ = [
    "AuditRecord",
    "CapabilitySet",
    "CredentialAttempt",
    "StageTrace",
]
