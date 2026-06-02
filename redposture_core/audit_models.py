"""Typed audit result models shared by staged modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class TargetSpec:
    raw: str
    host: str
    port: int | None = None
    scheme: str | None = None
    path: str = ""
    query: str = ""
    fragment: str = ""
    source: str | None = None
    normalized_key: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw": self.raw,
            "host": self.host,
            "port": self.port,
            "scheme": self.scheme,
            "path": self.path,
            "query": self.query,
            "fragment": self.fragment,
            "source": self.source,
            "normalized_key": self.normalized_key or self.raw,
        }

    @classmethod
    def from_mapping(cls, payload: dict[str, Any]) -> TargetSpec:
        return cls(
            raw=str(payload.get("raw") or payload.get("host") or ""),
            host=str(payload.get("host") or payload.get("raw") or ""),
            port=_optional_int(payload.get("port")),
            scheme=_optional_str(payload.get("scheme")),
            path=str(payload.get("path") or ""),
            query=str(payload.get("query") or ""),
            fragment=str(payload.get("fragment") or ""),
            source=_optional_str(payload.get("source")),
            normalized_key=_optional_str(payload.get("normalized_key")),
        )


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

    @classmethod
    def from_mapping(cls, payload: dict[str, Any]) -> StageTrace:
        return cls(
            stage_name=str(payload.get("stage_name") or payload.get("stage") or "unknown"),
            attempt=int(payload.get("attempt") or 1),
            duration_ms=int(payload.get("duration_ms") or 0),
            result=str(payload.get("result") or "ok"),
            error=_optional_str(payload.get("error")),
        )


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

    @classmethod
    def from_mapping(cls, payload: dict[str, Any]) -> CredentialAttempt:
        return cls(
            username=_optional_str(payload.get("username")),
            password=_optional_str(payload.get("password")),
            token=_optional_str(payload.get("token")),
            ok=_optional_bool(payload.get("ok")),
            error=_optional_str(payload.get("error")),
        )


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
class RenderEvent:
    kind: str
    fields: dict[str, Any] = field(default_factory=dict)
    severity: str | None = None
    payload_role: str | None = None
    message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "kind": self.kind,
            "fields": dict(self.fields),
        }
        if self.severity is not None:
            payload["severity"] = self.severity
        if self.payload_role is not None:
            payload["payload_role"] = self.payload_role
        if self.message is not None:
            payload["message"] = self.message
        return payload

    @classmethod
    def from_mapping(cls, payload: dict[str, Any]) -> RenderEvent:
        fields = payload.get("fields")
        return cls(
            kind=str(payload.get("kind") or "detail"),
            fields=dict(fields) if isinstance(fields, dict) else {},
            severity=_optional_str(payload.get("severity")),
            payload_role=_optional_str(payload.get("payload_role")),
            message=_optional_str(payload.get("message")),
        )


@dataclass(frozen=True)
class AuditRecord:
    host: str
    port: int
    service: str
    status: str
    auth_required: bool | None = None
    module: str | None = None
    target: TargetSpec | str | None = None
    transport: str | None = None
    stages: tuple[StageTrace, ...] = ()
    credentials: tuple[CredentialAttempt, ...] = ()
    capabilities: CapabilitySet | None = None
    render_events: tuple[RenderEvent, ...] = ()
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(
        cls,
        payload: dict[str, Any],
        *,
        module: str | None = None,
        service: str | None = None,
    ) -> AuditRecord:
        """Build a typed record from legacy stage dictionaries.

        This is the compatibility boundary for the ongoing migration: stages can
        still carry legacy dictionaries internally, but shared runtime/output
        code works with the same typed model before serializing back to JSON/TXT.
        Unknown fields stay in `extra`, preserving existing output contracts.
        """

        stages_raw = payload.get("stages")
        credentials_raw = payload.get("credential_attempts") or payload.get("credentials")
        capabilities_raw = payload.get("capabilities")
        render_events_raw = payload.get("render_events")
        target_raw = payload.get("target")
        target: TargetSpec | str | None
        if isinstance(target_raw, dict):
            target = TargetSpec.from_mapping(target_raw)
        elif target_raw is None:
            target = None
        else:
            target = str(target_raw)

        known_fields = {
            "host",
            "port",
            "service",
            "status",
            "auth_required",
            "module",
            "target",
            "transport",
            "stages",
            "credential_attempts",
            "credentials",
            "capabilities",
            "render_events",
        }
        extra = {key: value for key, value in payload.items() if key not in known_fields}
        return cls(
            host=str(payload.get("host") or ""),
            port=int(payload.get("port") or 0),
            service=str(payload.get("service") or service or payload.get("module") or module or ""),
            status=str(payload.get("status") or "unknown"),
            auth_required=_optional_bool(payload.get("auth_required")),
            module=_optional_str(payload.get("module")) or module,
            target=target,
            transport=_optional_str(payload.get("transport") or payload.get("transport_mode")),
            stages=tuple(
                StageTrace.from_mapping(item)
                for item in (stages_raw if isinstance(stages_raw, list) else [])
                if isinstance(item, dict)
            ),
            credentials=tuple(
                CredentialAttempt.from_mapping(item)
                for item in (credentials_raw if isinstance(credentials_raw, list) else [])
                if isinstance(item, dict)
            ),
            capabilities=CapabilitySet(dict(capabilities_raw)) if isinstance(capabilities_raw, dict) else None,
            render_events=tuple(
                RenderEvent.from_mapping(item)
                for item in (render_events_raw if isinstance(render_events_raw, list) else [])
                if isinstance(item, dict)
            ),
            extra=extra,
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "host": self.host,
            "port": int(self.port),
            "service": self.service,
            "status": self.status,
            "auth_required": self.auth_required,
        }
        if self.module is not None:
            payload["module"] = self.module
        if self.transport is not None:
            payload["transport"] = self.transport
        if self.target is not None:
            payload["target"] = self.target.to_dict() if hasattr(self.target, "to_dict") else self.target
        if self.stages:
            payload["stages"] = [stage.to_dict() for stage in self.stages]
        if self.credentials:
            payload["credential_attempts"] = [credential.to_dict() for credential in self.credentials]
        if self.capabilities is not None:
            payload["capabilities"] = self.capabilities.to_dict()
        if self.render_events:
            payload["render_events"] = [event.to_dict() for event in self.render_events]
        payload.update(self.extra)
        return payload


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None


def _optional_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes"}:
            return True
        if lowered in {"false", "0", "no"}:
            return False
    return bool(value)


def _optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    return int(value)


__all__ = [
    "AuditRecord",
    "CapabilitySet",
    "CredentialAttempt",
    "RenderEvent",
    "StageTrace",
    "TargetSpec",
]
