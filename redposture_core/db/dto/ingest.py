"""DTO used by ingest adapters and services."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ModuleRunCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    module_name: str
    protocol: str
    source_type: str
    execution_status: str = "success"
    tool_version: str | None = None
    target_scope: str | None = None
    commandline_args_snapshot_json: dict[str, Any] | list[Any] | None = None
    started_at: str | None = None
    finished_at: str | None = None
    dedup_key: str | None = None


class ObservationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_text: str | None = None
    canonical_host_key: str | None = None
    hostname: str | None = None
    fqdn: str | None = None
    ip_address: str | None = None
    scheme: str | None = None
    host: str | None = None
    ip: str | None = None
    port: int | None = None
    path: str | None = None
    protocol: str
    service_name: str | None = None
    service_status: str | None = None
    service_version: str | None = None
    auth_required: bool | None = None
    normalized_status: str
    severity: str | None = None
    confidence: str | None = None
    raw_json_result_sanitized: dict[str, Any] | list[Any] | None = None
    normalized_result_json: dict[str, Any] | list[Any] | None = None
    fingerprint_subject: str = "default"


class FindingCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str
    finding_type: str
    protocol: str
    module_name: str
    severity: str | None = None
    confidence: str | None = None
    status: str = "open"
    description: str | None = None
    dedup_subject: str = "default"


class ArtifactCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    artifact_role: str
    mime_type: str = "application/json"
    content_encoding: str = "gzip"
    payload: bytes
    sanitized_preview_text: str | None = None
    expires_at: str | None = None
    purge_after: str | None = None


class EvidenceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_type: str
    title: str
    description: str | None = None
    preview_text: str | None = None
    retention_class: str | None = None
    expires_at: str | None = None
    artifact_index: int | None = None
    finding_index: int | None = None


class ExtensionRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    table_name: str
    values: dict[str, Any] = Field(default_factory=dict)


class IngestEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    module_run: ModuleRunCreate
    observations: list[ObservationCreate]
    findings: list[FindingCreate] = Field(default_factory=list)
    artifacts: list[ArtifactCreate] = Field(default_factory=list)
    evidence: list[EvidenceCreate] = Field(default_factory=list)
    extensions: list[ExtensionRecord] = Field(default_factory=list)
