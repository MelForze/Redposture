"""Query/view DTOs for DB CLI and services."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict


class WorkspaceView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    slug: str
    display_name: str
    client_name: str | None = None
    environment_name: str | None = None
    is_archived: bool


class HostView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    canonical_key: str
    hostname: str | None = None
    fqdn: str | None = None
    ip_address: str | None = None
    last_seen_at: Any


class EndpointView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    canonical_key: str
    scheme: str | None = None
    host: str | None = None
    ip: str | None = None
    port: int | None = None
    path: str | None = None


class RunView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    module_name: str
    protocol: str
    source_type: str
    execution_status: str
    started_at: Any
    finished_at: Any | None = None


class ArtifactView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    artifact_role: str
    mime_type: str | None = None
    content_encoding: str | None = None
    sha256: str
    size_bytes: int
    sanitized_preview_text: str | None = None


class ModuleSummaryView(BaseModel):
    module: str
    hosts_count: int
    endpoints_count: int
    findings_count: int
    runs_count: int
    artifacts_count: int
    last_seen_at: Any | None = None


class ModuleOverviewView(ModuleSummaryView):
    records_count: int


class ModuleDashboardView(BaseModel):
    module: str
    summary: ModuleSummaryView
    findings: list[FindingView]
    hosts: list[HostView]
    endpoints: list[EndpointView]
    runs: list[RunView]


class ModuleRecentHitView(BaseModel):
    module: str
    target: str | None = None
    subject: str
    phase: str
    finding_type: str | None = None
    status: str | None = None
    severity: str | None = None
    seen_at: Any | None = None
    endpoint_or_resource: str | None = None
    endpoint_or_resource_label: str | None = None
    detail: str | None = None
    detail_label: str | None = None
    title: str


class ModuleRecentHitsView(BaseModel):
    module: str
    recent_hits: list[ModuleRecentHitView]
    shown: int
    limit: int


class ModuleStageRecordView(BaseModel):
    module: str
    primary_line: str
    detail_lines: list[str] = []
    seen_at: Any | None = None


class ExporterStageFindingView(BaseModel):
    phase_tag: str
    host: str
    port: int | None = None
    exporter_display_name: str
    endpoint: str | None = None
    callback_target: str | None = None
    url: str | None = None
    reason: str
    sample: str | None = None
    detail: str | None = None
    seen_at: Any | None = None


class DatabaseTotalsView(BaseModel):
    hosts_count: int
    endpoints_count: int
    findings_count: int
    runs_count: int
    artifacts_count: int
    import_jobs_count: int
    export_jobs_count: int
    last_seen_at: Any | None = None


class DatabaseOverviewView(BaseModel):
    totals: DatabaseTotalsView
    modules: list[ModuleOverviewView]


ExporterRecentHitView = ModuleRecentHitView


class FindingView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    description: str | None = None
    finding_type: str
    protocol: str
    module_name: str
    target: str | None = None
    endpoint: str | None = None
    severity: str | None = None
    confidence: str | None = None
    status: str
    last_seen_at: Any


class FindingFilter(BaseModel):
    module_name: str | None = None
    protocol: str | None = None
    severity: str | None = None
    status: str | None = None
    tag: str | None = None
    date_from: str | None = None
    date_to: str | None = None
