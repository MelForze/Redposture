"""Core SQLAlchemy models for the DB subsystem."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Table,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, SoftDeleteMixin, TimestampMixin, utcnow

host_tags = Table(
    "host_tags",
    Base.metadata,
    Column("host_id", ForeignKey("target_hosts.id", ondelete="CASCADE"), primary_key=True),
    Column("tag_id", ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True),
)

endpoint_tags = Table(
    "endpoint_tags",
    Base.metadata,
    Column("endpoint_id", ForeignKey("network_endpoints.id", ondelete="CASCADE"), primary_key=True),
    Column("tag_id", ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True),
)

finding_tags = Table(
    "finding_tags",
    Base.metadata,
    Column("finding_id", ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True),
    Column("tag_id", ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True),
)

run_tags = Table(
    "run_tags",
    Base.metadata,
    Column("module_run_id", ForeignKey("module_runs.id", ondelete="CASCADE"), primary_key=True),
    Column("tag_id", ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True),
)


class Workspace(TimestampMixin, SoftDeleteMixin, Base):
    __tablename__ = "workspaces"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    slug: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    client_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    environment_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)


class AppState(Base):
    __tablename__ = "app_state"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class AppMetadata(Base):
    __tablename__ = "app_metadata"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class TargetHost(TimestampMixin, SoftDeleteMixin, Base):
    __tablename__ = "target_hosts"
    __table_args__ = (
        UniqueConstraint("workspace_id", "canonical_key", name="uq_target_host_workspace_canonical"),
        Index("ix_target_hosts_workspace_last_seen", "workspace_id", "last_seen_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    canonical_key: Mapped[str] = mapped_column(String(512), nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    fqdn: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    workspace: Mapped[Workspace] = relationship("Workspace")
    endpoints: Mapped[list[NetworkEndpoint]] = relationship("NetworkEndpoint", back_populates="target_host")
    tags: Mapped[list[Tag]] = relationship("Tag", secondary=host_tags, back_populates="hosts")


class NetworkEndpoint(TimestampMixin, SoftDeleteMixin, Base):
    __tablename__ = "network_endpoints"
    __table_args__ = (
        UniqueConstraint("workspace_id", "canonical_key", name="uq_endpoint_workspace_canonical"),
        Index("ix_network_endpoints_workspace_port", "workspace_id", "port"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    target_host_id: Mapped[int | None] = mapped_column(
        ForeignKey("target_hosts.id", ondelete="SET NULL"), nullable=True
    )
    canonical_key: Mapped[str] = mapped_column(String(1024), nullable=False)
    scheme: Mapped[str | None] = mapped_column(String(32), nullable=True)
    host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    netloc: Mapped[str | None] = mapped_column(String(512), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    workspace: Mapped[Workspace] = relationship("Workspace")
    target_host: Mapped[TargetHost | None] = relationship("TargetHost", back_populates="endpoints")
    services: Mapped[list[ProtocolService]] = relationship("ProtocolService", back_populates="endpoint")
    tags: Mapped[list[Tag]] = relationship("Tag", secondary=endpoint_tags, back_populates="endpoints")


class ProtocolService(TimestampMixin, SoftDeleteMixin, Base):
    __tablename__ = "protocol_services"
    __table_args__ = (
        UniqueConstraint(
            "workspace_id",
            "protocol",
            "endpoint_id",
            "service_name",
            name="uq_protocol_service_workspace_endpoint",
        ),
        Index(
            "uq_protocol_service_workspace_null_endpoint",
            "workspace_id",
            "protocol",
            "service_name",
            unique=True,
            sqlite_where=text("endpoint_id IS NULL"),
            postgresql_where=text("endpoint_id IS NULL"),
        ),
        Index("ix_protocol_services_workspace_protocol", "workspace_id", "protocol"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    endpoint_id: Mapped[int | None] = mapped_column(
        ForeignKey("network_endpoints.id", ondelete="SET NULL"), nullable=True
    )
    protocol: Mapped[str] = mapped_column(String(64), nullable=False)
    service_name: Mapped[str] = mapped_column(String(128), nullable=False)
    auth_required: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    status: Mapped[str | None] = mapped_column(String(64), nullable=True)
    version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    extra_summary_json: Mapped[dict | list | None] = mapped_column(JSON, nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    workspace: Mapped[Workspace] = relationship("Workspace")
    endpoint: Mapped[NetworkEndpoint | None] = relationship("NetworkEndpoint", back_populates="services")


class ModuleRun(TimestampMixin, SoftDeleteMixin, Base):
    __tablename__ = "module_runs"
    __table_args__ = (
        Index("ix_module_runs_workspace_module", "workspace_id", "module_name"),
        Index("ix_module_runs_workspace_protocol", "workspace_id", "protocol"),
        Index("ix_module_runs_workspace_status", "workspace_id", "execution_status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    import_job_id: Mapped[int | None] = mapped_column(ForeignKey("import_jobs.id", ondelete="SET NULL"), nullable=True)
    module_name: Mapped[str] = mapped_column(String(64), nullable=False)
    protocol: Mapped[str] = mapped_column(String(64), nullable=False)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    target_scope: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    execution_status: Mapped[str] = mapped_column(String(32), nullable=False, default="running")
    tool_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    commandline_args_snapshot_json: Mapped[dict | list | None] = mapped_column(JSON, nullable=True)
    runner_hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    operator_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    dedup_key: Mapped[str | None] = mapped_column(String(128), nullable=True)

    workspace: Mapped[Workspace] = relationship("Workspace")
    observations: Mapped[list[RunObservation]] = relationship("RunObservation", back_populates="module_run")
    findings: Mapped[list[Finding]] = relationship("Finding", back_populates="module_run")
    evidence_items: Mapped[list[Evidence]] = relationship("Evidence", back_populates="module_run")
    artifacts: Mapped[list[Artifact]] = relationship("Artifact", back_populates="module_run")
    tags: Mapped[list[Tag]] = relationship("Tag", secondary=run_tags, back_populates="module_runs")


class RunObservation(TimestampMixin, SoftDeleteMixin, Base):
    __tablename__ = "run_observations"
    __table_args__ = (
        UniqueConstraint("workspace_id", "fingerprint", name="uq_run_observations_workspace_fingerprint"),
        Index("ix_run_observations_workspace_protocol", "workspace_id", "protocol"),
        Index("ix_run_observations_workspace_module", "workspace_id", "module_name"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    module_run_id: Mapped[int] = mapped_column(ForeignKey("module_runs.id", ondelete="CASCADE"), nullable=False)
    target_host_id: Mapped[int | None] = mapped_column(
        ForeignKey("target_hosts.id", ondelete="SET NULL"), nullable=True
    )
    endpoint_id: Mapped[int | None] = mapped_column(
        ForeignKey("network_endpoints.id", ondelete="SET NULL"), nullable=True
    )
    protocol_service_id: Mapped[int | None] = mapped_column(
        ForeignKey("protocol_services.id", ondelete="SET NULL"), nullable=True
    )
    target_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    module_name: Mapped[str] = mapped_column(String(64), nullable=False)
    protocol: Mapped[str] = mapped_column(String(64), nullable=False)
    normalized_status: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    confidence: Mapped[str | None] = mapped_column(String(32), nullable=True)
    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    raw_json_result_sanitized: Mapped[dict | list | None] = mapped_column(JSON, nullable=True)
    normalized_result_json: Mapped[dict | list | None] = mapped_column(JSON, nullable=True)

    workspace: Mapped[Workspace] = relationship("Workspace")
    module_run: Mapped[ModuleRun] = relationship("ModuleRun", back_populates="observations")
    target_host: Mapped[TargetHost | None] = relationship("TargetHost")
    endpoint: Mapped[NetworkEndpoint | None] = relationship("NetworkEndpoint")
    protocol_service: Mapped[ProtocolService | None] = relationship("ProtocolService")
    findings: Mapped[list[Finding]] = relationship("Finding", back_populates="run_observation")


class Finding(TimestampMixin, SoftDeleteMixin, Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("workspace_id", "fingerprint", name="uq_findings_workspace_fingerprint"),
        Index("ix_findings_workspace_module", "workspace_id", "module_name"),
        Index("ix_findings_workspace_protocol", "workspace_id", "protocol"),
        Index("ix_findings_workspace_severity", "workspace_id", "severity"),
        Index("ix_findings_workspace_status", "workspace_id", "status"),
        Index("ix_findings_workspace_last_seen", "workspace_id", "last_seen_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    module_run_id: Mapped[int | None] = mapped_column(ForeignKey("module_runs.id", ondelete="SET NULL"), nullable=True)
    run_observation_id: Mapped[int | None] = mapped_column(
        ForeignKey("run_observations.id", ondelete="SET NULL"), nullable=True
    )
    target_host_id: Mapped[int | None] = mapped_column(
        ForeignKey("target_hosts.id", ondelete="SET NULL"), nullable=True
    )
    endpoint_id: Mapped[int | None] = mapped_column(
        ForeignKey("network_endpoints.id", ondelete="SET NULL"), nullable=True
    )
    protocol_service_id: Mapped[int | None] = mapped_column(
        ForeignKey("protocol_services.id", ondelete="SET NULL"), nullable=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    finding_type: Mapped[str] = mapped_column(String(128), nullable=False)
    protocol: Mapped[str] = mapped_column(String(64), nullable=False)
    module_name: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    confidence: Mapped[str | None] = mapped_column(String(32), nullable=True)
    status: Mapped[str] = mapped_column(String(64), nullable=False, default="open")
    dedup_key: Mapped[str | None] = mapped_column(String(128), nullable=True)
    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    workspace: Mapped[Workspace] = relationship("Workspace")
    module_run: Mapped[ModuleRun | None] = relationship("ModuleRun", back_populates="findings")
    run_observation: Mapped[RunObservation | None] = relationship("RunObservation", back_populates="findings")
    target_host: Mapped[TargetHost | None] = relationship("TargetHost")
    endpoint: Mapped[NetworkEndpoint | None] = relationship("NetworkEndpoint")
    protocol_service: Mapped[ProtocolService | None] = relationship("ProtocolService")
    evidence_items: Mapped[list[Evidence]] = relationship("Evidence", back_populates="finding")
    tags: Mapped[list[Tag]] = relationship("Tag", secondary=finding_tags, back_populates="findings")


class Artifact(TimestampMixin, SoftDeleteMixin, Base):
    __tablename__ = "artifacts"
    __table_args__ = (Index("ix_artifacts_workspace_role", "workspace_id", "artifact_role"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    module_run_id: Mapped[int | None] = mapped_column(ForeignKey("module_runs.id", ondelete="SET NULL"), nullable=True)
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"), nullable=True)
    artifact_role: Mapped[str] = mapped_column(String(64), nullable=False)
    mime_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    content_encoding: Mapped[str | None] = mapped_column(String(64), nullable=True)
    sha256: Mapped[str] = mapped_column(String(128), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sanitized_preview_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    content_blob: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    purge_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    workspace: Mapped[Workspace] = relationship("Workspace")
    module_run: Mapped[ModuleRun | None] = relationship("ModuleRun", back_populates="artifacts")
    finding: Mapped[Finding | None] = relationship("Finding")
    evidence_items: Mapped[list[Evidence]] = relationship("Evidence", back_populates="artifact")


class Evidence(TimestampMixin, SoftDeleteMixin, Base):
    __tablename__ = "evidence"
    __table_args__ = (Index("ix_evidence_workspace_collected", "workspace_id", "collected_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    module_run_id: Mapped[int] = mapped_column(ForeignKey("module_runs.id", ondelete="CASCADE"), nullable=False)
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"), nullable=True)
    artifact_id: Mapped[int | None] = mapped_column(ForeignKey("artifacts.id", ondelete="SET NULL"), nullable=True)
    evidence_type: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    preview_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    retention_class: Mapped[str | None] = mapped_column(String(64), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    workspace: Mapped[Workspace] = relationship("Workspace")
    module_run: Mapped[ModuleRun] = relationship("ModuleRun", back_populates="evidence_items")
    finding: Mapped[Finding | None] = relationship("Finding", back_populates="evidence_items")
    artifact: Mapped[Artifact | None] = relationship("Artifact", back_populates="evidence_items")


class Tag(TimestampMixin, Base):
    __tablename__ = "tags"
    __table_args__ = (UniqueConstraint("workspace_id", "name", name="uq_tags_workspace_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    color: Mapped[str | None] = mapped_column(String(32), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    workspace: Mapped[Workspace] = relationship("Workspace")
    hosts: Mapped[list[TargetHost]] = relationship("TargetHost", secondary=host_tags, back_populates="tags")
    endpoints: Mapped[list[NetworkEndpoint]] = relationship(
        "NetworkEndpoint", secondary=endpoint_tags, back_populates="tags"
    )
    findings: Mapped[list[Finding]] = relationship("Finding", secondary=finding_tags, back_populates="tags")
    module_runs: Mapped[list[ModuleRun]] = relationship("ModuleRun", secondary=run_tags, back_populates="tags")


class Note(TimestampMixin, SoftDeleteMixin, Base):
    __tablename__ = "notes"
    __table_args__ = (
        CheckConstraint(
            "CASE WHEN target_host_id IS NOT NULL THEN 1 ELSE 0 END + "
            "CASE WHEN endpoint_id IS NOT NULL THEN 1 ELSE 0 END + "
            "CASE WHEN finding_id IS NOT NULL THEN 1 ELSE 0 END + "
            "CASE WHEN module_run_id IS NOT NULL THEN 1 ELSE 0 END + "
            "CASE WHEN artifact_id IS NOT NULL THEN 1 ELSE 0 END = 1",
            name="ck_notes_single_parent",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    target_host_id: Mapped[int | None] = mapped_column(ForeignKey("target_hosts.id", ondelete="CASCADE"), nullable=True)
    endpoint_id: Mapped[int | None] = mapped_column(
        ForeignKey("network_endpoints.id", ondelete="CASCADE"), nullable=True
    )
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), nullable=True)
    module_run_id: Mapped[int | None] = mapped_column(ForeignKey("module_runs.id", ondelete="CASCADE"), nullable=True)
    artifact_id: Mapped[int | None] = mapped_column(ForeignKey("artifacts.id", ondelete="CASCADE"), nullable=True)
    title: Mapped[str | None] = mapped_column(String(255), nullable=True)
    body: Mapped[str] = mapped_column(Text, nullable=False)


class ImportJob(TimestampMixin, SoftDeleteMixin, Base):
    __tablename__ = "import_jobs"
    __table_args__ = (Index("ix_import_jobs_workspace_status", "workspace_id", "status"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    module_name: Mapped[str] = mapped_column(String(64), nullable=False)
    source_format: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    input_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    stats_json: Mapped[dict | list | None] = mapped_column(JSON, nullable=True)
    error_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ExportJob(TimestampMixin, SoftDeleteMixin, Base):
    __tablename__ = "export_jobs"
    __table_args__ = (Index("ix_export_jobs_workspace_status", "workspace_id", "status"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    export_kind: Mapped[str] = mapped_column(String(64), nullable=False)
    output_format: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    output_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    stats_json: Mapped[dict | list | None] = mapped_column(JSON, nullable=True)
    error_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class SecretRef(TimestampMixin, Base):
    __tablename__ = "secret_refs"
    __table_args__ = (UniqueConstraint("workspace_id", "fingerprint", name="uq_secret_refs_workspace_fingerprint"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    secret_kind: Mapped[str] = mapped_column(String(128), nullable=False)
    redacted_value: Mapped[str] = mapped_column(Text, nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    source_hint: Mapped[str | None] = mapped_column(Text, nullable=True)


class SearchDocument(Base):
    __tablename__ = "search_documents"
    __table_args__ = (
        UniqueConstraint("workspace_id", "entity_type", "entity_id", name="uq_search_documents_entity"),
        Index("ix_search_documents_workspace_entity", "workspace_id", "entity_type"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str | None] = mapped_column(Text, nullable=True)
    body: Mapped[str | None] = mapped_column(Text, nullable=True)
    tags_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )
