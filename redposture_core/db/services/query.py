"""Query and search services."""

from __future__ import annotations

import re

from sqlalchemy import func, select
from sqlalchemy.orm import selectinload, sessionmaker

from ...stage_clickhouse import (
    _format_auth_attempt_detail_records as _clickhouse_auth_attempt_details,
)
from ...stage_clickhouse import (
    _format_databases_detail_records as _clickhouse_databases_details,
)
from ...stage_clickhouse import (
    _format_detect_record as _clickhouse_detect_record,
)
from ...stage_clickhouse import (
    _format_execute_detail_records as _clickhouse_execute_details,
)
from ...stage_clickhouse import (
    _format_record as _clickhouse_format_record,
)
from ...stage_clickhouse import (
    _format_sql_detail_records as _clickhouse_sql_details,
)
from ...stage_clickhouse import (
    _format_table_columns_detail_records as _clickhouse_table_columns_details,
)
from ...stage_clickhouse import (
    _format_table_dump_detail_records as _clickhouse_table_dump_details,
)
from ...stage_clickhouse import (
    _format_tables_detail_records as _clickhouse_tables_details,
)
from ...stage_consul import (
    _auth_summary_line as _consul_auth_summary_line,
)
from ...stage_consul import (
    _cx_prefix as _consul_prefix,
)
from ...stage_consul import (
    _detail_lines as _consul_detail_lines,
)
from ...stage_consul import (
    _detect_line as _consul_detect_line,
)
from ...stage_consul import (
    _summary_line as _consul_summary_line,
)
from ...stage_etcd import (
    _format_detect_record as _etcd_detect_record,
)
from ...stage_etcd import (
    _format_keys_detail_records as _etcd_keys_details,
)
from ...stage_etcd import (
    _format_record as _etcd_format_record,
)
from ...stage_gitlab import _format_detail_records as _gitlab_detail_records
from ...stage_gitlab import _format_record as _gitlab_format_record
from ...stage_grafana import (
    _format_auth_attempt_detail_records as _grafana_auth_details,
)
from ...stage_grafana import (
    _format_check_detail_records as _grafana_check_details,
)
from ...stage_grafana import (
    _format_datasources_detail_records as _grafana_datasource_details,
)
from ...stage_grafana import (
    _format_detect_record as _grafana_detect_record,
)
from ...stage_grafana import (
    _format_record as _grafana_format_record,
)
from ...stage_kafka import (
    _format_detect_record as _kafka_detect_record,
)
from ...stage_kafka import (
    _format_record as _kafka_format_record,
)
from ...stage_kafka import (
    _format_topics_detail_records as _kafka_topics_details,
)
from ...stage_kubeapi import (
    _format_detail_records as _kubeapi_detail_records,
)
from ...stage_kubeapi import (
    _format_detect_record as _kubeapi_detect_record,
)
from ...stage_kubeapi import (
    _kxc_prefix as _kubeapi_prefix,
)
from ...stage_kubeapi import (
    _status_summary_line as _kubeapi_status_summary_line,
)
from ...stage_postgres import (
    _format_databases_detail_records as _postgres_databases_details,
)
from ...stage_postgres import (
    _format_detect_record as _postgres_detect_record,
)
from ...stage_postgres import (
    _format_execute_detail_records as _postgres_execute_details,
)
from ...stage_postgres import (
    _format_record as _postgres_format_record,
)
from ...stage_postgres import (
    _format_sql_detail_records as _postgres_sql_details,
)
from ...stage_postgres import (
    _format_table_columns_detail_records as _postgres_table_columns_details,
)
from ...stage_postgres import (
    _format_table_dump_detail_records as _postgres_table_dump_details,
)
from ...stage_postgres import (
    _format_table_row_count_detail_records as _postgres_table_row_count_details,
)
from ...stage_postgres import (
    _format_tables_detail_records as _postgres_tables_details,
)
from ...stage_proxmox import (
    _format_add_user_detail_records as _proxmox_add_user_details,
)
from ...stage_proxmox import (
    _format_detect_record as _proxmox_detect_record,
)
from ...stage_proxmox import (
    _format_discovered_urls_detail_records as _proxmox_discovered_urls_details,
)
from ...stage_proxmox import (
    _format_findings_detail_records as _proxmox_findings_details,
)
from ...stage_proxmox import (
    _format_nodes_detail_records as _proxmox_nodes_details,
)
from ...stage_proxmox import (
    _format_record as _proxmox_format_record,
)
from ...stage_proxmox import (
    _format_users_detail_records as _proxmox_users_details,
)
from ...stage_qdrant import _format_detail_records as _qdrant_detail_records
from ...stage_qdrant import _format_detect_record as _qdrant_detect_record
from ...stage_qdrant import _format_record as _qdrant_format_record
from ...stage_redis import (
    _format_detect_record as _redis_detect_record,
)
from ...stage_redis import (
    _format_keys_detail_records as _redis_keys_details,
)
from ...stage_redis import (
    _format_record as _redis_format_record,
)
from ...stage_registry import _format_detail_records as _registry_detail_records
from ...stage_registry import _format_detect_record as _registry_detect_record
from ...stage_registry import _format_record as _registry_format_record
from ...stage_validate import _exporter_display_name as _stage_validate_exporter_display_name
from ...stage_zookeeper import (
    _format_detect_record as _zookeeper_detect_record,
)
from ...stage_zookeeper import (
    _format_record as _zookeeper_format_record,
)
from ...stage_zookeeper import (
    _format_znodes_detail_records as _zookeeper_znodes_details,
)
from ..dto.query import (
    ArtifactView,
    DatabaseOverviewView,
    DatabaseTotalsView,
    EndpointView,
    ExporterStageFindingView,
    FindingFilter,
    FindingView,
    HostView,
    ModuleDashboardView,
    ModuleOverviewView,
    ModuleRecentHitView,
    ModuleStageRecordView,
    ModuleSummaryView,
    RunView,
)
from ..models import (
    Artifact,
    ExportJob,
    Finding,
    ImportJob,
    ModuleRun,
    NetworkEndpoint,
    ProtocolService,
    RunObservation,
    TargetHost,
)
from ..repositories import (
    ArtifactRepository,
    EndpointRepository,
    FindingRepository,
    HostRepository,
    ModuleRunRepository,
    SearchRepository,
)
from ..session import session_scope


class QueryService:
    MODULE_DASHBOARD_LIMIT = 5
    MODULE_RECENT_HITS_LIMIT = 10
    EXPORTER_RECENT_HITS_LIMIT = MODULE_RECENT_HITS_LIMIT

    def __init__(self, session_factory: sessionmaker) -> None:
        self.session_factory = session_factory

    def list_hosts(self, *, workspace_id: int, module_name: str | None = None) -> list[HostView]:
        with session_scope(self.session_factory, read_only=True) as session:
            return [
                HostView.model_validate(item)
                for item in HostRepository(session).list(workspace_id=workspace_id, module_name=module_name)
            ]

    def list_endpoints(
        self,
        *,
        workspace_id: int,
        host_id: int | None = None,
        module_name: str | None = None,
    ) -> list[EndpointView]:
        with session_scope(self.session_factory, read_only=True) as session:
            return [
                EndpointView.model_validate(item)
                for item in EndpointRepository(session).list(
                    workspace_id=workspace_id,
                    host_id=host_id,
                    module_name=module_name,
                )
            ]

    def list_findings(self, *, workspace_id: int, filters: FindingFilter | None = None) -> list[FindingView]:
        with session_scope(self.session_factory, read_only=True) as session:
            return [
                FindingView(
                    id=item.id,
                    title=item.title,
                    description=item.description,
                    finding_type=item.finding_type,
                    protocol=item.protocol,
                    module_name=item.module_name,
                    target=_host_value(item.target_host),
                    endpoint=item.endpoint.canonical_key if item.endpoint is not None else None,
                    severity=item.severity,
                    confidence=item.confidence,
                    status=item.status,
                    last_seen_at=item.last_seen_at,
                )
                for item in FindingRepository(session).list(workspace_id=workspace_id, filters=filters)
            ]

    def list_runs(
        self,
        *,
        workspace_id: int,
        target_text: str | None = None,
        module_name: str | None = None,
    ) -> list[RunView]:
        with session_scope(self.session_factory, read_only=True) as session:
            return [
                RunView.model_validate(item)
                for item in ModuleRunRepository(session).list(
                    workspace_id=workspace_id,
                    target_text=target_text,
                    module_name=module_name,
                )
            ]

    def list_artifacts(
        self,
        *,
        workspace_id: int,
        module_run_id: int | None = None,
        module_name: str | None = None,
    ) -> list[ArtifactView]:
        with session_scope(self.session_factory, read_only=True) as session:
            return [
                ArtifactView.model_validate(item)
                for item in ArtifactRepository(session).list(
                    workspace_id=workspace_id,
                    module_run_id=module_run_id,
                    module_name=module_name,
                )
            ]

    def get_module_summary(self, *, workspace_id: int, module_name: str) -> ModuleSummaryView:
        with session_scope(self.session_factory, read_only=True) as session:
            hosts_count = session.scalar(
                select(func.count(func.distinct(TargetHost.id)))
                .join(RunObservation, RunObservation.target_host_id == TargetHost.id)
                .where(
                    TargetHost.workspace_id == workspace_id,
                    TargetHost.deleted_at.is_(None),
                    RunObservation.workspace_id == workspace_id,
                    RunObservation.module_name == module_name,
                    RunObservation.deleted_at.is_(None),
                )
            )
            endpoints_count = session.scalar(
                select(func.count(func.distinct(NetworkEndpoint.id)))
                .join(RunObservation, RunObservation.endpoint_id == NetworkEndpoint.id)
                .where(
                    NetworkEndpoint.workspace_id == workspace_id,
                    NetworkEndpoint.deleted_at.is_(None),
                    RunObservation.workspace_id == workspace_id,
                    RunObservation.module_name == module_name,
                    RunObservation.deleted_at.is_(None),
                )
            )
            findings_count = session.scalar(
                select(func.count(Finding.id)).where(
                    Finding.workspace_id == workspace_id,
                    Finding.module_name == module_name,
                    Finding.deleted_at.is_(None),
                )
            )
            runs_count = session.scalar(
                select(func.count(ModuleRun.id)).where(
                    ModuleRun.workspace_id == workspace_id,
                    ModuleRun.module_name == module_name,
                    ModuleRun.deleted_at.is_(None),
                )
            )
            artifacts_count = session.scalar(
                select(func.count(Artifact.id))
                .join(ModuleRun, ModuleRun.id == Artifact.module_run_id)
                .where(
                    Artifact.workspace_id == workspace_id,
                    Artifact.deleted_at.is_(None),
                    ModuleRun.workspace_id == workspace_id,
                    ModuleRun.module_name == module_name,
                    ModuleRun.deleted_at.is_(None),
                )
            )
            observation_last_seen = session.scalar(
                select(func.max(RunObservation.updated_at)).where(
                    RunObservation.workspace_id == workspace_id,
                    RunObservation.module_name == module_name,
                    RunObservation.deleted_at.is_(None),
                )
            )
            finding_last_seen = session.scalar(
                select(func.max(Finding.last_seen_at)).where(
                    Finding.workspace_id == workspace_id,
                    Finding.module_name == module_name,
                    Finding.deleted_at.is_(None),
                )
            )
        timestamps = [value for value in (observation_last_seen, finding_last_seen) if value is not None]
        return ModuleSummaryView(
            module=module_name,
            hosts_count=int(hosts_count or 0),
            endpoints_count=int(endpoints_count or 0),
            findings_count=int(findings_count or 0),
            runs_count=int(runs_count or 0),
            artifacts_count=int(artifacts_count or 0),
            last_seen_at=max(timestamps) if timestamps else None,
        )

    def get_module_dashboard(self, *, workspace_id: int, module_name: str) -> ModuleDashboardView:
        summary = self.get_module_summary(workspace_id=workspace_id, module_name=module_name)
        findings = self.list_findings(
            workspace_id=workspace_id,
            filters=FindingFilter(module_name=module_name),
        )[: self.MODULE_DASHBOARD_LIMIT]
        hosts = self.list_hosts(workspace_id=workspace_id, module_name=module_name)[: self.MODULE_DASHBOARD_LIMIT]
        endpoints = self.list_endpoints(workspace_id=workspace_id, module_name=module_name)[
            : self.MODULE_DASHBOARD_LIMIT
        ]
        runs = self.list_runs(workspace_id=workspace_id, module_name=module_name)[: self.MODULE_DASHBOARD_LIMIT]
        return ModuleDashboardView(
            module=module_name,
            summary=summary,
            findings=findings,
            hosts=hosts,
            endpoints=endpoints,
            runs=runs,
        )

    def list_recent_module_hits(
        self,
        *,
        workspace_id: int,
        module_name: str,
        limit: int | None = None,
    ) -> list[ModuleRecentHitView]:
        max_items = max(1, int(limit or self.MODULE_RECENT_HITS_LIMIT))
        candidate_limit = max(max_items * 5, 50)
        with session_scope(self.session_factory, read_only=True) as session:
            findings_stmt = (
                select(Finding)
                .options(
                    selectinload(Finding.run_observation).selectinload(RunObservation.module_run),
                    selectinload(Finding.run_observation).selectinload(RunObservation.target_host),
                    selectinload(Finding.run_observation).selectinload(RunObservation.endpoint),
                    selectinload(Finding.run_observation).selectinload(RunObservation.protocol_service),
                    selectinload(Finding.module_run),
                    selectinload(Finding.target_host),
                    selectinload(Finding.endpoint),
                    selectinload(Finding.protocol_service),
                )
                .where(
                    Finding.workspace_id == workspace_id,
                    Finding.module_name == module_name,
                    Finding.deleted_at.is_(None),
                )
                .order_by(Finding.last_seen_at.desc())
                .limit(candidate_limit)
            )
            findings = list(session.scalars(findings_stmt).unique())

            finding_hits = [
                item for item in (_finding_to_recent_hit(finding) for finding in findings) if item is not None
            ]
            if finding_hits:
                return finding_hits[:max_items]

            observations_stmt = (
                select(RunObservation)
                .options(
                    selectinload(RunObservation.module_run),
                    selectinload(RunObservation.target_host),
                    selectinload(RunObservation.endpoint),
                    selectinload(RunObservation.protocol_service),
                    selectinload(RunObservation.findings),
                )
                .where(
                    RunObservation.workspace_id == workspace_id,
                    RunObservation.module_name == module_name,
                    RunObservation.deleted_at.is_(None),
                )
                .order_by(RunObservation.updated_at.desc())
                .limit(candidate_limit)
            )
            observations = list(session.scalars(observations_stmt).unique())

            observation_hits: list[ModuleRecentHitView] = []
            for observation in observations:
                hit = _observation_to_recent_hit(observation)
                if hit is None:
                    continue
                observation_hits.append(hit)
                if len(observation_hits) >= max_items:
                    break
            if observation_hits:
                return observation_hits

            runs_stmt = (
                select(ModuleRun)
                .where(
                    ModuleRun.workspace_id == workspace_id,
                    ModuleRun.module_name == module_name,
                    ModuleRun.deleted_at.is_(None),
                )
                .order_by(ModuleRun.finished_at.desc(), ModuleRun.started_at.desc())
                .limit(candidate_limit)
            )
            runs = list(session.scalars(runs_stmt).unique())

            run_hits: list[ModuleRecentHitView] = []
            for run in runs:
                hit = _run_to_recent_hit(run)
                if hit is None:
                    continue
                run_hits.append(hit)
                if len(run_hits) >= max_items:
                    break
            return run_hits

    def list_module_stage_records(
        self,
        *,
        workspace_id: int,
        module_name: str,
        limit: int | None = None,
        phase_filter: str | None = None,
        host_filter: str | None = None,
    ) -> list[ModuleStageRecordView]:
        max_items = max(1, int(limit or self.MODULE_RECENT_HITS_LIMIT))
        if module_name == "exporters":
            return [
                _exporter_stage_row_to_stage_record(item)
                for item in self.list_exporter_stage_rows(
                    workspace_id=workspace_id,
                    limit=max_items,
                    phase_filter=phase_filter,
                    host_filter=host_filter,
                )
            ]

        candidate_limit = max(max_items * 5, 50)
        with session_scope(self.session_factory, read_only=True) as session:
            findings_stmt = (
                select(Finding)
                .options(
                    selectinload(Finding.run_observation).selectinload(RunObservation.module_run),
                    selectinload(Finding.run_observation).selectinload(RunObservation.target_host),
                    selectinload(Finding.run_observation).selectinload(RunObservation.endpoint),
                    selectinload(Finding.run_observation).selectinload(RunObservation.protocol_service),
                    selectinload(Finding.module_run),
                    selectinload(Finding.target_host),
                    selectinload(Finding.endpoint),
                    selectinload(Finding.protocol_service),
                )
                .where(
                    Finding.workspace_id == workspace_id,
                    Finding.module_name == module_name,
                    Finding.deleted_at.is_(None),
                )
                .order_by(Finding.last_seen_at.desc())
                .limit(candidate_limit)
            )
            findings = list(session.scalars(findings_stmt).unique())
            finding_records = _dedup_stage_records(_finding_to_module_stage_record(finding) for finding in findings)
            combined_records = list(finding_records[:max_items])

            observations_stmt = (
                select(RunObservation)
                .options(
                    selectinload(RunObservation.module_run),
                    selectinload(RunObservation.target_host),
                    selectinload(RunObservation.endpoint),
                    selectinload(RunObservation.protocol_service),
                    selectinload(RunObservation.findings),
                )
                .where(
                    RunObservation.workspace_id == workspace_id,
                    RunObservation.module_name == module_name,
                    RunObservation.deleted_at.is_(None),
                )
                .order_by(RunObservation.updated_at.desc())
                .limit(candidate_limit)
            )
            observations = list(session.scalars(observations_stmt).unique())
            observation_records = _dedup_stage_records(
                _observation_to_module_stage_record(observation) for observation in observations
            )
            if len(combined_records) < max_items:
                combined_records = _dedup_stage_records([*combined_records, *observation_records])[:max_items]

            runs_stmt = (
                select(ModuleRun)
                .where(
                    ModuleRun.workspace_id == workspace_id,
                    ModuleRun.module_name == module_name,
                    ModuleRun.deleted_at.is_(None),
                )
                .order_by(ModuleRun.finished_at.desc(), ModuleRun.started_at.desc())
                .limit(candidate_limit)
            )
            runs = list(session.scalars(runs_stmt).unique())
            run_records = _dedup_stage_records(_run_to_module_stage_record(run) for run in runs)
            if not combined_records:
                combined_records = _dedup_stage_records([*combined_records, *run_records])[:max_items]
            return combined_records

    def get_database_overview(
        self,
        *,
        workspace_id: int,
        modules: tuple[str, ...] | list[str],
    ) -> DatabaseOverviewView:
        with session_scope(self.session_factory, read_only=True) as session:
            hosts_count = session.scalar(
                select(func.count(TargetHost.id)).where(
                    TargetHost.workspace_id == workspace_id,
                    TargetHost.deleted_at.is_(None),
                )
            )
            endpoints_count = session.scalar(
                select(func.count(NetworkEndpoint.id)).where(
                    NetworkEndpoint.workspace_id == workspace_id,
                    NetworkEndpoint.deleted_at.is_(None),
                )
            )
            findings_count = session.scalar(
                select(func.count(Finding.id)).where(
                    Finding.workspace_id == workspace_id,
                    Finding.deleted_at.is_(None),
                )
            )
            runs_count = session.scalar(
                select(func.count(ModuleRun.id)).where(
                    ModuleRun.workspace_id == workspace_id,
                    ModuleRun.deleted_at.is_(None),
                )
            )
            artifacts_count = session.scalar(
                select(func.count(Artifact.id)).where(
                    Artifact.workspace_id == workspace_id,
                    Artifact.deleted_at.is_(None),
                )
            )
            import_jobs_count = session.scalar(
                select(func.count(ImportJob.id)).where(ImportJob.workspace_id == workspace_id)
            )
            export_jobs_count = session.scalar(
                select(func.count(ExportJob.id)).where(ExportJob.workspace_id == workspace_id)
            )
            observation_last_seen = session.scalar(
                select(func.max(RunObservation.updated_at)).where(
                    RunObservation.workspace_id == workspace_id,
                    RunObservation.deleted_at.is_(None),
                )
            )
            finding_last_seen = session.scalar(
                select(func.max(Finding.last_seen_at)).where(
                    Finding.workspace_id == workspace_id,
                    Finding.deleted_at.is_(None),
                )
            )

        module_rows: list[ModuleOverviewView] = []
        for module_name in modules:
            summary = self.get_module_summary(workspace_id=workspace_id, module_name=module_name)
            module_rows.append(
                ModuleOverviewView(
                    module=summary.module,
                    records_count=(
                        summary.hosts_count
                        + summary.endpoints_count
                        + summary.findings_count
                        + summary.runs_count
                        + summary.artifacts_count
                    ),
                    hosts_count=summary.hosts_count,
                    endpoints_count=summary.endpoints_count,
                    findings_count=summary.findings_count,
                    runs_count=summary.runs_count,
                    artifacts_count=summary.artifacts_count,
                    last_seen_at=summary.last_seen_at,
                )
            )

        timestamps = [value for value in (observation_last_seen, finding_last_seen) if value is not None]
        return DatabaseOverviewView(
            totals=DatabaseTotalsView(
                hosts_count=int(hosts_count or 0),
                endpoints_count=int(endpoints_count or 0),
                findings_count=int(findings_count or 0),
                runs_count=int(runs_count or 0),
                artifacts_count=int(artifacts_count or 0),
                import_jobs_count=int(import_jobs_count or 0),
                export_jobs_count=int(export_jobs_count or 0),
                last_seen_at=max(timestamps) if timestamps else None,
            ),
            modules=module_rows,
        )

    def list_recent_exporter_hits(
        self,
        *,
        workspace_id: int,
        limit: int | None = None,
        phase_filter: str | None = None,
        host_filter: str | None = None,
    ) -> list[ModuleRecentHitView]:
        max_items = max(1, int(limit or self.EXPORTER_RECENT_HITS_LIMIT))
        candidate_limit = max(max_items * 5, 50)
        normalized_phase = str(phase_filter or "").strip().lower() or None
        normalized_host = _normalized_exporter_host_filter(host_filter)
        with session_scope(self.session_factory, read_only=True) as session:
            findings_stmt = (
                select(Finding)
                .options(
                    selectinload(Finding.run_observation).selectinload(RunObservation.module_run),
                    selectinload(Finding.run_observation).selectinload(RunObservation.target_host),
                    selectinload(Finding.run_observation).selectinload(RunObservation.endpoint),
                    selectinload(Finding.run_observation).selectinload(RunObservation.protocol_service),
                    selectinload(Finding.module_run),
                    selectinload(Finding.target_host),
                    selectinload(Finding.endpoint),
                    selectinload(Finding.protocol_service),
                )
                .where(
                    Finding.workspace_id == workspace_id,
                    Finding.module_name == "exporters",
                    Finding.deleted_at.is_(None),
                )
                .order_by(Finding.last_seen_at.desc())
                .limit(candidate_limit)
            )
            findings = list(session.scalars(findings_stmt).unique())

            hits: list[ModuleRecentHitView] = []
            seen_signatures: set[tuple[str | None, str, str, str | None, str | None, str | None]] = set()
            for finding in findings:
                stage_row = _finding_to_exporter_stage_row(finding)
                if stage_row is None:
                    continue
                if normalized_phase and str(stage_row.phase_tag or "").strip().lower() != normalized_phase:
                    continue
                if not _exporter_stage_row_matches_host_filter(stage_row, normalized_host):
                    continue
                hit = _finding_to_recent_hit(finding)
                if hit is None:
                    continue
                signature = _recent_hit_signature(hit)
                if signature in seen_signatures:
                    continue
                seen_signatures.add(signature)
                hits.append(hit)
                if len(hits) >= max_items:
                    break
            if len(hits) >= max_items:
                return hits

            observations_stmt = (
                select(RunObservation)
                .options(
                    selectinload(RunObservation.module_run),
                    selectinload(RunObservation.target_host),
                    selectinload(RunObservation.endpoint),
                    selectinload(RunObservation.protocol_service),
                    selectinload(RunObservation.findings),
                )
                .where(
                    RunObservation.workspace_id == workspace_id,
                    RunObservation.module_name == "exporters",
                    RunObservation.deleted_at.is_(None),
                )
                .order_by(RunObservation.updated_at.desc())
                .limit(candidate_limit)
            )
            observations = list(session.scalars(observations_stmt).unique())
            for observation in observations:
                stage_row = _observation_to_exporter_stage_row(observation)
                if stage_row is None:
                    continue
                if normalized_phase and str(stage_row.phase_tag or "").strip().lower() != normalized_phase:
                    continue
                if not _exporter_stage_row_matches_host_filter(stage_row, normalized_host):
                    continue
                hit = _observation_to_recent_hit(observation)
                if hit is None:
                    continue
                signature = _recent_hit_signature(hit)
                if signature in seen_signatures:
                    continue
                seen_signatures.add(signature)
                hits.append(hit)
                if len(hits) >= max_items:
                    break
            return hits

    def list_exporter_stage_rows(
        self,
        *,
        workspace_id: int,
        limit: int | None = None,
        phase_filter: str | None = None,
        host_filter: str | None = None,
    ) -> list[ExporterStageFindingView]:
        max_items = max(1, int(limit or self.EXPORTER_RECENT_HITS_LIMIT))
        candidate_limit = max(max_items * 5, 50)
        normalized_phase = str(phase_filter or "").strip().lower() or None
        normalized_host = _normalized_exporter_host_filter(host_filter)
        with session_scope(self.session_factory, read_only=True) as session:
            findings_stmt = (
                select(Finding)
                .options(
                    selectinload(Finding.run_observation).selectinload(RunObservation.module_run),
                    selectinload(Finding.run_observation).selectinload(RunObservation.target_host),
                    selectinload(Finding.run_observation).selectinload(RunObservation.endpoint),
                    selectinload(Finding.run_observation).selectinload(RunObservation.protocol_service),
                    selectinload(Finding.module_run),
                    selectinload(Finding.target_host),
                    selectinload(Finding.endpoint),
                    selectinload(Finding.protocol_service),
                )
                .where(
                    Finding.workspace_id == workspace_id,
                    Finding.module_name == "exporters",
                    Finding.deleted_at.is_(None),
                )
                .order_by(Finding.last_seen_at.desc())
                .limit(candidate_limit)
            )
            findings = list(session.scalars(findings_stmt).unique())
            rows: list[ExporterStageFindingView] = []
            seen_signatures: set[tuple[str, str, int | None, str, str | None, str | None, str | None, str | None]] = (
                set()
            )
            for finding in findings:
                row = _finding_to_exporter_stage_row(finding)
                if row is None:
                    continue
                if normalized_phase and str(row.phase_tag or "").strip().lower() != normalized_phase:
                    continue
                if not _exporter_stage_row_matches_host_filter(row, normalized_host):
                    continue
                signature = _exporter_stage_row_signature(row)
                if signature in seen_signatures:
                    continue
                seen_signatures.add(signature)
                rows.append(row)
                if len(rows) >= max_items:
                    break
            if len(rows) >= max_items:
                return rows

            observations_stmt = (
                select(RunObservation)
                .options(
                    selectinload(RunObservation.module_run),
                    selectinload(RunObservation.target_host),
                    selectinload(RunObservation.endpoint),
                    selectinload(RunObservation.protocol_service),
                    selectinload(RunObservation.findings),
                )
                .where(
                    RunObservation.workspace_id == workspace_id,
                    RunObservation.module_name == "exporters",
                    RunObservation.deleted_at.is_(None),
                )
                .order_by(RunObservation.updated_at.desc())
                .limit(candidate_limit)
            )
            observations = list(session.scalars(observations_stmt).unique())
            for observation in observations:
                row = _observation_to_exporter_stage_row(observation)
                if row is None:
                    continue
                if normalized_phase and str(row.phase_tag or "").strip().lower() != normalized_phase:
                    continue
                if not _exporter_stage_row_matches_host_filter(row, normalized_host):
                    continue
                signature = _exporter_stage_row_signature(row)
                if signature in seen_signatures:
                    continue
                seen_signatures.add(signature)
                rows.append(row)
                if len(rows) >= max_items:
                    break
            return rows

    def search(self, *, workspace_id: int, query: str) -> list[dict[str, str]]:
        with session_scope(self.session_factory, read_only=True) as session:
            return SearchRepository(session).search(workspace_id=workspace_id, query=query)


def _classify_exporter_hit_phase(observation: RunObservation | None, raw: dict[str, object]) -> str | None:
    if any(key in raw for key in ("trigger_url", "callback_target", "probe_success")):
        return "trigger"
    if any(key in raw for key in ("endpoint", "url", "ok")):
        return "collect"
    source_type = str(observation.source_type or "").strip().lower() if observation is not None else ""
    if source_type in {"collect", "trigger"}:
        return source_type
    return None


def _is_successful_exporter_hit(phase: str, raw: dict[str, object]) -> bool:
    if phase == "collect":
        if raw.get("ok") is True:
            return True
        status = _int_or_none(raw.get("status"))
        if status is not None and status < 400 and not _as_clean_text(raw.get("error")):
            return True
        return False
    if phase == "trigger":
        if raw.get("probe_success") is True or raw.get("success") is True:
            return True
        status = _int_or_none(raw.get("status"))
        if _as_clean_text(raw.get("callback_target") or raw.get("trigger_url")) and not _as_clean_text(
            raw.get("error")
        ):
            if status is None or status < 400:
                return True
        return False
    return False


def _int_or_none(value: object) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _as_clean_text(value: object) -> str | None:
    text = str(value or "").strip()
    return text or None


def _host_value(host: TargetHost | None) -> str | None:
    if host is None:
        return None
    return host.ip_address or host.fqdn or host.hostname or host.canonical_key


def _endpoint_host_value(endpoint: NetworkEndpoint | None) -> str | None:
    if endpoint is None:
        return None
    return endpoint.ip or endpoint.host


def _protocol_service_name(service: ProtocolService | None) -> str | None:
    if service is None:
        return None
    return str(service.service_name or "").strip() or None


def _target_text(
    *,
    raw: dict[str, object],
    target_host: TargetHost | None,
    endpoint: NetworkEndpoint | None,
    fallback_target: str | None = None,
) -> str | None:
    host = (
        _as_clean_text(raw.get("host")) or _host_value(target_host) or _endpoint_host_value(endpoint) or fallback_target
    )
    port = _int_or_none(raw.get("port"))
    if port is None and endpoint is not None:
        port = endpoint.port
    if host and port is not None:
        return f"{host}:{port}"
    if host:
        return host
    if endpoint is not None and endpoint.canonical_key:
        return endpoint.canonical_key
    return None


def _phase_from_context(
    *,
    module_name: str,
    raw: dict[str, object],
    observation: RunObservation | None,
    module_run: ModuleRun | None,
) -> str:
    if module_name == "exporters":
        phase = _classify_exporter_hit_phase(observation, raw)
        if phase:
            return phase
    for value in (
        observation.source_type if observation is not None else None,
        module_run.source_type if module_run is not None else None,
        raw.get("source_type"),
    ):
        text = _as_clean_text(value)
        if text:
            return text
    return "-"


def _subject_from_context(
    *,
    protocol: str,
    raw: dict[str, object],
    protocol_service: ProtocolService | None,
) -> str:
    for value in (
        raw.get("exporter"),
        raw.get("service"),
        raw.get("resource_kind"),
        raw.get("type"),
        _protocol_service_name(protocol_service),
        protocol,
    ):
        text = _as_clean_text(value)
        if text:
            return text
    return protocol or "module"


def _resource_summary_from_raw(raw: dict[str, object]) -> tuple[str | None, str | None]:
    scalar_keys = (
        "database",
        "table",
        "repository",
        "project",
        "collection",
        "topic",
        "znode",
        "key",
        "name",
        "namespace",
    )
    for key in scalar_keys:
        text = _as_clean_text(raw.get(key))
        if text:
            return "resource", f"{key}={text}"

    list_keys = ("tables", "databases", "namespaces", "pods", "datasources", "collections", "topics")
    for key in list_keys:
        value = raw.get(key)
        if isinstance(value, list) and value:
            return "resource", f"{key}={len(value)}"
    return None, None


def _location_from_context(
    *,
    module_name: str,
    raw: dict[str, object],
    endpoint: NetworkEndpoint | None,
    target: str | None,
) -> tuple[str | None, str | None]:
    if module_name == "exporters":
        callback_target = _as_clean_text(raw.get("callback_target"))
        if callback_target:
            return "callback", callback_target
        endpoint_text = _as_clean_text(raw.get("endpoint"))
        if endpoint_text:
            return "endpoint", endpoint_text
        trigger_target = _as_clean_text(raw.get("trigger_url"))
        if trigger_target:
            return "target", trigger_target

    endpoint_text = _as_clean_text(raw.get("endpoint")) or _as_clean_text(raw.get("path"))
    if endpoint_text:
        return "endpoint", endpoint_text

    resource_label, resource_value = _resource_summary_from_raw(raw)
    if resource_label and resource_value:
        return resource_label, resource_value

    if endpoint is not None and endpoint.canonical_key:
        return "endpoint", endpoint.canonical_key
    if target:
        return "target", target
    return None, None


def _split_description_sample(description: str | None) -> tuple[str | None, str | None]:
    text = str(description or "").strip()
    if not text:
        return None, None
    marker = "sample="
    if marker not in text:
        return None, text
    prefix, sample = text.split(marker, 1)
    detail = prefix.strip() or None
    sample_text = sample.strip() or None
    return sample_text, detail


_EXPORTER_ENDPOINT_RE = re.compile(r"(?:^|\s)endpoint=([^\s]+)")
_EXPORTER_REASONS_RE = re.compile(r"(?:^|\s)reasons=([^\s]+)")


def _parse_exporter_finding_description(description: str | None) -> tuple[str | None, str | None, str | None]:
    text = str(description or "").strip()
    if not text:
        return None, None, None

    sample: str | None = None
    working = text
    sample_marker = "sample="
    if sample_marker in working:
        prefix, sample_text = working.split(sample_marker, 1)
        working = prefix.strip()
        sample = sample_text.strip() or None

    endpoint_match = _EXPORTER_ENDPOINT_RE.search(working)
    endpoint = endpoint_match.group(1).strip() if endpoint_match else None
    if endpoint_match:
        working = _EXPORTER_ENDPOINT_RE.sub(" ", working)

    working = _EXPORTER_REASONS_RE.sub(" ", working)
    detail = " ".join(working.split()) or None
    return endpoint, sample, detail


def _exporter_stage_reason(value: str | None) -> str:
    text = str(value or "").strip()
    if not text:
        return "-"
    normalized: list[str] = []
    for token in text.split(","):
        item = token.strip()
        if not item:
            continue
        normalized.append(item.rsplit(":", 1)[-1])
    return ",".join(normalized) or "-"


def _observation_detail(raw: dict[str, object]) -> tuple[str | None, str | None]:
    for key in ("error", "message", "reason"):
        text = _as_clean_text(raw.get(key))
        if text:
            return "detail", text
    version = _as_clean_text(raw.get("version") or raw.get("server_version"))
    if version:
        return "detail", f"version={version}"
    return None, None


def _finding_to_recent_hit(finding: Finding) -> ModuleRecentHitView | None:
    observation = finding.run_observation
    module_run = finding.module_run or (observation.module_run if observation is not None else None)
    raw = observation.raw_json_result_sanitized if observation is not None else None
    raw = raw if isinstance(raw, dict) else {}
    if finding.module_name == "exporters":
        phase = _classify_exporter_hit_phase(observation, raw)
        if phase is None or not _is_successful_exporter_hit(phase, raw):
            return None
    else:
        phase = _phase_from_context(
            module_name=finding.module_name,
            raw=raw,
            observation=observation,
            module_run=module_run,
        )
    target = _target_text(
        raw=raw,
        target_host=finding.target_host or (observation.target_host if observation is not None else None),
        endpoint=finding.endpoint or (observation.endpoint if observation is not None else None),
        fallback_target=observation.target_text if observation is not None else None,
    )
    protocol_service = finding.protocol_service or (observation.protocol_service if observation is not None else None)
    location_label, location_value = _location_from_context(
        module_name=finding.module_name,
        raw=raw,
        endpoint=finding.endpoint or (observation.endpoint if observation is not None else None),
        target=target,
    )
    sample, detail = _split_description_sample(finding.description)
    return ModuleRecentHitView(
        module=finding.module_name,
        target=target,
        subject=_subject_from_context(protocol=finding.protocol, raw=raw, protocol_service=protocol_service),
        phase=phase,
        finding_type=finding.finding_type,
        status=finding.status,
        severity=finding.severity,
        seen_at=finding.last_seen_at,
        endpoint_or_resource=location_value,
        endpoint_or_resource_label=location_label,
        detail=sample or detail,
        detail_label="sample" if sample else ("detail" if detail else None),
        title=finding.title,
    )


def _host_port_from_context(
    *,
    raw: dict[str, object],
    target_host: TargetHost | None,
    endpoint: NetworkEndpoint | None,
    fallback_target: str | None = None,
) -> tuple[str | None, int | None]:
    host = (
        _as_clean_text(raw.get("host")) or _host_value(target_host) or _endpoint_host_value(endpoint) or fallback_target
    )
    port = _int_or_none(raw.get("port"))
    if port is None and endpoint is not None:
        port = endpoint.port
    return host, port


def _finding_to_exporter_stage_row(finding: Finding) -> ExporterStageFindingView | None:
    if finding.module_name != "exporters":
        return None

    observation = finding.run_observation
    module_run = finding.module_run or (observation.module_run if observation is not None else None)
    raw = observation.raw_json_result_sanitized if observation is not None else None
    raw = raw if isinstance(raw, dict) else {}

    phase = _classify_exporter_hit_phase(observation, raw)
    if phase is None:
        phase = _phase_from_context(
            module_name=finding.module_name,
            raw=raw,
            observation=observation,
            module_run=module_run,
        )
    if phase not in {"collect", "trigger"}:
        return None
    if not _is_successful_exporter_hit(phase, raw):
        return None

    target_host = finding.target_host or (observation.target_host if observation is not None else None)
    endpoint = finding.endpoint or (observation.endpoint if observation is not None else None)
    host, port = _host_port_from_context(
        raw=raw,
        target_host=target_host,
        endpoint=endpoint,
        fallback_target=observation.target_text if observation is not None else None,
    )
    desc_endpoint, sample, detail = _parse_exporter_finding_description(finding.description)
    endpoint_value = _as_clean_text(raw.get("endpoint")) or desc_endpoint
    callback_target = _as_clean_text(raw.get("callback_target"))
    url = _as_clean_text(raw.get("url"))
    if phase == "collect" and not url and host and port is not None and endpoint_value:
        url = f"http://{host}:{port}{endpoint_value}"
    if phase == "trigger" and not detail:
        detail = _as_clean_text(raw.get("trigger_url"))
    if detail and detail in {url, endpoint_value}:
        detail = None

    subject = _subject_from_context(
        protocol=finding.protocol,
        raw=raw,
        protocol_service=finding.protocol_service
        or (observation.protocol_service if observation is not None else None),
    )
    trigger_port = _int_or_none(raw.get("listen_port"))
    return ExporterStageFindingView(
        phase_tag=phase.upper(),
        host=(callback_target if phase == "trigger" and callback_target else host) or "-",
        port=port if phase == "collect" else trigger_port,
        exporter_display_name=_stage_validate_exporter_display_name(subject),
        endpoint=endpoint_value,
        callback_target=callback_target,
        url=url,
        reason=_exporter_stage_reason(finding.finding_type),
        sample=sample,
        detail=detail,
        seen_at=finding.last_seen_at,
    )


def _observation_to_exporter_stage_row(observation: RunObservation) -> ExporterStageFindingView | None:
    if observation.findings:
        return None
    if not _is_successful_observation(observation):
        return None

    raw = observation.raw_json_result_sanitized
    raw = raw if isinstance(raw, dict) else {}
    phase = _classify_exporter_hit_phase(observation, raw)
    if phase is None:
        phase = _phase_from_context(
            module_name=observation.module_name,
            raw=raw,
            observation=observation,
            module_run=observation.module_run,
        )
    if phase not in {"collect", "trigger"}:
        return None
    if not _is_successful_exporter_hit(phase, raw):
        return None

    host, port = _host_port_from_context(
        raw=raw,
        target_host=observation.target_host,
        endpoint=observation.endpoint,
        fallback_target=observation.target_text,
    )
    endpoint_value = _as_clean_text(raw.get("endpoint"))
    callback_target = _as_clean_text(raw.get("callback_target"))
    url = _as_clean_text(raw.get("url"))
    if phase == "collect" and not url and host and port is not None and endpoint_value:
        url = f"http://{host}:{port}{endpoint_value}"
    detail = None
    if phase == "trigger":
        detail = _as_clean_text(raw.get("trigger_url")) or _as_clean_text(raw.get("target"))
    elif raw.get("error"):
        detail = _as_clean_text(raw.get("error"))

    subject = _subject_from_context(
        protocol=observation.protocol,
        raw=raw,
        protocol_service=observation.protocol_service,
    )
    trigger_port = _int_or_none(raw.get("listen_port"))
    return ExporterStageFindingView(
        phase_tag=phase.upper(),
        host=(callback_target if phase == "trigger" and callback_target else host) or "-",
        port=port if phase == "collect" else trigger_port,
        exporter_display_name=_stage_validate_exporter_display_name(subject),
        endpoint=endpoint_value,
        callback_target=callback_target,
        url=url,
        reason=_exporter_stage_reason(observation.normalized_status or _as_clean_text(raw.get("status")) or phase),
        detail=detail,
        seen_at=observation.updated_at,
    )


def _normalized_exporter_host_filter(value: str | None) -> str | None:
    text = _as_clean_text(value)
    if not text:
        return None
    return text.strip().lower()


def _exporter_stage_row_matches_host_filter(
    row: ExporterStageFindingView,
    normalized_host_filter: str | None,
) -> bool:
    if not normalized_host_filter:
        return True
    return str(row.host or "").strip().lower() == normalized_host_filter


def _exporter_stage_row_signature(
    row: ExporterStageFindingView,
) -> tuple[str, str, int | None, str, str | None, str | None, str | None, str | None]:
    return (
        str(row.phase_tag or ""),
        str(row.host or ""),
        row.port,
        str(row.exporter_display_name or ""),
        row.endpoint,
        row.url,
        row.reason,
        row.detail or row.sample,
    )


def _recent_hit_signature(hit: ModuleRecentHitView) -> tuple[str | None, str, str, str | None, str | None, str | None]:
    return (
        hit.target,
        hit.subject,
        hit.phase,
        hit.finding_type,
        hit.status,
        hit.endpoint_or_resource,
    )


def _dedup_stage_records(records: list[ModuleStageRecordView | None] | object) -> list[ModuleStageRecordView]:
    deduped: list[ModuleStageRecordView] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()
    for item in records:
        if item is None:
            continue
        signature = (item.primary_line, tuple(item.detail_lines))
        if signature in seen:
            continue
        seen.add(signature)
        deduped.append(item)
    return deduped


def _collect_stage_lines(*items: object) -> list[str]:
    lines: list[str] = []
    for item in items:
        if item is None:
            continue
        if isinstance(item, str):
            text = item.strip()
            if text and text not in lines:
                lines.append(text)
            continue
        if isinstance(item, list):
            for entry in item:
                if not isinstance(entry, str):
                    continue
                text = entry.strip()
                if text and text not in lines:
                    lines.append(text)
    return lines


def _module_stage_tag(module_name: str) -> str:
    return str(module_name or "module").strip().upper() or "MODULE"


def _fallback_marker_for_hit(hit: ModuleRecentHitView) -> str:
    phase = str(hit.phase or "").strip().lower()
    status = str(hit.status or "").strip().lower()
    finding_type = str(hit.finding_type or "").strip()
    if finding_type:
        return "[+]"
    if status in {"success", "completed", "open"}:
        return "[+]"
    if status in {"auth_required", "closed"}:
        return "[-]"
    if status in {"failed", "error"}:
        return "[!]"
    if phase in {"detect", "scan"}:
        return "[*]"
    return "[*]"


def _recent_hit_to_module_stage_record(hit: ModuleRecentHitView | None) -> ModuleStageRecordView | None:
    if hit is None:
        return None
    target = hit.target or "-"
    primary = f"{_module_stage_tag(hit.module)}\t{target}\t-\t {_fallback_marker_for_hit(hit)} {hit.title}"
    details: list[str] = []
    location = str(hit.endpoint_or_resource or "").strip()
    if location:
        label = str(hit.endpoint_or_resource_label or "detail").strip() or "detail"
        details.append(f"{_module_stage_tag(hit.module)}\t{label}={location}")
    detail = str(hit.detail or "").strip()
    if detail:
        label = str(hit.detail_label or "detail").strip() or "detail"
        details.append(f"{_module_stage_tag(hit.module)}\t{label}={detail}")
    return ModuleStageRecordView(module=hit.module, primary_line=primary, detail_lines=details, seen_at=hit.seen_at)


def _exporter_stage_row_to_stage_record(row: ExporterStageFindingView) -> ModuleStageRecordView:
    port_text = str(row.port) if row.port is not None else "-"
    first_line = f"{row.phase_tag:<8}\t{row.host}\t{port_text}\t [+] {row.exporter_display_name}"
    if row.phase_tag == "COLLECT" and row.url:
        first_line += f" url={row.url}"

    detail_lines = [f"{'VALIDATE':<8}\t{row.host}\t{port_text}\t [*] Dump Validate {row.exporter_display_name}"]
    reason_line = f"{'VALIDATE':<8}\t{row.host}\t{port_text}\t reason={row.reason}"
    if row.endpoint:
        reason_line += f" endpoint={row.endpoint}"
    detail_lines.append(reason_line)
    evidence = str(row.sample or row.detail or "").strip()
    if evidence:
        detail_lines.append(f"{'VALIDATE':<8}\t{row.host}\t{port_text}\t {evidence}")
    return ModuleStageRecordView(
        module="exporters",
        primary_line=first_line,
        detail_lines=detail_lines,
        seen_at=row.seen_at,
    )


def _augment_stage_record(
    *,
    module_name: str,
    raw: dict[str, object] | None,
    target_host: TargetHost | None,
    endpoint: NetworkEndpoint | None,
    observation: RunObservation | None = None,
    finding: Finding | None = None,
    module_run: ModuleRun | None = None,
    seen_at: object | None = None,
) -> dict[str, object] | None:
    if raw is None:
        return None
    record = dict(raw)
    host, port = _host_port_from_context(
        raw=record,
        target_host=target_host,
        endpoint=endpoint,
        fallback_target=observation.target_text if observation is not None else None,
    )
    if host and not _as_clean_text(record.get("host")):
        record["host"] = host
    if port is not None and _int_or_none(record.get("port")) is None:
        record["port"] = port
    if endpoint is not None:
        if not _as_clean_text(record.get("endpoint")) and endpoint.path:
            record["endpoint"] = endpoint.path
        if not _as_clean_text(record.get("path")) and endpoint.path:
            record["path"] = endpoint.path
        if observation is not None:
            protocol_service = observation.protocol_service
            if (
                record.get("auth_required") is None
                and protocol_service is not None
                and protocol_service.auth_required is not None
            ):
                record["auth_required"] = protocol_service.auth_required
            if not _as_clean_text(record.get("status")) and observation.normalized_status:
                record["status"] = observation.normalized_status
            if (
                not _as_clean_text(record.get("service"))
                and protocol_service is not None
                and protocol_service.service_name
            ):
                record["service"] = protocol_service.service_name
            if not _as_clean_text(record.get("version")) and not _as_clean_text(record.get("server_version")):
                if protocol_service is not None and protocol_service.version:
                    record["version"] = protocol_service.version
    if module_run is not None and not _as_clean_text(record.get("tool_version")) and module_run.tool_version:
        record["tool_version"] = module_run.tool_version
    if seen_at is not None and not _as_clean_text(record.get("timestamp")):
        record["timestamp"] = str(seen_at)
    if module_name == "grafana" and record.get("auth_required") is False and not _as_clean_text(record.get("status")):
        record["status"] = "open_no_auth"
    if module_name == "kubeapi" and record.get("auth_required") is False and not _as_clean_text(record.get("status")):
        record["status"] = "open_no_auth"
    if module_name == "consul" and "is_consul" not in record and str(record.get("status") or "") != "not_consul":
        record["is_consul"] = True
    if finding is not None and finding.description and module_name == "proxmox":
        record.setdefault("finding_description", finding.description)
    return _normalize_stage_record(module_name, record)


def _normalize_stage_record(module_name: str, record: dict[str, object]) -> dict[str, object]:
    normalized = dict(record)
    if module_name == "grafana":
        if normalized.get("datasources") is not None and "show_datasources" not in normalized:
            normalized["show_datasources"] = True
    elif module_name == "kubeapi":
        if normalized.get("namespaces") is not None and "show_namespaces" not in normalized:
            normalized["show_namespaces"] = True
        if normalized.get("pods") is not None and "show_pods" not in normalized:
            normalized["show_pods"] = True
        if normalized.get("secrets") is not None and "show_secrets" not in normalized:
            normalized["show_secrets"] = True
    elif module_name == "postgres":
        if normalized.get("databases") is not None and "show_databases" not in normalized:
            normalized["show_databases"] = True
            normalized.setdefault("database_names", normalized.get("databases"))
        if normalized.get("tables") is not None and "show_tables" not in normalized:
            normalized["show_tables"] = True
            normalized.setdefault("table_names", normalized.get("tables"))
        if normalized.get("columns") is not None and normalized.get("table") is not None:
            normalized.setdefault(
                "table_columns_info",
                [
                    {
                        "database": normalized.get("database"),
                        "table": normalized.get("table"),
                        "columns": normalized.get("columns"),
                    }
                ],
            )
    elif module_name == "clickhouse":
        if normalized.get("databases") is not None and "show_databases" not in normalized:
            normalized["show_databases"] = True
            normalized.setdefault("database_names", normalized.get("databases"))
        if normalized.get("tables") is not None and "show_tables" not in normalized:
            normalized["show_tables"] = True
            normalized.setdefault("table_names", normalized.get("tables"))
        if normalized.get("columns") is not None and normalized.get("table") is not None:
            normalized.setdefault(
                "table_columns_info",
                [
                    {
                        "database": normalized.get("database"),
                        "table": normalized.get("table"),
                        "columns": normalized.get("columns"),
                    }
                ],
            )
    elif module_name == "redis":
        if normalized.get("keys") is not None and "show_keys" not in normalized:
            normalized["show_keys"] = True
    elif module_name == "etcd":
        if normalized.get("keys") is not None and "show_keys" not in normalized:
            normalized["show_keys"] = True
        if normalized.get("key_values") is not None and "dump_keys" not in normalized:
            normalized["dump_keys"] = True
    elif module_name == "kafka":
        if (
            any(key in normalized for key in ("topics", "dump_topics", "topic_messages"))
            and "show_topics" not in normalized
        ):
            normalized["show_topics"] = True
        if normalized.get("topic_messages") is not None and "dump" not in normalized:
            normalized["dump"] = True
    elif module_name == "zookeeper":
        if any(key in normalized for key in ("znodes", "znode_values")) and "show_znodes" not in normalized:
            normalized["show_znodes"] = True
        if normalized.get("znode_values") is not None and "dump" not in normalized:
            normalized["dump"] = True
    elif module_name == "registry":
        if normalized.get("images") is not None and "show_images" not in normalized:
            normalized["show_images"] = True
        if normalized.get("harbor_projects") is not None:
            normalized.setdefault("harbor", True)
            normalized.setdefault("show_images", True)
        if normalized.get("harbor_repositories") is not None:
            normalized.setdefault("harbor", True)
            normalized.setdefault("show_images", True)
        if normalized.get("harbor_artifacts") is not None:
            normalized.setdefault("harbor", True)
            normalized.setdefault("show_images", True)
        if normalized.get("nexus_assets") is not None:
            normalized.setdefault("nexus", True)
            normalized.setdefault("assets", True)
    elif module_name == "qdrant":
        if normalized.get("collections") is not None and "show_collections" not in normalized:
            normalized["show_collections"] = True
        if normalized.get("collection_dump_items") is not None and "dump" not in normalized:
            normalized["dump"] = True
    elif module_name == "proxmox":
        if normalized.get("endpoint_results") is not None and "discover_creds" not in normalized:
            normalized["discover_creds"] = True
        if normalized.get("nodes") is not None and "show_nodes" not in normalized:
            normalized["show_nodes"] = True
        if normalized.get("users") is not None and "show_users" not in normalized:
            normalized["show_users"] = True
    elif module_name == "consul":
        if normalized.get("kv_keys_list") is not None and "keys_requested" not in normalized:
            normalized["keys_requested"] = True
        if normalized.get("kv_dump_items") is not None and "dump_requested" not in normalized:
            normalized["dump_requested"] = True
        if normalized.get("services_list") is not None and "services_list_requested" not in normalized:
            normalized["services_list_requested"] = True
        if normalized.get("agents_list") is not None and "agents_list_requested" not in normalized:
            normalized["agents_list_requested"] = True
        if normalized.get("checks_list") is not None and "checks_list_requested" not in normalized:
            normalized["checks_list_requested"] = True
        if normalized.get("nodes_list") is not None and "nodes_list_requested" not in normalized:
            normalized["nodes_list_requested"] = True
    return normalized


def _module_stage_lines(module_name: str, record: dict[str, object]) -> list[str]:
    if module_name == "grafana":
        return _collect_stage_lines(
            _grafana_detect_record(record, "txt"),
            _grafana_format_record(record, "txt"),
            _grafana_auth_details(record, "txt"),
            _grafana_datasource_details(record, "txt"),
            _grafana_check_details(record, "txt"),
        )
    if module_name == "registry":
        return _collect_stage_lines(
            _registry_detect_record(record, "txt"),
            _registry_format_record(record, "txt"),
            _registry_detail_records(record, "txt"),
        )
    if module_name == "postgres":
        return _collect_stage_lines(
            _postgres_detect_record(record, "txt"),
            _postgres_format_record(record, "txt"),
            _postgres_databases_details(record, "txt"),
            _postgres_tables_details(record, "txt"),
            _postgres_table_columns_details(record, "txt"),
            _postgres_table_row_count_details(record, "txt"),
            _postgres_table_dump_details(record, "txt"),
            _postgres_execute_details(record, "txt"),
            _postgres_sql_details(record, "txt"),
        )
    if module_name == "clickhouse":
        return _collect_stage_lines(
            _clickhouse_detect_record(record, "txt"),
            _clickhouse_format_record(record, "txt"),
            _clickhouse_auth_attempt_details(record, "txt"),
            _clickhouse_databases_details(record, "txt"),
            _clickhouse_tables_details(record, "txt"),
            _clickhouse_table_columns_details(record, "txt"),
            _clickhouse_table_dump_details(record, "txt"),
            _clickhouse_execute_details(record, "txt"),
            _clickhouse_sql_details(record, "txt"),
        )
    if module_name == "redis":
        return _collect_stage_lines(
            _redis_detect_record(record, "txt"),
            _redis_format_record(record, "txt"),
            _redis_keys_details(record, "txt"),
        )
    if module_name == "etcd":
        return _collect_stage_lines(
            _etcd_detect_record(record, "txt"),
            _etcd_format_record(record, "txt"),
            _etcd_keys_details(record, "txt"),
        )
    if module_name == "kafka":
        return _collect_stage_lines(
            _kafka_detect_record(record, "txt"),
            _kafka_format_record(record, "txt"),
            _kafka_topics_details(record, "txt"),
        )
    if module_name == "zookeeper":
        return _collect_stage_lines(
            _zookeeper_detect_record(record, "txt"),
            _zookeeper_format_record(record, "txt"),
            _zookeeper_znodes_details(record, "txt"),
        )
    if module_name == "qdrant":
        return _collect_stage_lines(
            _qdrant_detect_record(record, "txt"),
            _qdrant_format_record(record, "txt"),
            _qdrant_detail_records(record, "txt", debug=False),
        )
    if module_name == "gitlab":
        return _collect_stage_lines(
            _gitlab_format_record(record, "txt"),
            _gitlab_detail_records(record, "txt"),
        )
    if module_name == "proxmox":
        return _collect_stage_lines(
            _proxmox_detect_record(record, "txt"),
            _proxmox_format_record(record, "txt"),
            _proxmox_findings_details(record, "txt"),
            _proxmox_discovered_urls_details(record, "txt"),
            _proxmox_nodes_details(record, "txt"),
            _proxmox_users_details(record, "txt"),
            _proxmox_add_user_details(record, "txt"),
        )
    if module_name == "kubeapi":
        return _collect_stage_lines(
            _kubeapi_detect_record(record, "txt"),
            f"{_kubeapi_prefix(record)} {_kubeapi_status_summary_line(record)}"
            if _kubeapi_status_summary_line(record)
            else None,
            _kubeapi_detail_records(record, "txt"),
        )
    if module_name == "consul":
        return _collect_stage_lines(
            _consul_detect_line(record, "txt"),
            f"{_consul_prefix(record)} {_consul_summary_line(record)}" if _consul_summary_line(record) else None,
            f"{_consul_prefix(record)} {_consul_auth_summary_line(record)}"
            if _consul_auth_summary_line(record)
            else None,
            _consul_detail_lines(record, "txt", debug=False),
        )
    return []


def _finding_to_module_stage_record(finding: Finding) -> ModuleStageRecordView | None:
    if finding.module_name == "exporters":
        row = _finding_to_exporter_stage_row(finding)
        return _exporter_stage_row_to_stage_record(row) if row is not None else None
    observation = finding.run_observation
    module_run = finding.module_run or (observation.module_run if observation is not None else None)
    raw = (
        observation.raw_json_result_sanitized
        if observation is not None and isinstance(observation.raw_json_result_sanitized, dict)
        else None
    )
    record = _augment_stage_record(
        module_name=finding.module_name,
        raw=raw,
        target_host=finding.target_host or (observation.target_host if observation is not None else None),
        endpoint=finding.endpoint or (observation.endpoint if observation is not None else None),
        observation=observation,
        finding=finding,
        module_run=module_run,
        seen_at=finding.last_seen_at,
    )
    if record is not None:
        lines = _module_stage_lines(finding.module_name, record)
        if lines:
            return ModuleStageRecordView(
                module=finding.module_name,
                primary_line=lines[0],
                detail_lines=lines[1:],
                seen_at=finding.last_seen_at,
            )
    return _recent_hit_to_module_stage_record(_finding_to_recent_hit(finding))


def _observation_to_module_stage_record(observation: RunObservation) -> ModuleStageRecordView | None:
    if observation.findings:
        return None
    if not _is_successful_observation(observation):
        return None
    raw = observation.raw_json_result_sanitized if isinstance(observation.raw_json_result_sanitized, dict) else None
    record = _augment_stage_record(
        module_name=observation.module_name,
        raw=raw,
        target_host=observation.target_host,
        endpoint=observation.endpoint,
        observation=observation,
        module_run=observation.module_run,
        seen_at=observation.updated_at,
    )
    if record is not None:
        lines = _module_stage_lines(observation.module_name, record)
        if lines:
            return ModuleStageRecordView(
                module=observation.module_name,
                primary_line=lines[0],
                detail_lines=lines[1:],
                seen_at=observation.updated_at,
            )
    return _recent_hit_to_module_stage_record(_observation_to_recent_hit(observation))


def _run_to_module_stage_record(module_run: ModuleRun) -> ModuleStageRecordView | None:
    return _recent_hit_to_module_stage_record(_run_to_recent_hit(module_run))


def _is_successful_observation(observation: RunObservation) -> bool:
    module_run = observation.module_run
    if module_run is not None and str(module_run.execution_status or "").strip().lower() in {"success", "completed"}:
        return True
    return str(observation.normalized_status or "").strip().lower() not in {"error", "failed"}


def _observation_to_recent_hit(observation: RunObservation) -> ModuleRecentHitView | None:
    if observation.findings:
        return None
    if not _is_successful_observation(observation):
        return None
    raw = observation.raw_json_result_sanitized
    raw = raw if isinstance(raw, dict) else {}
    target = _target_text(
        raw=raw,
        target_host=observation.target_host,
        endpoint=observation.endpoint,
        fallback_target=observation.target_text,
    )
    location_label, location_value = _location_from_context(
        module_name=observation.module_name,
        raw=raw,
        endpoint=observation.endpoint,
        target=target,
    )
    detail_label, detail = _observation_detail(raw)
    subject = _subject_from_context(
        protocol=observation.protocol,
        raw=raw,
        protocol_service=observation.protocol_service,
    )
    return ModuleRecentHitView(
        module=observation.module_name,
        target=target,
        subject=subject,
        phase=_phase_from_context(
            module_name=observation.module_name,
            raw=raw,
            observation=observation,
            module_run=observation.module_run,
        ),
        status=observation.normalized_status,
        severity=observation.severity,
        seen_at=observation.updated_at,
        endpoint_or_resource=location_value,
        endpoint_or_resource_label=location_label,
        detail=detail,
        detail_label=detail_label,
        title=f"{subject} {observation.normalized_status} on {target or observation.module_name}",
    )


def _run_to_recent_hit(module_run: ModuleRun) -> ModuleRecentHitView | None:
    if str(module_run.execution_status or "").strip().lower() not in {"success", "completed"}:
        return None
    subject = str(module_run.protocol or module_run.module_name or "run").strip() or "run"
    return ModuleRecentHitView(
        module=module_run.module_name,
        target=_as_clean_text(module_run.target_scope),
        subject=subject,
        phase=_as_clean_text(module_run.source_type) or "-",
        status=module_run.execution_status,
        seen_at=module_run.finished_at or module_run.started_at,
        detail=_as_clean_text(module_run.tool_version),
        detail_label="version" if _as_clean_text(module_run.tool_version) else None,
        title=f"{module_run.module_name} {module_run.source_type} {module_run.execution_status}",
    )


def _exporter_sample_from_description(description: str | None) -> str | None:
    _, sample, _ = _parse_exporter_finding_description(description)
    return sample
