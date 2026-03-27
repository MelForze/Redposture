"""Ingest service and adapter orchestration."""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from ..ingest import ModuleIngestRegistry, build_ingest_registry
from ..models import ImportJob, ModuleRun
from ..repositories import (
    ArtifactRepository,
    EndpointRepository,
    EvidenceRepository,
    ExtensionRepository,
    FindingRepository,
    HostRepository,
    ImportJobRepository,
    ModuleRunRepository,
    ProtocolServiceRepository,
    RunObservationRepository,
    SearchRepository,
)
from ..repositories.security import SecretRefRepository
from ..security import NoOpArtifactCipher, build_secret_ref, sanitize_payload
from ..session import session_scope
from ..util import compress_json_payload, parse_datetime, stable_hash, utcnow
from .workspace import WorkspaceService


class IngestService:
    def __init__(self, session_factory: sessionmaker) -> None:
        self.session_factory = session_factory
        self.registry: ModuleIngestRegistry = build_ingest_registry()
        self.workspace_service = WorkspaceService(session_factory)
        self.cipher = NoOpArtifactCipher()

    def ingest_file(self, *, workspace_slug: str | None, module_name: str, json_file: str) -> dict[str, object]:
        workspace_id, resolved_slug = self.workspace_service.resolve_workspace_id(workspace_slug)
        records_iter = iter(_read_records(json_file))
        first_record = next(records_iter, None)
        if first_record is None:
            raise ValueError(f"no JSON records found in {json_file}")
        adapter = self.registry.get(module_name)
        base_run = adapter.build_run(first_record)

        import_job_id, module_run_id = self._create_job_and_run(
            workspace_id=workspace_id,
            module_name=module_name,
            json_file=json_file,
            base_run=base_run.model_dump(),
        )

        try:
            with session_scope(self.session_factory) as session:
                import_job = session.get(ImportJob, import_job_id)
                module_run = session.get(ModuleRun, module_run_id)
                if import_job is None or module_run is None:
                    raise RuntimeError("ingest state initialization failed")

                host_repo = HostRepository(session)
                endpoint_repo = EndpointRepository(session)
                service_repo = ProtocolServiceRepository(session)
                observation_repo = RunObservationRepository(session)
                finding_repo = FindingRepository(session)
                artifact_repo = ArtifactRepository(session)
                evidence_repo = EvidenceRepository(session)
                extension_repo = ExtensionRepository(session)
                search_repo = SearchRepository(session)
                secret_repo = SecretRefRepository(session)

                stats = {
                    "module": module_name,
                    "workspace": resolved_slug,
                    "records": 0,
                    "observations": 0,
                    "findings": 0,
                    "artifacts": 0,
                }

                for record in _prepend_record(first_record, records_iter):
                    envelope = adapter.ingest_record(record)
                    self._persist_envelope(
                        session=session,
                        workspace_id=workspace_id,
                        module_run=module_run,
                        envelope=envelope,
                        host_repo=host_repo,
                        endpoint_repo=endpoint_repo,
                        service_repo=service_repo,
                        observation_repo=observation_repo,
                        finding_repo=finding_repo,
                        artifact_repo=artifact_repo,
                        evidence_repo=evidence_repo,
                        extension_repo=extension_repo,
                        search_repo=search_repo,
                        secret_repo=secret_repo,
                        stats=stats,
                    )
                    stats["records"] = int(stats["records"]) + 1

                import_job.status = "success"
                import_job.finished_at = utcnow()
                import_job.stats_json = stats
                module_run.execution_status = "success"
                module_run.finished_at = parse_datetime(base_run.finished_at) or utcnow()
                return stats
        except Exception as exc:
            self._mark_job_and_run_failed(
                import_job_id=import_job_id,
                module_run_id=module_run_id,
                error_text=str(exc),
            )
            raise

    def _create_job_and_run(
        self,
        *,
        workspace_id: int,
        module_name: str,
        json_file: str,
        base_run: dict[str, object],
    ) -> tuple[int, int]:
        with session_scope(self.session_factory) as session:
            import_job = ImportJobRepository(session).create(
                workspace_id=workspace_id,
                module_name=module_name,
                source_format=_source_format(json_file),
                input_path=json_file,
            )
            module_run = ModuleRunRepository(session).create(
                workspace_id=workspace_id,
                import_job_id=import_job.id,
                module_name=str(base_run["module_name"]),
                protocol=str(base_run["protocol"]),
                source_type=str(base_run["source_type"]),
                execution_status="running",
                tool_version=_as_str_or_none(base_run.get("tool_version")),
                target_scope=_as_str_or_none(base_run.get("target_scope")) or json_file,
                commandline_args_snapshot_json=base_run.get("commandline_args_snapshot_json"),
                started_at=parse_datetime(_as_str_or_none(base_run.get("started_at"))) or utcnow(),
                finished_at=parse_datetime(_as_str_or_none(base_run.get("finished_at"))),
                dedup_key=_as_str_or_none(base_run.get("dedup_key")),
            )
            return int(import_job.id), int(module_run.id)

    def _mark_job_and_run_failed(self, *, import_job_id: int, module_run_id: int, error_text: str) -> None:
        with session_scope(self.session_factory) as session:
            import_job = session.get(ImportJob, import_job_id)
            module_run = session.get(ModuleRun, module_run_id)
            if import_job is not None:
                import_job.status = "failed"
                import_job.error_text = error_text
                import_job.finished_at = utcnow()
            if module_run is not None:
                module_run.execution_status = "failed"
                module_run.finished_at = utcnow()

    def _persist_envelope(
        self,
        *,
        session: Session,
        workspace_id: int,
        module_run: ModuleRun,
        envelope: Any,
        host_repo: HostRepository,
        endpoint_repo: EndpointRepository,
        service_repo: ProtocolServiceRepository,
        observation_repo: RunObservationRepository,
        finding_repo: FindingRepository,
        artifact_repo: ArtifactRepository,
        evidence_repo: EvidenceRepository,
        extension_repo: ExtensionRepository,
        search_repo: SearchRepository,
        secret_repo: SecretRefRepository,
        stats: dict[str, object],
    ) -> None:
        del session  # Repositories own DB interaction; the session is passed for symmetry and future hooks.
        for observation_payload in envelope.observations:
            host = None
            if observation_payload.canonical_host_key:
                host = host_repo.upsert(
                    workspace_id=workspace_id,
                    canonical_key=observation_payload.canonical_host_key,
                    hostname=observation_payload.hostname,
                    fqdn=observation_payload.fqdn,
                    ip_address=observation_payload.ip_address,
                )

            endpoint = None
            if any(
                [
                    observation_payload.scheme,
                    observation_payload.host,
                    observation_payload.ip,
                    observation_payload.port,
                ]
            ):
                endpoint_host = (
                    observation_payload.host
                    or observation_payload.ip
                    or observation_payload.hostname
                    or observation_payload.canonical_host_key
                    or "-"
                )
                endpoint_key = (
                    f"{observation_payload.scheme or 'tcp'}://"
                    f"{endpoint_host}:{observation_payload.port or 0}{observation_payload.path or ''}"
                )
                endpoint = endpoint_repo.upsert(
                    workspace_id=workspace_id,
                    target_host_id=host.id if host else None,
                    canonical_key=endpoint_key,
                    scheme=observation_payload.scheme,
                    host=observation_payload.host,
                    ip=observation_payload.ip,
                    port=observation_payload.port,
                    path=observation_payload.path,
                    netloc=f"{endpoint_host}:{observation_payload.port}" if observation_payload.port else endpoint_host,
                )

            service = service_repo.upsert(
                workspace_id=workspace_id,
                endpoint_id=endpoint.id if endpoint else None,
                protocol=observation_payload.protocol,
                service_name=observation_payload.service_name or observation_payload.protocol,
                auth_required=observation_payload.auth_required,
                status=observation_payload.service_status or observation_payload.normalized_status,
                version=observation_payload.service_version,
                extra_summary_json=observation_payload.normalized_result_json,
            )

            observation_fingerprint = stable_hash(
                str(workspace_id),
                module_run.module_name,
                observation_payload.protocol,
                observation_payload.target_text,
                str(endpoint.id if endpoint else "-"),
                observation_payload.normalized_status,
                observation_payload.fingerprint_subject,
            )
            observation = observation_repo.upsert(
                workspace_id=workspace_id,
                module_run_id=module_run.id,
                target_host_id=host.id if host else None,
                endpoint_id=endpoint.id if endpoint else None,
                protocol_service_id=service.id,
                target_text=observation_payload.target_text,
                module_name=module_run.module_name,
                protocol=observation_payload.protocol,
                normalized_status=observation_payload.normalized_status,
                severity=observation_payload.severity,
                confidence=observation_payload.confidence,
                fingerprint=observation_fingerprint,
                source_type=module_run.source_type,
                raw_json_result_sanitized=observation_payload.raw_json_result_sanitized,
                normalized_result_json=observation_payload.normalized_result_json,
            )
            stats["observations"] = int(stats["observations"]) + 1

            created_findings = []
            for finding_payload in envelope.findings:
                fingerprint = stable_hash(
                    str(workspace_id),
                    finding_payload.protocol,
                    finding_payload.module_name,
                    finding_payload.finding_type,
                    observation_payload.target_text,
                    finding_payload.dedup_subject,
                    finding_payload.severity,
                )
                finding = finding_repo.upsert(
                    workspace_id=workspace_id,
                    module_run_id=module_run.id,
                    run_observation_id=observation.id,
                    target_host_id=host.id if host else None,
                    endpoint_id=endpoint.id if endpoint else None,
                    protocol_service_id=service.id,
                    title=finding_payload.title,
                    description=finding_payload.description,
                    finding_type=finding_payload.finding_type,
                    protocol=finding_payload.protocol,
                    module_name=finding_payload.module_name,
                    severity=finding_payload.severity,
                    confidence=finding_payload.confidence,
                    status=finding_payload.status,
                    dedup_key=finding_payload.dedup_subject,
                    fingerprint=fingerprint,
                )
                search_repo.upsert_document(
                    workspace_id=workspace_id,
                    entity_type="finding",
                    entity_id=str(finding.id),
                    title=finding.title,
                    body=finding.description,
                    tags_text=f"{finding.protocol} {finding.module_name} {finding.severity or ''}",
                )
                created_findings.append(finding)
                stats["findings"] = int(stats["findings"]) + 1

            artifact_rows = []
            for artifact_payload in envelope.artifacts:
                payload_json = _load_artifact_payload(artifact_payload.payload)
                compressed, _, size_bytes, sha256_value = compress_json_payload(payload_json)
                encrypted = self.cipher.encrypt(compressed)
                artifact = artifact_repo.create(
                    workspace_id=workspace_id,
                    module_run_id=module_run.id,
                    finding_id=created_findings[0].id if created_findings else None,
                    artifact_role=artifact_payload.artifact_role,
                    mime_type=artifact_payload.mime_type,
                    content_encoding=artifact_payload.content_encoding or encrypted.content_encoding,
                    sha256=sha256_value,
                    size_bytes=size_bytes,
                    sanitized_preview_text=artifact_payload.sanitized_preview_text,
                    content_blob=encrypted.payload,
                    expires_at=parse_datetime(artifact_payload.expires_at),
                    purge_after=parse_datetime(artifact_payload.purge_after),
                )
                artifact_rows.append(artifact)
                search_repo.upsert_document(
                    workspace_id=workspace_id,
                    entity_type="artifact",
                    entity_id=str(artifact.id),
                    title=f"{artifact.artifact_role}:{module_run.module_name}",
                    body=artifact.sanitized_preview_text,
                    tags_text=f"{module_run.module_name} {module_run.protocol}",
                )
                stats["artifacts"] = int(stats["artifacts"]) + 1

            for evidence_payload in envelope.evidence:
                evidence_repo.create(
                    workspace_id=workspace_id,
                    module_run_id=module_run.id,
                    finding_id=(
                        created_findings[evidence_payload.finding_index].id
                        if evidence_payload.finding_index is not None
                        and evidence_payload.finding_index < len(created_findings)
                        else None
                    ),
                    artifact_id=(
                        artifact_rows[evidence_payload.artifact_index].id
                        if evidence_payload.artifact_index is not None
                        and evidence_payload.artifact_index < len(artifact_rows)
                        else None
                    ),
                    evidence_type=evidence_payload.evidence_type,
                    title=evidence_payload.title,
                    description=evidence_payload.description,
                    preview_text=evidence_payload.preview_text,
                    retention_class=evidence_payload.retention_class,
                    expires_at=parse_datetime(evidence_payload.expires_at),
                )

            for extension_payload in envelope.extensions:
                extension_values = dict(extension_payload.values)
                extension_values.update(
                    {
                        "workspace_id": workspace_id,
                        "run_observation_id": observation.id,
                        "protocol_service_id": service.id,
                    }
                )
                extension_repo.create(table_name=extension_payload.table_name, values=extension_values)

            raw_json = observation_payload.raw_json_result_sanitized
            if raw_json:
                sanitized = sanitize_payload(raw_json)
                for secret_candidate in sanitized.secret_candidates:
                    ref = build_secret_ref(secret_candidate)
                    secret_repo.upsert(
                        workspace_id=workspace_id,
                        secret_kind=ref.secret_kind,
                        redacted_value=ref.redacted_value,
                        fingerprint=ref.fingerprint,
                        source_hint=ref.source_hint,
                    )


def _prepend_record(first_record: dict[str, Any], records_iter: Iterator[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    yield first_record
    yield from records_iter


def _read_records(path: str) -> Iterable[dict[str, Any]]:
    with Path(path).open("r", encoding="utf-8") as handle:
        if path.endswith(".jsonl"):
            yield from _read_jsonl_records(handle)
            return

        try:
            payload = json.load(handle)
        except json.JSONDecodeError:
            handle.seek(0)
            yielded = False
            for item in _read_jsonl_records(handle):
                yielded = True
                yield item
            if yielded:
                return
            raise

        if isinstance(payload, list):
            for item in payload:
                if isinstance(item, dict):
                    yield item
            return
        if isinstance(payload, dict):
            yield payload


def _read_jsonl_records(handle: Iterator[str]) -> Iterable[dict[str, Any]]:
    for raw_line in handle:
        line = raw_line.strip()
        if not line:
            continue
        payload = json.loads(line)
        if isinstance(payload, dict):
            yield payload


def _source_format(path: str) -> str:
    if path.endswith(".jsonl"):
        return "jsonl"
    try:
        with Path(path).open("r", encoding="utf-8") as handle:
            try:
                json.load(handle)
            except json.JSONDecodeError:
                handle.seek(0)
                for raw_line in handle:
                    if raw_line.strip():
                        return "jsonl"
            return "json"
    except OSError:
        return "json"


def _load_artifact_payload(payload: bytes) -> dict[str, Any]:
    try:
        decoded = payload.decode("utf-8")
    except UnicodeDecodeError:
        decoded = payload.decode("utf-8", errors="replace")
    try:
        loaded = json.loads(decoded)
    except Exception:
        return {"payload": decoded}
    if isinstance(loaded, dict):
        return loaded
    if isinstance(loaded, list):
        return {"items": loaded}
    return {"payload": loaded}


def _as_str_or_none(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
