from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import func, select

from redposture_core.db.dto.query import FindingFilter
from redposture_core.db.models import ExportJob, ImportJob, Tag, finding_tags
from redposture_core.db.repositories import (
    AppMetadataRepository,
    AppStateRepository,
    ArtifactRepository,
    EndpointRepository,
    EvidenceRepository,
    ExportJobRepository,
    ExtensionRepository,
    FindingRepository,
    HostRepository,
    ImportJobRepository,
    ModuleRunRepository,
    ProtocolServiceRepository,
    RunObservationRepository,
    SearchRepository,
    SecretRefRepository,
    WorkspaceRepository,
)
from redposture_core.db.session import session_scope


def _seed_run(session, workspace_id: int):
    run = ModuleRunRepository(session).create(
        workspace_id=workspace_id,
        module_name="grafana",
        protocol="grafana",
        source_type="scan",
        execution_status="success",
    )
    host = HostRepository(session).upsert(
        workspace_id=workspace_id,
        canonical_key="10.0.0.10",
        hostname="10.0.0.10",
        fqdn=None,
        ip_address="10.0.0.10",
    )
    endpoint = EndpointRepository(session).upsert(
        workspace_id=workspace_id,
        target_host_id=host.id,
        canonical_key="http://10.0.0.10:3000",
        scheme="http",
        host="10.0.0.10",
        ip="10.0.0.10",
        port=3000,
        path=None,
        netloc="10.0.0.10:3000",
    )
    service = ProtocolServiceRepository(session).upsert(
        workspace_id=workspace_id,
        endpoint_id=endpoint.id,
        protocol="grafana",
        service_name="grafana",
        auth_required=False,
        status="open_no_auth",
        version="10.0.0",
        extra_summary_json={"status": "open_no_auth"},
    )
    return run, host, endpoint, service


def test_workspace_state_and_metadata_repositories(session_factory) -> None:
    with session_scope(session_factory) as session:
        repo = WorkspaceRepository(session)
        created = repo.create(slug="acme", display_name="Acme", client_name="Client", environment_name="Prod")
        assert repo.get_by_slug("acme") is created
        assert [item.slug for item in repo.list()] == ["acme"]
        created.deleted_at = datetime.now(timezone.utc)
        session.flush()
        assert repo.get_by_slug("acme") is None
        assert repo.list() == []
        created.deleted_at = None
        session.flush()

        state_repo = AppStateRepository(session)
        assert state_repo.get_active_workspace_slug() is None
        state_repo.set_active_workspace_slug("acme")
        assert state_repo.get_active_workspace_slug() == "acme"

        meta_repo = AppMetadataRepository(session)
        assert meta_repo.get("schema_semver") == "1.0.0"
        meta_repo.set("schema_semver", "1.0.1")
        assert meta_repo.get("schema_semver") == "1.0.1"


def test_inventory_repositories_upsert_and_list(workspace_id: int, session_factory) -> None:
    with session_scope(session_factory) as session:
        host_repo = HostRepository(session)
        endpoint_repo = EndpointRepository(session)
        service_repo = ProtocolServiceRepository(session)

        host = host_repo.upsert(
            workspace_id=workspace_id,
            canonical_key="10.0.0.10",
            hostname="host-a",
            fqdn=None,
            ip_address="10.0.0.10",
        )
        updated_host = host_repo.upsert(
            workspace_id=workspace_id,
            canonical_key="10.0.0.10",
            hostname=None,
            fqdn="host-a.internal",
            ip_address=None,
        )
        assert updated_host.id == host.id
        assert updated_host.fqdn == "host-a.internal"
        assert [item.canonical_key for item in host_repo.list(workspace_id=workspace_id)] == ["10.0.0.10"]

        endpoint = endpoint_repo.upsert(
            workspace_id=workspace_id,
            target_host_id=host.id,
            canonical_key="http://10.0.0.10:3000",
            scheme="http",
            host="10.0.0.10",
            ip="10.0.0.10",
            port=3000,
            path="/",
            netloc="10.0.0.10:3000",
        )
        updated_endpoint = endpoint_repo.upsert(
            workspace_id=workspace_id,
            target_host_id=host.id,
            canonical_key="http://10.0.0.10:3000",
            scheme=None,
            host=None,
            ip=None,
            port=None,
            path="/login",
            netloc=None,
        )
        assert updated_endpoint.id == endpoint.id
        assert updated_endpoint.path == "/login"
        assert endpoint_repo.list(workspace_id=workspace_id, host_id=host.id)[0].id == endpoint.id

        service = service_repo.upsert(
            workspace_id=workspace_id,
            endpoint_id=endpoint.id,
            protocol="grafana",
            service_name="grafana",
            auth_required=False,
            status="open_no_auth",
            version="10.0.0",
            extra_summary_json={"a": 1},
        )
        updated_service = service_repo.upsert(
            workspace_id=workspace_id,
            endpoint_id=endpoint.id,
            protocol="grafana",
            service_name="grafana",
            auth_required=None,
            status="valid_credentials",
            version=None,
            extra_summary_json={"b": 2},
        )
        assert updated_service.id == service.id
        assert updated_service.status == "valid_credentials"
        assert updated_service.extra_summary_json == {"b": 2}

        run = ModuleRunRepository(session).create(
            workspace_id=workspace_id,
            module_name="grafana",
            protocol="grafana",
            source_type="scan",
            execution_status="success",
        )
        RunObservationRepository(session).upsert(
            workspace_id=workspace_id,
            module_run_id=run.id,
            target_host_id=host.id,
            endpoint_id=endpoint.id,
            target_text="10.0.0.10",
            module_name="grafana",
            protocol="grafana",
            normalized_status="open_no_auth",
            severity="high",
            confidence="high",
            fingerprint="inv-obs-grafana",
            source_type="scan",
            raw_json_result_sanitized={"host": "10.0.0.10"},
            normalized_result_json={"status": "open_no_auth"},
        )

        assert [item.canonical_key for item in host_repo.list(workspace_id=workspace_id, module_name="grafana")] == [
            "10.0.0.10"
        ]
        assert endpoint_repo.list(workspace_id=workspace_id, module_name="grafana")[0].id == endpoint.id


def test_finding_repository_upsert_and_filters(workspace_id: int, session_factory) -> None:
    with session_scope(session_factory) as session:
        repo = FindingRepository(session)
        first = repo.upsert(
            workspace_id=workspace_id,
            title="Grafana anonymous access",
            description="A",
            finding_type="anonymous_access",
            protocol="grafana",
            module_name="grafana",
            severity="high",
            confidence="high",
            status="open",
            dedup_key="g1",
            fingerprint="fp-1",
        )
        second = repo.upsert(
            workspace_id=workspace_id,
            title="Postgres weak default creds",
            description="B",
            finding_type="weak_default_creds",
            protocol="postgres",
            module_name="postgres",
            severity="medium",
            confidence="high",
            status="open",
            dedup_key="p1",
            fingerprint="fp-2",
        )
        repo.upsert(
            workspace_id=workspace_id,
            title="Grafana anonymous access updated",
            description="A2",
            finding_type="anonymous_access",
            protocol="grafana",
            module_name="grafana",
            severity="critical",
            confidence="high",
            status="closed",
            dedup_key="g1",
            fingerprint="fp-1",
        )
        first.last_seen_at = datetime(2026, 3, 10, tzinfo=timezone.utc)
        second.last_seen_at = datetime(2026, 3, 1, tzinfo=timezone.utc)
        tag = Tag(workspace_id=workspace_id, name="prod")
        session.add(tag)
        session.flush()
        first.tags.append(tag)
        session.flush()

        assert (
            repo.list(workspace_id=workspace_id, filters=FindingFilter(module_name="grafana"))[0].fingerprint == "fp-1"
        )
        assert repo.list(workspace_id=workspace_id, filters=FindingFilter(protocol="postgres"))[0].fingerprint == "fp-2"
        assert repo.list(workspace_id=workspace_id, filters=FindingFilter(severity="critical"))[0].fingerprint == "fp-1"
        assert repo.list(workspace_id=workspace_id, filters=FindingFilter(status="closed"))[0].fingerprint == "fp-1"
        assert repo.list(workspace_id=workspace_id, filters=FindingFilter(tag="prod"))[0].fingerprint == "fp-1"
        assert (
            repo.list(workspace_id=workspace_id, filters=FindingFilter(date_from="2026-03-05T00:00:00Z"))[0].fingerprint
            == "fp-1"
        )
        assert (
            repo.list(workspace_id=workspace_id, filters=FindingFilter(date_to="2026-03-05T00:00:00Z"))[0].fingerprint
            == "fp-2"
        )

        finding_tag_rows = session.execute(select(func.count()).select_from(finding_tags)).scalar_one()
        assert finding_tag_rows == 1


def test_run_repositories_upsert_and_target_filter(workspace_id: int, session_factory) -> None:
    with session_scope(session_factory) as session:
        run_repo = ModuleRunRepository(session)
        observation_repo = RunObservationRepository(session)
        run = run_repo.create(
            workspace_id=workspace_id,
            module_name="grafana",
            protocol="grafana",
            source_type="scan",
            execution_status="success",
        )
        observation = observation_repo.upsert(
            workspace_id=workspace_id,
            module_run_id=run.id,
            target_text="10.0.0.10",
            module_name="grafana",
            protocol="grafana",
            normalized_status="open_no_auth",
            severity="high",
            confidence="high",
            fingerprint="obs-fp",
            source_type="scan",
            raw_json_result_sanitized={"host": "10.0.0.10"},
            normalized_result_json={"status": "open_no_auth"},
        )
        updated = observation_repo.upsert(
            workspace_id=workspace_id,
            module_run_id=run.id,
            target_text="10.0.0.10",
            module_name="grafana",
            protocol="grafana",
            normalized_status="valid_credentials",
            severity="medium",
            confidence="high",
            fingerprint="obs-fp",
            source_type="scan",
            raw_json_result_sanitized={"host": "10.0.0.10"},
            normalized_result_json={"status": "valid_credentials"},
        )
        assert updated.id == observation.id
        assert updated.normalized_status == "valid_credentials"
        run.deleted_at = datetime.now(timezone.utc)
        session.flush()
        assert run_repo.list(workspace_id=workspace_id, module_name="grafana") == []
        run.deleted_at = None
        session.flush()
        assert run_repo.list(workspace_id=workspace_id, target_text="10.0.0.10")[0].id == run.id
        assert run_repo.list(workspace_id=workspace_id, module_name="grafana")[0].id == run.id


def test_artifact_evidence_job_secret_and_extension_repositories(workspace_id: int, session_factory) -> None:
    with session_scope(session_factory) as session:
        run, _, _, service = _seed_run(session, workspace_id)
        observation = RunObservationRepository(session).upsert(
            workspace_id=workspace_id,
            module_run_id=run.id,
            protocol_service_id=service.id,
            target_text="10.0.0.10",
            module_name="grafana",
            protocol="grafana",
            normalized_status="open_no_auth",
            severity="high",
            confidence="high",
            fingerprint="repo-observation",
            source_type="scan",
            raw_json_result_sanitized={"status": "open_no_auth"},
            normalized_result_json={"status": "open_no_auth"},
        )
        artifact_repo = ArtifactRepository(session)
        evidence_repo = EvidenceRepository(session)
        secret_repo = SecretRefRepository(session)
        import_repo = ImportJobRepository(session)
        export_repo = ExportJobRepository(session)
        extension_repo = ExtensionRepository(session)

        artifact = artifact_repo.create(
            workspace_id=workspace_id,
            module_run_id=run.id,
            artifact_role="raw_payload",
            sha256="abc",
            size_bytes=3,
            content_blob=b"abc",
            sanitized_preview_text="preview",
        )
        evidence = evidence_repo.create(
            workspace_id=workspace_id,
            module_run_id=run.id,
            artifact_id=artifact.id,
            evidence_type="observation",
            title="raw payload",
        )
        assert artifact_repo.list(workspace_id=workspace_id, module_run_id=run.id)[0].id == artifact.id
        assert artifact_repo.list(workspace_id=workspace_id, module_name="grafana")[0].id == artifact.id
        assert evidence_repo.list_for_run(module_run_id=run.id)[0].id == evidence.id
        evidence.deleted_at = datetime.now(timezone.utc)
        session.flush()
        assert evidence_repo.list_for_run(module_run_id=run.id) == []
        evidence.deleted_at = None
        session.flush()

        import_job = import_repo.create(
            workspace_id=workspace_id, module_name="grafana", source_format="json", input_path="in.json"
        )
        export_job = export_repo.create(
            workspace_id=workspace_id, export_kind="findings", output_format="json", output_path="out.json"
        )
        assert import_job.status == "running"
        assert export_job.status == "running"
        assert session.scalar(select(func.count()).select_from(ImportJob)) == 1
        assert session.scalar(select(func.count()).select_from(ExportJob)) == 1

        first_ref = secret_repo.upsert(
            workspace_id=workspace_id,
            secret_kind="password",
            redacted_value="<redacted:password>",
            fingerprint="secret-fp",
            source_hint="payload.password",
        )
        second_ref = secret_repo.upsert(
            workspace_id=workspace_id,
            secret_kind="password",
            redacted_value="<redacted:password>",
            fingerprint="secret-fp",
            source_hint="payload.password2",
        )
        assert first_ref.id == second_ref.id

        ext_row = extension_repo.create(
            table_name="grafana_datasources",
            values={
                "workspace_id": workspace_id,
                "run_observation_id": observation.id,
                "protocol_service_id": service.id,
                "name": "prometheus",
                "datasource_type": "prometheus",
                "url": "https://metrics.internal",
            },
        )
        assert ext_row.name == "prometheus"

        with pytest.raises(KeyError):
            extension_repo.create(table_name="missing_table", values={})


def test_search_repository_upserts_and_returns_results(workspace_id: int, session_factory) -> None:
    with session_scope(session_factory) as session:
        finding = FindingRepository(session).upsert(
            workspace_id=workspace_id,
            title="Grafana anonymous access",
            description="datasource leakage",
            finding_type="anonymous_access",
            protocol="grafana",
            module_name="grafana",
            severity="high",
            confidence="high",
            status="open",
            dedup_key="grafana",
            fingerprint="search-finding-1",
        )
        repo = SearchRepository(session)
        created = repo.upsert_document(
            workspace_id=workspace_id,
            entity_type="finding",
            entity_id=str(finding.id),
            title="Grafana anonymous access",
            body="datasource leakage",
            tags_text="grafana high",
        )
        updated = repo.upsert_document(
            workspace_id=workspace_id,
            entity_type="finding",
            entity_id=str(finding.id),
            title="Grafana anonymous access updated",
            body="datasource leakage",
            tags_text="grafana critical",
        )
        assert updated.id == created.id
        rows = repo.search(workspace_id=workspace_id, query="Grafana")
        assert rows
        assert rows[0]["entity_type"] == "finding"
        finding.deleted_at = datetime.now(timezone.utc)
        session.flush()
        assert repo.search(workspace_id=workspace_id, query="Grafana") == []
