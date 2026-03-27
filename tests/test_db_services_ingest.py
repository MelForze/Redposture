from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest
from sqlalchemy import func, select

from redposture_core.db.ingest import build_ingest_registry
from redposture_core.db.ingest.registry import (
    ExportersIngestor,
    GenericModuleIngestor,
    GrafanaIngestor,
    KubeApiIngestor,
    PostgresIngestor,
    _exporter_findings,
    _exporter_fingerprint_subject,
    _exporter_phase,
    _exporter_severity,
    _exporter_status,
    _exporter_validation_reasons,
)
from redposture_core.db.models import (
    Artifact,
    Finding,
    GrafanaDatasource,
    ImportJob,
    ModuleRun,
    PostgresTableAsset,
    RunObservation,
    SecretRef,
)
from redposture_core.db.services import IngestService
from redposture_core.db.services.ingest import _read_records, _source_format
from redposture_core.db.session import session_scope


class _BrokenAdapter:
    module_name = "grafana"

    def build_run(self, _first_record: dict[str, object]):
        from redposture_core.db.dto.ingest import ModuleRunCreate

        return ModuleRunCreate(module_name="grafana", protocol="grafana", source_type="import")

    def ingest_record(self, record: dict[str, object]):
        from redposture_core.db.dto.ingest import ExtensionRecord, IngestEnvelope, ObservationCreate

        return IngestEnvelope(
            module_run=self.build_run(record),
            observations=[ObservationCreate(protocol="grafana", normalized_status="open_no_auth")],
            extensions=[ExtensionRecord(table_name="missing_table", values={})],
        )


def test_read_records_supports_json_and_jsonl(write_json_payload, write_jsonl_payload) -> None:
    json_path = write_json_payload("records.json", [{"host": "a"}, {"host": "b"}, "skip"])
    jsonl_path = write_jsonl_payload("records.jsonl", [{"host": "a"}, {"host": "b"}, [1, 2, 3]])

    assert list(_read_records(str(json_path))) == [{"host": "a"}, {"host": "b"}]
    assert list(_read_records(str(jsonl_path))) == [{"host": "a"}, {"host": "b"}]
    assert _source_format(str(jsonl_path)) == "jsonl"
    assert _source_format(str(json_path)) == "json"


def test_read_records_auto_detects_jsonl_payload_in_json_file(tmp_path: Path) -> None:
    payload_path = tmp_path / "records.json"
    payload_path.write_text('{"host":"a"}\n{"host":"b"}\n', encoding="utf-8")

    assert list(_read_records(str(payload_path))) == [{"host": "a"}, {"host": "b"}]
    assert _source_format(str(payload_path)) == "jsonl"


def test_ingest_registry_contains_supported_modules_and_rejects_unknown() -> None:
    registry = build_ingest_registry()
    for module_name in (
        "exporters",
        "registry",
        "grafana",
        "proxmox",
        "gitlab",
        "consul",
        "kubeapi",
        "postgres",
        "clickhouse",
        "redis",
        "etcd",
        "qdrant",
        "kafka",
        "zookeeper",
    ):
        assert registry.get(module_name).module_name == module_name

    with pytest.raises(ValueError, match="unsupported ingest module"):
        registry.get("missing")


def test_generic_and_specialized_ingestors_create_expected_envelopes() -> None:
    generic = GenericModuleIngestor("redis", "redis").ingest_record(
        {"host": "10.0.0.40", "port": 6379, "status": "open_no_auth"}
    )
    assert generic.observations[0].protocol == "redis"
    assert generic.findings[0].finding_type == "open_no_auth"
    assert generic.artifacts[0].artifact_role == "raw_payload"
    assert generic.evidence[0].artifact_index == 0

    grafana = GrafanaIngestor().ingest_record(
        {
            "host": "10.0.0.10",
            "status": "open_no_auth",
            "type": "datasources_dump",
            "datasources": [{"name": "prom", "type": "prometheus", "url": "https://metrics"}],
        }
    )
    assert any(item.table_name == "grafana_datasources" for item in grafana.extensions)
    assert any(item.finding_type == "anonymous_access" for item in grafana.findings)

    kubeapi = KubeApiIngestor().ingest_record(
        {"host": "10.0.0.20", "auth_required": False, "namespaces": ["default"], "pods": [{"name": "api"}]}
    )
    assert any(item.table_name == "kube_resources" for item in kubeapi.extensions)
    assert any(item.finding_type == "anonymous_access" for item in kubeapi.findings)

    postgres = PostgresIngestor().ingest_record(
        {
            "host": "10.0.0.30",
            "status": "weak_default_creds",
            "type": "tables_dump",
            "tables": ["appdb.public.users"],
        }
    )
    assert any(item.table_name == "postgres_tables" for item in postgres.extensions)
    assert any(item.finding_type == "weak_default_creds" for item in postgres.findings)

    exporters = ExportersIngestor().ingest_record(
        {
            "host": "10.0.0.40",
            "port": 9187,
            "exporter": "postgres_exporter",
            "endpoint": "/debug/vars",
            "url": "http://10.0.0.40:9187/debug/vars",
            "ok": True,
            "status": 200,
            "body": '{"data_source_name":"postgresql://postgres:postgres@db.internal/app"}',
        }
    )
    assert exporters.module_run.source_type == "collect"
    assert exporters.observations[0].normalized_status == "credential_exposure"
    assert any("connection_string_auth" in item.finding_type for item in exporters.findings)
    assert "postgres:postgres@db.internal" not in exporters.artifacts[0].sanitized_preview_text
    assert any(
        marker in (exporters.artifacts[0].sanitized_preview_text or "")
        for marker in ("<redacted:url_basic_auth>", "<redacted:dsn_auth>")
    )
    assert "postgres:postgres@db/app" not in exporters.findings[0].description


def test_ingest_registry_helpers_cover_exporter_phase_status_and_findings() -> None:
    assert _exporter_phase({"source_type": "import"}) == "import"
    assert _exporter_phase({"callback_target": "10.0.0.1"}) == "trigger"
    assert _exporter_phase({"body": "metrics"}) == "collect"
    assert _exporter_phase({"detected": True}) == "scan"
    assert _exporter_phase({}) is None

    reasons = _exporter_validation_reasons(
        [{"reason": "connection_string_auth, default_creds_known_pair"}, {"reason": "connection_string_auth"}]
    )
    assert reasons == ["connection_string_auth", "default_creds_known_pair"]

    assert _exporter_status({"status": "open_no_auth"}, phase="collect", validation_reasons=[]) == "open_no_auth"
    assert _exporter_status({}, phase="collect", validation_reasons=["connection_string_auth"]) == "credential_exposure"
    assert _exporter_status({"ok": True}, phase="collect", validation_reasons=[]) == "collect_success"
    assert _exporter_status({"error": "boom"}, phase="trigger", validation_reasons=[]) == "trigger_error"
    assert _exporter_status({"detected": True}, phase="scan", validation_reasons=[]) == "detected"
    assert _exporter_status({}, phase=None, validation_reasons=[]) == "observed"

    assert _exporter_severity({}, validation_reasons=["default_creds_known_pair"]) == "high"
    assert _exporter_severity({}, validation_reasons=["other_reason"]) == "medium"
    assert _exporter_severity({"status": "auth_required"}, validation_reasons=[]) == "medium"

    assert (
        _exporter_fingerprint_subject(
            {"endpoint": "/debug/vars"},
            phase="collect",
            validation_reasons=["connection_string_auth"],
        )
        == "collect:/debug/vars:connection_string_auth"
    )
    assert (
        _exporter_fingerprint_subject({"status": "open_no_auth"}, phase="scan", validation_reasons=[]) == "open_no_auth"
    )
    assert _exporter_fingerprint_subject({}, phase="scan", validation_reasons=[]) == "scan"

    findings = _exporter_findings(
        record={"endpoint": "/debug/vars", "status": "valid_credentials"},
        exporter_name="postgres_exporter",
        host="10.0.0.1",
        port=9187,
        phase="collect",
        severity="high",
        confidence="high",
        validation_hits=[{"sample": "postgres://postgres:postgres@db/app"}],
        validation_reasons=["connection_string_auth"],
    )
    assert len(findings) == 2
    assert findings[0].finding_type == "connection_string_auth"
    assert findings[1].finding_type == "valid_credentials"
    assert "postgres:postgres@db/app" not in findings[0].description
    assert any(marker in findings[0].description for marker in ("<redacted:url_basic_auth>", "<redacted:dsn_auth>"))


def test_specialized_ingestors_skip_invalid_items_and_cover_additional_assets() -> None:
    grafana = GrafanaIngestor().ingest_record(
        {
            "host": "10.0.0.10",
            "status": "observed",
            "type": "datasources_dump",
            "datasources": ["skip", {"name": "prom", "type": "prometheus", "url": "https://metrics"}],
        }
    )
    assert len(grafana.extensions) == 1
    assert grafana.findings == []

    kubeapi = KubeApiIngestor().ingest_record(
        {
            "host": "10.0.0.20",
            "auth_required": True,
            "namespaces": ["default"],
            "pods": ["skip", {"namespace": "prod", "name": "api"}],
        }
    )
    assert len(kubeapi.extensions) == 2
    assert kubeapi.findings == []

    postgres_db = PostgresIngestor().ingest_record(
        {
            "host": "10.0.0.30",
            "status": "observed",
            "type": "databases_dump",
            "databases": ["appdb"],
        }
    )
    assert postgres_db.extensions[0].table_name == "postgres_databases"

    postgres_table = PostgresIngestor().ingest_record(
        {
            "host": "10.0.0.30",
            "status": "observed",
            "type": "table_dump",
            "database": "appdb",
            "table": "public.users",
            "columns": ["id", "email"],
        }
    )
    assert postgres_table.extensions[0].table_name == "postgres_tables"
    assert postgres_table.extensions[0].values["columns_json"] == ["id", "email"]
    assert postgres_table.findings == []

    exporters_scan = ExportersIngestor().ingest_record(
        {"host": "10.0.0.40", "port": 9308, "exporter": "kafka_exporter", "detected": True}
    )
    assert exporters_scan.module_run.source_type == "scan"
    assert exporters_scan.observations[0].normalized_status == "detected"
    assert exporters_scan.findings == []

    exporters_trigger = ExportersIngestor().ingest_record(
        {
            "host": "10.0.0.41",
            "port": 9121,
            "exporter": "redis_exporter",
            "callback_target": "10.0.0.99",
            "probe_success": True,
        }
    )
    assert exporters_trigger.module_run.source_type == "trigger"
    assert exporters_trigger.observations[0].normalized_status == "trigger_success"
    assert exporters_trigger.findings == []

    exporters_import = ExportersIngestor().ingest_record(
        {
            "host": "10.0.0.42",
            "port": 9113,
            "exporter": "nginx_exporter",
            "source_type": "import",
        }
    )
    assert exporters_import.module_run.source_type == "import"
    assert exporters_import.observations[0].normalized_status == "observed"


def test_ingest_file_supports_jsonl_and_deduplicates_findings(db_service, workspace, write_jsonl_payload) -> None:
    ingest_service = IngestService(db_service.session_factory)
    payload_path = write_jsonl_payload(
        "grafana.jsonl",
        [
            {
                "host": "10.0.0.10",
                "port": 3000,
                "status": "open_no_auth",
                "type": "datasources_dump",
                "datasources": [],
            },
            {
                "host": "10.0.0.10",
                "port": 3000,
                "status": "open_no_auth",
                "type": "datasources_dump",
                "datasources": [],
            },
        ],
    )

    stats = ingest_service.ingest_file(workspace_slug=None, module_name="grafana", json_file=str(payload_path))

    assert stats["records"] == 2
    with session_scope(db_service.session_factory) as session:
        assert session.scalar(select(func.count()).select_from(ModuleRun)) == 1
        assert session.scalar(select(func.count()).select_from(RunObservation)) == 1
        assert session.scalar(select(func.count()).select_from(Finding)) == 2


def test_ingest_file_raises_for_empty_records(db_service, workspace, write_json_payload) -> None:
    ingest_service = IngestService(db_service.session_factory)
    empty_path = write_json_payload("empty.json", [])

    with pytest.raises(ValueError, match="no JSON records"):
        ingest_service.ingest_file(workspace_slug=None, module_name="grafana", json_file=str(empty_path))


def test_ingest_file_failure_marks_import_and_run_failed(
    db_service, workspace, write_json_payload, monkeypatch: pytest.MonkeyPatch
) -> None:
    ingest_service = IngestService(db_service.session_factory)
    ingest_service.registry = build_ingest_registry()
    monkeypatch.setattr(ingest_service.registry, "get", lambda _module_name: _BrokenAdapter())
    path = write_json_payload("broken.json", [{"host": "10.0.0.10"}])

    with pytest.raises(KeyError):
        ingest_service.ingest_file(workspace_slug=None, module_name="grafana", json_file=str(path))

    with session_scope(db_service.session_factory) as session:
        job = session.scalar(select(ImportJob).order_by(ImportJob.id.desc()))
        run = session.scalar(select(ModuleRun).order_by(ModuleRun.id.desc()))
        assert job is not None
        assert run is not None
        assert job.status == "failed"
        assert "missing_table" in str(job.error_text)
        assert run.execution_status == "failed"


def test_ingest_creates_specialized_assets_and_sanitized_artifact_blobs(
    db_service, workspace, db_fixture_dir: Path
) -> None:
    ingest_service = IngestService(db_service.session_factory)
    ingest_service.ingest_file(
        workspace_slug=workspace.slug, module_name="grafana", json_file=str(db_fixture_dir / "grafana.json")
    )
    ingest_service.ingest_file(
        workspace_slug=workspace.slug, module_name="postgres", json_file=str(db_fixture_dir / "postgres.json")
    )

    with session_scope(db_service.session_factory) as session:
        assert session.scalar(select(func.count()).select_from(GrafanaDatasource)) == 2
        assert session.scalar(select(func.count()).select_from(PostgresTableAsset)) == 2
        artifact = session.scalar(select(Artifact).order_by(Artifact.id.asc()))
        assert artifact is not None
        restored = json.loads(gzip.decompress(bytes(artifact.content_blob)).decode("utf-8"))
        assert isinstance(restored, dict)


def test_ingest_redacts_secret_payloads_and_creates_secret_refs(db_service, workspace, write_json_payload) -> None:
    ingest_service = IngestService(db_service.session_factory)
    payload_path = write_json_payload(
        "redis.json",
        [
            {
                "host": "10.10.10.40",
                "port": 6379,
                "status": "open_no_auth",
                "password": "SuperSecret!2026",
                "connection": "redis://default:default@redis.internal:6379/0",
            }
        ],
    )

    stats = ingest_service.ingest_file(workspace_slug=workspace.slug, module_name="redis", json_file=str(payload_path))
    assert stats["records"] == 1

    with session_scope(db_service.session_factory) as session:
        observation = session.scalar(select(RunObservation))
        assert observation is not None
        dumped = json.dumps(observation.raw_json_result_sanitized, ensure_ascii=False)
        assert "SuperSecret!2026" not in dumped
        assert "<redacted:password>" in dumped
        assert any(marker in dumped for marker in ("<redacted:url_basic_auth>", "<redacted:dsn_auth>"))
        assert session.scalar(select(func.count()).select_from(SecretRef)) >= 2
        artifact = session.scalar(select(Artifact))
        assert artifact is not None
        assert artifact.sanitized_preview_text is not None
        assert "SuperSecret!2026" not in artifact.sanitized_preview_text
