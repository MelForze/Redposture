from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from redposture_core.db.dto.query import FindingFilter
from redposture_core.db.models import Finding, ModuleRun, RunObservation
from redposture_core.db.services import IngestService, QueryService
from redposture_core.db.services.query import (
    _classify_exporter_hit_phase,
    _finding_to_exporter_stage_row,
    _finding_to_recent_hit,
    _is_successful_exporter_hit,
    _observation_detail,
    _parse_exporter_finding_description,
    _resource_summary_from_raw,
    _run_to_recent_hit,
    _split_description_sample,
)
from redposture_core.db.session import session_scope


def test_query_service_lists_inventory_findings_runs_artifacts_and_search(
    db_service, workspace, db_fixture_dir: Path
) -> None:
    ingest_service = IngestService(db_service.session_factory)
    ingest_service.ingest_file(
        workspace_slug=workspace.slug, module_name="grafana", json_file=str(db_fixture_dir / "grafana.json")
    )
    ingest_service.ingest_file(
        workspace_slug=workspace.slug, module_name="kubeapi", json_file=str(db_fixture_dir / "kubeapi.json")
    )
    query_service = QueryService(db_service.session_factory)

    hosts = query_service.list_hosts(workspace_id=workspace.id)
    assert {item.canonical_key for item in hosts} >= {"10.10.10.10", "10.10.10.20"}
    grafana_hosts = query_service.list_hosts(workspace_id=workspace.id, module_name="grafana")
    assert [item.canonical_key for item in grafana_hosts] == ["10.10.10.10"]

    endpoints = query_service.list_endpoints(workspace_id=workspace.id)
    assert any(item.port == 3000 for item in endpoints)
    host_endpoints = query_service.list_endpoints(workspace_id=workspace.id, host_id=hosts[0].id)
    assert host_endpoints
    grafana_endpoints = query_service.list_endpoints(workspace_id=workspace.id, module_name="grafana")
    assert [item.port for item in grafana_endpoints] == [3000]

    findings = query_service.list_findings(workspace_id=workspace.id, filters=FindingFilter(module_name="grafana"))
    assert all(item.module_name == "grafana" for item in findings)

    runs = query_service.list_runs(workspace_id=workspace.id, target_text="10.10.10.10")
    assert any(item.module_name == "grafana" for item in runs)
    grafana_runs = query_service.list_runs(workspace_id=workspace.id, module_name="grafana")
    assert grafana_runs
    assert all(item.module_name == "grafana" for item in grafana_runs)

    artifacts = query_service.list_artifacts(workspace_id=workspace.id, module_run_id=runs[0].id)
    assert artifacts
    grafana_artifacts = query_service.list_artifacts(workspace_id=workspace.id, module_name="grafana")
    assert grafana_artifacts

    summary = query_service.get_module_summary(
        workspace_id=workspace.id,
        module_name="grafana",
    )
    assert summary.module == "grafana"
    assert summary.hosts_count == 1
    assert summary.endpoints_count == 1
    assert summary.findings_count >= 1
    assert summary.runs_count >= 1
    assert summary.artifacts_count >= 1
    assert summary.last_seen_at is not None

    recent_hits = query_service.list_recent_module_hits(
        workspace_id=workspace.id,
        module_name="grafana",
    )
    assert recent_hits
    assert len(recent_hits) <= query_service.MODULE_RECENT_HITS_LIMIT
    assert all(item.module == "grafana" for item in recent_hits)
    assert {item.finding_type for item in recent_hits} >= {"open_no_auth", "anonymous_access"}
    assert all(item.target == "10.10.10.10:3000" for item in recent_hits)

    dashboard = query_service.get_module_dashboard(
        workspace_id=workspace.id,
        module_name="grafana",
    )
    assert dashboard.module == "grafana"
    assert dashboard.summary == summary
    assert len(dashboard.findings) <= query_service.MODULE_DASHBOARD_LIMIT
    assert len(dashboard.hosts) <= query_service.MODULE_DASHBOARD_LIMIT
    assert len(dashboard.endpoints) <= query_service.MODULE_DASHBOARD_LIMIT
    assert len(dashboard.runs) <= query_service.MODULE_DASHBOARD_LIMIT
    assert all(item.module_name == "grafana" for item in dashboard.findings)
    assert {item.canonical_key for item in dashboard.hosts} == {"10.10.10.10"}
    assert [item.port for item in dashboard.endpoints] == [3000]
    assert all(item.module_name == "grafana" for item in dashboard.runs)

    empty_summary = query_service.get_module_summary(
        workspace_id=workspace.id,
        module_name="missing",
    )
    assert empty_summary.hosts_count == 0
    assert empty_summary.endpoints_count == 0
    assert empty_summary.findings_count == 0
    assert empty_summary.runs_count == 0
    assert empty_summary.artifacts_count == 0
    assert empty_summary.last_seen_at is None

    empty_recent_hits = query_service.list_recent_module_hits(
        workspace_id=workspace.id,
        module_name="missing",
    )
    assert empty_recent_hits == []

    empty_dashboard = query_service.get_module_dashboard(
        workspace_id=workspace.id,
        module_name="missing",
    )
    assert empty_dashboard.summary == empty_summary
    assert empty_dashboard.findings == []
    assert empty_dashboard.hosts == []
    assert empty_dashboard.endpoints == []
    assert empty_dashboard.runs == []

    empty_hosts = query_service.list_hosts(workspace_id=workspace.id, module_name="missing")
    assert empty_hosts == []

    rows = query_service.search(workspace_id=workspace.id, query="Grafana")
    assert any(row["entity_type"] == "finding" for row in rows)


def test_query_service_lists_recent_exporter_hits_with_findings(
    db_service,
    workspace,
    db_fixture_dir: Path,
) -> None:
    ingest_service = IngestService(db_service.session_factory)
    ingest_service.ingest_file(
        workspace_slug=workspace.slug,
        module_name="exporters",
        json_file=str(db_fixture_dir / "exporters.json"),
    )
    query_service = QueryService(db_service.session_factory)

    hits = query_service.list_recent_exporter_hits(workspace_id=workspace.id)

    assert len(hits) == 2
    assert [item.phase for item in hits] == ["trigger", "collect"]
    assert [item.subject for item in hits] == ["redis_exporter", "postgres_exporter"]
    assert hits[0].endpoint_or_resource_label == "callback"
    assert hits[0].endpoint_or_resource == "10.99.0.10"
    assert hits[1].endpoint_or_resource_label == "endpoint"
    assert hits[1].endpoint_or_resource == "/debug/pprof/cmdline?debug=1"
    assert all(item.status == "open" for item in hits)

    collect_hits = query_service.list_recent_exporter_hits(workspace_id=workspace.id, host_filter="10.20.30.40")
    assert [item.phase for item in collect_hits] == ["collect"]

    trigger_hits = query_service.list_recent_exporter_hits(workspace_id=workspace.id, host_filter="10.99.0.10")
    assert [item.phase for item in trigger_hits] == ["trigger"]

    assert query_service.list_recent_exporter_hits(workspace_id=workspace.id, host_filter="203.0.113.10") == []


def test_query_service_lists_recent_exporter_hits_from_collect_body_validation(
    db_service,
    workspace,
    tmp_path: Path,
) -> None:
    payload_path = tmp_path / "exporters_collect.json"
    payload_path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "timestamp": "2026-03-23T18:15:53Z",
                        "host": "127.0.0.1",
                        "exporter": "nats_exporter",
                        "port": 7777,
                        "endpoint": "/debug/vars",
                        "url": "http://127.0.0.1:7777/debug/vars",
                        "ok": True,
                        "status": 200,
                        "body": '{"nats":{"url":"nats://nats_metrics:NatsRead!2026@nats.internal:4222"}}',
                    }
                )
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    ingest_service = IngestService(db_service.session_factory)
    ingest_service.ingest_file(
        workspace_slug=workspace.slug,
        module_name="exporters",
        json_file=str(payload_path),
    )
    query_service = QueryService(db_service.session_factory)

    hits = query_service.list_recent_exporter_hits(workspace_id=workspace.id)

    assert len(hits) == 1
    assert hits[0].phase == "collect"
    assert hits[0].subject == "nats_exporter"
    assert hits[0].endpoint_or_resource == "/debug/vars"
    assert hits[0].detail_label == "sample"
    assert hits[0].detail is not None
    assert "<redacted:dsn_auth>@nats.internal:4222" in hits[0].detail
    assert "NatsRead!2026" not in hits[0].detail


def test_query_service_lists_exporter_stage_rows_newest_first(
    db_service,
    workspace,
    db_fixture_dir: Path,
) -> None:
    ingest_service = IngestService(db_service.session_factory)
    ingest_service.ingest_file(
        workspace_slug=workspace.slug,
        module_name="exporters",
        json_file=str(db_fixture_dir / "exporters.json"),
    )
    query_service = QueryService(db_service.session_factory)

    rows = query_service.list_exporter_stage_rows(workspace_id=workspace.id)

    assert len(rows) == 2
    assert [item.phase_tag for item in rows] == ["TRIGGER", "COLLECT"]
    assert rows[0].host == "10.99.0.10"
    assert rows[0].port is None
    assert rows[0].exporter_display_name == "Redis Exporter"
    assert rows[0].reason == "open_no_auth"
    assert rows[0].detail == "http://10.20.30.41:9121/scrape?target=redis://10.99.0.10:6379"
    assert rows[1].host == "10.20.30.40"
    assert rows[1].port == 9187
    assert rows[1].endpoint == "/debug/pprof/cmdline?debug=1"
    assert rows[1].url == "http://10.20.30.40:9187/debug/pprof/cmdline?debug=1"
    assert rows[1].detail is None

    collect_rows = query_service.list_exporter_stage_rows(workspace_id=workspace.id, host_filter="10.20.30.40")
    assert [item.phase_tag for item in collect_rows] == ["COLLECT"]

    trigger_rows = query_service.list_exporter_stage_rows(workspace_id=workspace.id, host_filter="10.99.0.10")
    assert [item.phase_tag for item in trigger_rows] == ["TRIGGER"]

    assert query_service.list_exporter_stage_rows(workspace_id=workspace.id, host_filter="203.0.113.10") == []


def test_query_service_lists_exporter_stage_rows_from_validation_finding(
    db_service,
    workspace,
    tmp_path: Path,
) -> None:
    payload_path = tmp_path / "exporters_collect.json"
    payload_path.write_text(
        json.dumps(
            [
                {
                    "host": "127.0.0.1",
                    "exporter": "nats_exporter",
                    "port": 7777,
                    "endpoint": "/debug/vars",
                    "url": "http://127.0.0.1:7777/debug/vars",
                    "ok": True,
                    "status": 200,
                    "body": '{"nats":{"url":"nats://nats_metrics:NatsRead!2026@nats.internal:4222"}}',
                }
            ]
        ),
        encoding="utf-8",
    )
    ingest_service = IngestService(db_service.session_factory)
    ingest_service.ingest_file(
        workspace_slug=workspace.slug,
        module_name="exporters",
        json_file=str(payload_path),
    )
    query_service = QueryService(db_service.session_factory)

    rows = query_service.list_exporter_stage_rows(workspace_id=workspace.id)

    assert len(rows) == 1
    assert rows[0].phase_tag == "COLLECT"
    assert rows[0].host == "127.0.0.1"
    assert rows[0].port == 7777
    assert rows[0].exporter_display_name == "NATS Exporter"
    assert rows[0].reason == "connection_string_auth"
    assert rows[0].endpoint == "/debug/vars"
    assert rows[0].sample is not None
    assert "<redacted:dsn_auth>@nats.internal:4222" in rows[0].sample
    assert "NatsRead!2026" not in rows[0].sample


def test_query_service_lists_exporter_trigger_rows_from_successful_observation_without_finding(
    db_service,
    workspace,
    tmp_path: Path,
) -> None:
    payload_path = tmp_path / "exporters_trigger.json"
    payload_path.write_text(
        json.dumps(
            [
                {
                    "timestamp": "2026-03-27T10:00:00Z",
                    "source_type": "trigger",
                    "host": "127.0.0.1",
                    "exporter": "redis_exporter",
                    "port": 9121,
                    "listen_port": 6379,
                    "callback_target": "10.0.0.99",
                    "trigger_url": "http://127.0.0.1:9121/scrape?target=redis://10.0.0.99:6379",
                    "success": True,
                    "probe_success": True,
                }
            ]
        ),
        encoding="utf-8",
    )
    ingest_service = IngestService(db_service.session_factory)
    ingest_service.ingest_file(
        workspace_slug=workspace.slug,
        module_name="exporters",
        json_file=str(payload_path),
    )
    query_service = QueryService(db_service.session_factory)

    hits = query_service.list_recent_exporter_hits(workspace_id=workspace.id, phase_filter="trigger")
    assert len(hits) == 1
    assert hits[0].phase == "trigger"
    assert hits[0].status == "trigger_success"
    assert hits[0].target == "127.0.0.1:9121"

    rows = query_service.list_exporter_stage_rows(workspace_id=workspace.id, phase_filter="trigger")
    assert len(rows) == 1
    assert rows[0].phase_tag == "TRIGGER"
    assert rows[0].host == "10.0.0.99"
    assert rows[0].port == 6379
    assert rows[0].reason == "trigger_success"
    assert rows[0].detail == "http://127.0.0.1:9121/scrape?target=redis://10.0.0.99:6379"


def test_query_service_lists_module_stage_records_for_grafana_and_postgres(
    db_service,
    workspace,
    db_fixture_dir: Path,
) -> None:
    ingest_service = IngestService(db_service.session_factory)
    ingest_service.ingest_file(
        workspace_slug=workspace.slug,
        module_name="grafana",
        json_file=str(db_fixture_dir / "grafana.json"),
    )
    ingest_service.ingest_file(
        workspace_slug=workspace.slug,
        module_name="postgres",
        json_file=str(db_fixture_dir / "postgres.json"),
    )
    query_service = QueryService(db_service.session_factory)

    grafana_rows = query_service.list_module_stage_records(workspace_id=workspace.id, module_name="grafana")

    assert grafana_rows
    assert grafana_rows[0].module == "grafana"
    assert "[*] Grafana Service (auth required:False)" in grafana_rows[0].primary_line
    assert any("[+] anonymous access" in line for line in grafana_rows[0].detail_lines)
    assert any("[*] Dump Datasources" in line for line in grafana_rows[0].detail_lines)
    assert any("prometheus-prod" in line for line in grafana_rows[0].detail_lines)

    postgres_rows = query_service.list_module_stage_records(workspace_id=workspace.id, module_name="postgres")
    postgres_detail_lines = [line for row in postgres_rows for line in row.detail_lines]

    assert postgres_rows
    assert postgres_rows[0].module == "postgres"
    assert all("[*] Postgres Database" in row.primary_line for row in postgres_rows)
    assert any("[+] postgres:postgres" in line for line in postgres_detail_lines)
    assert any("[*] Dump Databases" in line for line in postgres_detail_lines)
    assert any("appdb" in line for line in postgres_detail_lines)
    assert any("[*] Dump Tables" in line for line in postgres_detail_lines)


def test_query_service_lists_module_stage_records_for_kubeapi_and_kafka(
    db_service,
    workspace,
    db_fixture_dir: Path,
    tmp_path: Path,
) -> None:
    ingest_service = IngestService(db_service.session_factory)
    ingest_service.ingest_file(
        workspace_slug=workspace.slug,
        module_name="kubeapi",
        json_file=str(db_fixture_dir / "kubeapi.json"),
    )
    kafka_payload_path = tmp_path / "kafka.json"
    kafka_payload_path.write_text(
        json.dumps(
            [
                {
                    "host": "10.20.30.70",
                    "port": 9092,
                    "status": "open_no_auth",
                    "tool_version": "3.5.0",
                    "topics": ["events", "metrics"],
                }
            ]
        ),
        encoding="utf-8",
    )
    ingest_service.ingest_file(
        workspace_slug=workspace.slug,
        module_name="kafka",
        json_file=str(kafka_payload_path),
    )
    query_service = QueryService(db_service.session_factory)

    kubeapi_rows = query_service.list_module_stage_records(workspace_id=workspace.id, module_name="kubeapi")
    kubeapi_detail_lines = [line for row in kubeapi_rows for line in row.detail_lines]

    assert kubeapi_rows
    assert kubeapi_rows[0].module == "kubeapi"
    assert "[*] Kubernetes API" in kubeapi_rows[0].primary_line
    assert any("[+] anonymous access" in line for line in kubeapi_detail_lines)
    assert any("[*] Namespaces" in line for line in kubeapi_detail_lines)
    assert any("default" in line for line in kubeapi_detail_lines)
    assert any("[*] Pods" in line for line in kubeapi_detail_lines)

    kafka_rows = query_service.list_module_stage_records(workspace_id=workspace.id, module_name="kafka")
    kafka_detail_lines = [line for row in kafka_rows for line in row.detail_lines]

    assert kafka_rows
    assert kafka_rows[0].module == "kafka"
    assert "[*] Kafka Broker" in kafka_rows[0].primary_line
    assert any("[+] anonymous access" in line for line in kafka_detail_lines)
    assert any("[*] Show Topics" in line for line in kafka_detail_lines)
    assert any("events" in line for line in kafka_detail_lines)
    assert any("metrics" in line for line in kafka_detail_lines)


def test_query_service_module_stage_records_fall_back_to_observations_and_runs(
    db_service,
    workspace,
    tmp_path: Path,
) -> None:
    registry_payload_path = tmp_path / "registry_observed.json"
    registry_payload_path.write_text(
        json.dumps(
            [
                {
                    "host": "10.20.30.50",
                    "port": 5000,
                    "status": "auth_required",
                    "service": "docker_registry",
                    "tool_version": "3.5.0",
                }
            ]
        ),
        encoding="utf-8",
    )
    ingest_service = IngestService(db_service.session_factory)
    ingest_service.ingest_file(
        workspace_slug=workspace.slug,
        module_name="registry",
        json_file=str(registry_payload_path),
    )
    query_service = QueryService(db_service.session_factory)

    observation_rows = query_service.list_module_stage_records(workspace_id=workspace.id, module_name="registry")

    assert len(observation_rows) == 1
    assert observation_rows[0].module == "registry"
    assert "Registry" in observation_rows[0].primary_line
    assert any(
        "auth required" in line.lower() or "docker_registry" in line.lower()
        for line in observation_rows[0].detail_lines
    ) or ("auth required" in observation_rows[0].primary_line.lower())

    redis_payload_path = tmp_path / "redis_observed.json"
    redis_payload_path.write_text(
        json.dumps([{"host": "10.20.30.60", "port": 6379, "service": "redis", "status": "observed"}]),
        encoding="utf-8",
    )
    ingest_service.ingest_file(
        workspace_slug=workspace.slug,
        module_name="redis",
        json_file=str(redis_payload_path),
    )
    with session_scope(db_service.session_factory) as session:
        observation = session.query(RunObservation).filter(RunObservation.module_name == "redis").one()
        observation.deleted_at = datetime.now(timezone.utc)
        run = session.query(ModuleRun).filter(ModuleRun.module_name == "redis").one()
        run.execution_status = "success"
        run.source_type = "scan"

    run_rows = query_service.list_module_stage_records(workspace_id=workspace.id, module_name="redis")

    assert len(run_rows) == 1
    assert run_rows[0].module == "redis"
    assert "success" in run_rows[0].primary_line.lower()


def test_query_service_recent_module_hits_falls_back_to_observations(
    db_service,
    workspace,
    tmp_path: Path,
) -> None:
    payload_path = tmp_path / "registry_observed.json"
    payload_path.write_text(
        json.dumps(
            [
                {
                    "host": "10.20.30.50",
                    "port": 5000,
                    "status": "auth_required",
                    "service": "docker_registry",
                    "tool_version": "3.5.0",
                }
            ]
        ),
        encoding="utf-8",
    )
    ingest_service = IngestService(db_service.session_factory)
    ingest_service.ingest_file(
        workspace_slug=workspace.slug,
        module_name="registry",
        json_file=str(payload_path),
    )
    query_service = QueryService(db_service.session_factory)

    hits = query_service.list_recent_module_hits(workspace_id=workspace.id, module_name="registry")

    assert len(hits) == 1
    assert hits[0].module == "registry"
    assert hits[0].target == "10.20.30.50:5000"
    assert hits[0].subject == "docker_registry"
    assert hits[0].status == "auth_required"


def test_query_service_recent_module_hits_falls_back_to_successful_runs(
    db_service,
    workspace,
    tmp_path: Path,
) -> None:
    payload_path = tmp_path / "redis_observed.json"
    payload_path.write_text(
        json.dumps([{"host": "10.20.30.60", "port": 6379, "service": "redis", "status": "observed"}]),
        encoding="utf-8",
    )
    ingest_service = IngestService(db_service.session_factory)
    ingest_service.ingest_file(
        workspace_slug=workspace.slug,
        module_name="redis",
        json_file=str(payload_path),
    )
    with session_scope(db_service.session_factory) as session:
        observation = session.query(RunObservation).one()
        observation.deleted_at = datetime.now(timezone.utc)
        run = session.query(ModuleRun).one()
        run.execution_status = "success"
        run.source_type = "scan"

    query_service = QueryService(db_service.session_factory)
    hits = query_service.list_recent_module_hits(workspace_id=workspace.id, module_name="redis")

    assert len(hits) == 1
    assert hits[0].module == "redis"
    assert hits[0].status == "success"
    assert hits[0].phase == "scan"
    assert hits[0].title == "redis scan success"


def test_query_service_database_overview_handles_empty_and_populated_state(
    db_service,
    workspace,
    db_fixture_dir: Path,
) -> None:
    query_service = QueryService(db_service.session_factory)

    empty = query_service.get_database_overview(workspace_id=workspace.id, modules=("grafana", "redis"))
    assert empty.totals.hosts_count == 0
    assert empty.totals.last_seen_at is None
    assert [item.module for item in empty.modules] == ["grafana", "redis"]
    assert all(item.records_count == 0 for item in empty.modules)

    ingest_service = IngestService(db_service.session_factory)
    ingest_service.ingest_file(
        workspace_slug=workspace.slug,
        module_name="grafana",
        json_file=str(db_fixture_dir / "grafana.json"),
    )

    populated = query_service.get_database_overview(workspace_id=workspace.id, modules=("grafana", "redis"))
    assert populated.totals.hosts_count == 1
    assert populated.totals.findings_count >= 1
    assert populated.totals.last_seen_at is not None
    assert populated.modules[0].module == "grafana"
    assert populated.modules[0].records_count > 0
    assert populated.modules[1].module == "redis"
    assert populated.modules[1].records_count == 0


def test_query_helpers_cover_exporter_and_resource_branches() -> None:
    assert _classify_exporter_hit_phase(None, {"trigger_url": "http://callback"}) == "trigger"
    assert _classify_exporter_hit_phase(None, {"endpoint": "/metrics"}) == "collect"
    assert _classify_exporter_hit_phase(SimpleNamespace(source_type="trigger"), {}) == "trigger"
    assert _classify_exporter_hit_phase(None, {}) is None

    assert _is_successful_exporter_hit("collect", {"ok": True}) is True
    assert _is_successful_exporter_hit("collect", {"status": 200}) is True
    assert _is_successful_exporter_hit("collect", {"status": 500, "error": "boom"}) is False
    assert _is_successful_exporter_hit("trigger", {"probe_success": True}) is True
    assert _is_successful_exporter_hit("trigger", {"callback_target": "10.0.0.1", "status": 204}) is True
    assert _is_successful_exporter_hit("trigger", {"callback_target": "10.0.0.1", "error": "boom"}) is False
    assert _is_successful_exporter_hit("scan", {}) is False

    assert _resource_summary_from_raw({"database": "app"}) == ("resource", "database=app")
    assert _resource_summary_from_raw({"tables": ["users", "events"]}) == ("resource", "tables=2")
    assert _resource_summary_from_raw({}) == (None, None)

    assert _split_description_sample("reasons=foo sample=postgres://user:pass@db/app") == (
        "postgres://user:pass@db/app",
        "reasons=foo",
    )
    assert _split_description_sample("detail only") == (None, "detail only")
    assert _split_description_sample(None) == (None, None)

    assert _observation_detail({"error": "boom"}) == ("detail", "boom")
    assert _observation_detail({"message": "ok"}) == ("detail", "ok")
    assert _observation_detail({"reason": "denied"}) == ("detail", "denied")
    assert _observation_detail({"version": "1.2.3"}) == ("detail", "version=1.2.3")
    assert _observation_detail({}) == (None, None)


def test_query_helper_recent_hit_builders_cover_run_and_finding_paths() -> None:
    failed_run = ModuleRun(module_name="grafana", protocol="grafana", source_type="scan", execution_status="failed")
    assert _run_to_recent_hit(failed_run) is None

    success_run = ModuleRun(
        module_name="grafana",
        protocol="grafana",
        source_type="scan",
        execution_status="success",
        tool_version="3.5.0",
    )
    run_hit = _run_to_recent_hit(success_run)
    assert run_hit is not None
    assert run_hit.detail_label == "version"
    assert run_hit.detail == "3.5.0"

    exporter_finding = Finding(
        module_name="exporters",
        protocol="exporters",
        finding_type="connection_string_auth",
        severity="high",
        status="open",
        title="exposure",
        description="sample=postgres://user:pass@db/app",
    )
    exporter_finding.run_observation = RunObservation(
        module_name="exporters",
        protocol="exporters",
        source_type="collect",
        raw_json_result_sanitized={"endpoint": "/debug/vars", "status": 500, "error": "boom"},
    )
    assert _finding_to_recent_hit(exporter_finding) is None

    normal_finding = Finding(
        module_name="grafana",
        protocol="grafana",
        finding_type="anonymous_access",
        severity="high",
        status="open",
        title="Grafana anonymous access",
        description="sample=http://10.0.0.10:3000",
    )
    normal_finding.run_observation = RunObservation(
        module_name="grafana",
        protocol="grafana",
        source_type="scan",
        raw_json_result_sanitized={"host": "10.0.0.10", "port": 3000, "path": "/login"},
    )
    hit = _finding_to_recent_hit(normal_finding)
    assert hit is not None
    assert hit.target == "10.0.0.10:3000"
    assert hit.endpoint_or_resource == "/login"
    assert hit.detail_label == "sample"
    assert hit.detail == "http://10.0.0.10:3000"

    trigger_exporter = Finding(
        module_name="exporters",
        protocol="exporters",
        finding_type="open_no_auth",
        severity="high",
        status="open",
        title="redis_exporter exposure on 10.0.0.20",
        description="http://10.0.0.20:9121/scrape?target=redis://10.0.0.5:6379",
    )
    trigger_exporter.run_observation = RunObservation(
        module_name="exporters",
        protocol="exporters",
        source_type="trigger",
        raw_json_result_sanitized={
            "host": "10.0.0.20",
            "port": 9121,
            "callback_target": "10.0.0.5",
            "trigger_url": "http://10.0.0.20:9121/scrape?target=redis://10.0.0.5:6379",
            "probe_success": True,
            "service": "redis_exporter",
        },
    )
    trigger_row = _finding_to_exporter_stage_row(trigger_exporter)
    assert trigger_row is not None
    assert trigger_row.phase_tag == "TRIGGER"
    assert trigger_row.host == "10.0.0.5"
    assert trigger_row.port is None
    assert trigger_row.exporter_display_name == "Redis Exporter"


def test_query_helper_parses_exporter_finding_description() -> None:
    endpoint, sample, detail = _parse_exporter_finding_description(
        "reasons=connection_string_auth endpoint=/debug/vars sample=postgres://user:pass@db/app"
    )
    assert endpoint == "/debug/vars"
    assert sample == "postgres://user:pass@db/app"
    assert detail is None

    endpoint, sample, detail = _parse_exporter_finding_description("http://10.0.0.10:9121/scrape?target=redis://x")
    assert endpoint is None
    assert sample is None
    assert detail == "http://10.0.0.10:9121/scrape?target=redis://x"
