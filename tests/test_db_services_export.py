from __future__ import annotations

import json
from pathlib import Path

import pytest
from sqlalchemy import select

from redposture_core.db.models import ExportJob
from redposture_core.db.services import ExportService, IngestService
from redposture_core.db.services.export import _render_rows
from redposture_core.db.session import session_scope


def test_render_rows_supports_json_csv_and_empty() -> None:
    rows = [{"id": 1, "name": "alpha"}]

    json_output = _render_rows(rows=rows, output_format="json")
    csv_output = _render_rows(rows=rows, output_format="csv")
    empty_output = _render_rows(rows=[], output_format="csv")

    assert json.loads(json_output)[0]["name"] == "alpha"
    assert "id,name" in csv_output
    assert empty_output == ""

    with pytest.raises(ValueError, match="unsupported export format"):
        _render_rows(rows=rows, output_format="yaml")


def test_export_service_writes_outputs_and_records_jobs(
    db_service, workspace, db_fixture_dir: Path, tmp_path: Path
) -> None:
    ingest_service = IngestService(db_service.session_factory)
    ingest_service.ingest_file(
        workspace_slug=workspace.slug, module_name="grafana", json_file=str(db_fixture_dir / "grafana.json")
    )
    ingest_service.ingest_file(
        workspace_slug=workspace.slug, module_name="kubeapi", json_file=str(db_fixture_dir / "kubeapi.json")
    )
    service = ExportService(db_service.session_factory)

    findings_path = tmp_path / "findings.json"
    hosts_path = tmp_path / "hosts.csv"
    findings_output = service.export_findings(
        workspace_id=workspace.id,
        output_format="json",
        output_path=str(findings_path),
        module_name="grafana",
    )
    hosts_output = service.export_hosts(
        workspace_id=workspace.id,
        output_format="csv",
        output_path=str(hosts_path),
        module_name="grafana",
    )

    assert findings_path.exists()
    assert hosts_path.exists()
    assert "grafana" in findings_output
    assert "kubeapi" not in findings_output
    assert "canonical_key" in hosts_output
    assert "10.10.10.10" in hosts_output
    assert "10.10.10.20" not in hosts_output

    with session_scope(db_service.session_factory) as session:
        jobs = list(session.scalars(select(ExportJob).order_by(ExportJob.id.asc())))
        assert len(jobs) == 2
        assert all(job.status == "success" for job in jobs)
        assert jobs[0].stats_json == {"rows": 2}


def test_export_service_persists_failed_job_status(db_service, workspace) -> None:
    service = ExportService(db_service.session_factory)

    with pytest.raises(ValueError, match="unsupported export format"):
        service.export_hosts(workspace_id=workspace.id, output_format="yaml")

    with session_scope(db_service.session_factory) as session:
        job = session.scalar(select(ExportJob).order_by(ExportJob.id.desc()))
        assert job is not None
        assert job.status == "failed"
        assert "unsupported export format" in str(job.error_text)
