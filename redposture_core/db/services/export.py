"""Export service."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from sqlalchemy.orm import sessionmaker

from ..dto.query import FindingFilter
from ..models import ExportJob
from ..repositories import ExportJobRepository
from ..session import session_scope
from ..util import utcnow
from .query import QueryService

_SUPPORTED_EXPORT_FORMATS = {"json", "csv"}


class ExportService:
    def __init__(self, session_factory: sessionmaker) -> None:
        self.session_factory = session_factory
        self.query_service = QueryService(session_factory)

    def export_findings(
        self,
        *,
        workspace_id: int,
        output_format: str,
        output_path: str | None = None,
        module_name: str | None = None,
    ) -> str:
        filters = FindingFilter(module_name=module_name) if module_name else FindingFilter()
        findings = [
            item.model_dump() for item in self.query_service.list_findings(workspace_id=workspace_id, filters=filters)
        ]
        return self._export_rows(
            workspace_id=workspace_id,
            rows=findings,
            export_kind="findings",
            output_format=output_format,
            output_path=output_path,
        )

    def export_hosts(
        self,
        *,
        workspace_id: int,
        output_format: str,
        output_path: str | None = None,
        module_name: str | None = None,
    ) -> str:
        hosts = [
            item.model_dump()
            for item in self.query_service.list_hosts(workspace_id=workspace_id, module_name=module_name)
        ]
        return self._export_rows(
            workspace_id=workspace_id,
            rows=hosts,
            export_kind="hosts",
            output_format=output_format,
            output_path=output_path,
        )

    def _export_rows(
        self,
        *,
        workspace_id: int,
        rows: list[dict[str, object]],
        export_kind: str,
        output_format: str,
        output_path: str | None,
    ) -> str:
        job_id: int | None = None
        with session_scope(self.session_factory) as session:
            job = ExportJobRepository(session).create(
                workspace_id=workspace_id,
                export_kind=export_kind,
                output_format=output_format,
                output_path=output_path,
            )
            job_id = int(job.id)
        try:
            rendered = _render_rows(rows=rows, output_format=output_format)
            if output_path:
                Path(output_path).parent.mkdir(parents=True, exist_ok=True)
                Path(output_path).write_text(rendered, encoding="utf-8")
            self._mark_job_success(job_id=job_id, rows_count=len(rows))
            return rendered
        except Exception as exc:
            self._mark_job_failed(job_id=job_id, error_text=str(exc))
            raise

    def _mark_job_success(self, *, job_id: int | None, rows_count: int) -> None:
        if job_id is None:
            return
        with session_scope(self.session_factory) as session:
            job = session.get(ExportJob, job_id)
            if job is None:
                return
            job.status = "success"
            job.stats_json = {"rows": rows_count}
            job.finished_at = utcnow()

    def _mark_job_failed(self, *, job_id: int | None, error_text: str) -> None:
        if job_id is None:
            return
        with session_scope(self.session_factory) as session:
            job = session.get(ExportJob, job_id)
            if job is None:
                return
            job.status = "failed"
            job.error_text = error_text
            job.finished_at = utcnow()


def _render_rows(*, rows: list[dict[str, object]], output_format: str) -> str:
    if output_format not in _SUPPORTED_EXPORT_FORMATS:
        raise ValueError(f"unsupported export format: {output_format}")
    if output_format == "json":
        return json.dumps(rows, ensure_ascii=False, indent=2, default=str)
    if not rows:
        return ""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return buffer.getvalue()
