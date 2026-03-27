"""Import/export job repositories."""

from __future__ import annotations

from sqlalchemy.orm import Session

from ..models.core import ExportJob, ImportJob


class ImportJobRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def create(self, *, workspace_id: int, module_name: str, source_format: str, input_path: str | None) -> ImportJob:
        job = ImportJob(
            workspace_id=workspace_id,
            module_name=module_name,
            source_format=source_format,
            status="running",
            input_path=input_path,
        )
        self.session.add(job)
        self.session.flush()
        return job


class ExportJobRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def create(self, *, workspace_id: int, export_kind: str, output_format: str, output_path: str | None) -> ExportJob:
        job = ExportJob(
            workspace_id=workspace_id,
            export_kind=export_kind,
            output_format=output_format,
            status="running",
            output_path=output_path,
        )
        self.session.add(job)
        self.session.flush()
        return job
