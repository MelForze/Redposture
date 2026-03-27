"""Artifact and evidence repositories."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models.core import Artifact, Evidence, ModuleRun


class ArtifactRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def create(self, **values: object) -> Artifact:
        artifact = Artifact(**values)
        self.session.add(artifact)
        self.session.flush()
        return artifact

    def list(
        self,
        *,
        workspace_id: int,
        module_run_id: int | None = None,
        module_name: str | None = None,
    ) -> list[Artifact]:
        stmt = select(Artifact).where(Artifact.workspace_id == workspace_id, Artifact.deleted_at.is_(None))
        if module_run_id is not None:
            stmt = stmt.where(Artifact.module_run_id == module_run_id)
        if module_name:
            stmt = stmt.join(ModuleRun, ModuleRun.id == Artifact.module_run_id).where(
                ModuleRun.module_name == module_name,
                ModuleRun.deleted_at.is_(None),
            )
        return list(self.session.scalars(stmt.order_by(Artifact.created_at.desc())))


class EvidenceRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def create(self, **values: object) -> Evidence:
        evidence = Evidence(**values)
        self.session.add(evidence)
        self.session.flush()
        return evidence

    def list_for_run(self, *, module_run_id: int) -> list[Evidence]:
        return list(
            self.session.scalars(
                select(Evidence)
                .where(Evidence.module_run_id == module_run_id, Evidence.deleted_at.is_(None))
                .order_by(Evidence.collected_at.desc())
            )
        )
