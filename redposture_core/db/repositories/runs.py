"""Run repositories."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models.core import ModuleRun, RunObservation
from ..util import utcnow
from .common import dialect_insert


class ModuleRunRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def create(self, **values: object) -> ModuleRun:
        run = ModuleRun(**values)
        self.session.add(run)
        self.session.flush()
        return run

    def list(
        self,
        *,
        workspace_id: int,
        target_text: str | None = None,
        module_name: str | None = None,
    ) -> list[ModuleRun]:
        stmt = (
            select(ModuleRun)
            .where(ModuleRun.workspace_id == workspace_id, ModuleRun.deleted_at.is_(None))
            .order_by(ModuleRun.started_at.desc())
        )
        if module_name:
            stmt = stmt.where(ModuleRun.module_name == module_name)
        if not target_text:
            return list(self.session.scalars(stmt))
        stmt = stmt.join(RunObservation, RunObservation.module_run_id == ModuleRun.id).where(
            RunObservation.target_text == target_text,
            RunObservation.deleted_at.is_(None),
        )
        return list(self.session.scalars(stmt).unique())


class RunObservationRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def upsert(self, **values: object) -> RunObservation:
        workspace_id = int(values["workspace_id"])
        fingerprint = str(values["fingerprint"])
        now = utcnow()
        stmt = dialect_insert(self.session, RunObservation).values(
            **values,
            created_at=now,
            updated_at=now,
            is_archived=False,
            archived_at=None,
            deleted_at=None,
        )
        update_values = {
            key: value
            for key, value in values.items()
            if key not in {"id", "workspace_id", "fingerprint", "created_at", "updated_at"}
        }
        update_values.update(
            {
                "updated_at": now,
                "is_archived": False,
                "archived_at": None,
                "deleted_at": None,
            }
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[RunObservation.workspace_id, RunObservation.fingerprint],
            set_=update_values,
        )
        self.session.execute(stmt)
        observation = self.session.scalar(
            select(RunObservation)
            .where(
                RunObservation.workspace_id == workspace_id,
                RunObservation.fingerprint == fingerprint,
            )
            .execution_options(populate_existing=True)
        )
        if observation is None:
            raise RuntimeError("run observation upsert failed")
        return observation
