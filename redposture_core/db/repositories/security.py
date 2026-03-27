"""Secret reference repository."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models.core import SecretRef
from .common import dialect_insert


class SecretRefRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def upsert(
        self, *, workspace_id: int, secret_kind: str, redacted_value: str, fingerprint: str, source_hint: str | None
    ) -> SecretRef:
        stmt = dialect_insert(self.session, SecretRef).values(
            workspace_id=workspace_id,
            secret_kind=secret_kind,
            redacted_value=redacted_value,
            fingerprint=fingerprint,
            source_hint=source_hint,
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[SecretRef.workspace_id, SecretRef.fingerprint],
            set_={
                "secret_kind": secret_kind,
                "redacted_value": redacted_value,
                "source_hint": source_hint,
            },
        )
        self.session.execute(stmt)
        row = self.session.scalar(
            select(SecretRef)
            .where(SecretRef.workspace_id == workspace_id, SecretRef.fingerprint == fingerprint)
            .execution_options(populate_existing=True)
        )
        if row is None:
            raise RuntimeError("secret ref upsert failed")
        return row
