"""Small, aggregate source manifest; object catalogs remain in disk readers."""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any


@dataclass
class SourceRead:
    """Evidence for one attempt; readers acknowledge only validated content."""

    status: int | None = None
    count: int = 0
    complete: bool = False
    unsupported: bool = False

    def accept(self, count: int = 1) -> None:
        if count < 0:
            raise ValueError("negative source object count")
        self.count += count
        self.complete = True


class SourceManifest:
    """Track access and completion separately from the number of findings.

    Rows describe adapter source classes, not one row per object. No credential
    values, object contents or unbounded server error text are retained here.
    """

    def __init__(self) -> None:
        self._rows: dict[str, dict[str, Any]] = {}

    def declare(self, source: str, *, implemented: bool = True) -> None:
        if not source:
            raise ValueError("source id is required")
        row = self._rows.setdefault(
            source,
            {
                "id": source,
                "implemented": implemented,
                "requested": 0,
                "read": 0,
                "denied": 0,
                "unsupported": False,
                "complete": True,
            },
        )
        if row["implemented"] != implemented:
            raise ValueError("source implementation state cannot change during traversal")

    def request(self, source: str, *, implemented: bool = True, scope: str | None = None) -> None:
        self.declare(source, implemented=implemented)
        row = self._rows[source]
        row["requested"] += 1
        if scope is not None:
            row["scope"] = scope

    def read(self, source: str, count: int = 1) -> None:
        if count < 0:
            raise ValueError("negative source object count")
        self._rows[source]["read"] += count

    def finish(self, source: str, *, complete: bool, denied: bool = False, unsupported: bool = False) -> None:
        row = self._rows[source]
        row["complete"] &= complete
        row["denied"] += int(denied)
        row["unsupported"] |= unsupported

    @contextmanager
    def guard(self, source: str) -> Iterator[None]:
        """An aborted traversal cannot leave its requested source complete.

        Keep earlier read counts and unrelated completed source classes intact.
        Normal completion remains the reader's responsibility, including empty
        sources and protocol-specific unsupported/denied states.
        """
        try:
            yield
        except BaseException:
            self.finish(source, complete=False)
            raise

    def result(self) -> list[dict[str, Any]]:
        return [{**row, "complete": bool(row["requested"] and row["complete"])} for row in self._rows.values()]

    def merge(self, sources: Iterable[Mapping[str, Any]]) -> None:
        """Merge independent traversal reports without losing ACL evidence."""
        for source in sources:
            name = source["id"]
            self.declare(name, implemented=source["implemented"])
            row = self._rows[name]
            for field in ("requested", "read", "denied"):
                row[field] += source[field]
            if source["requested"]:
                row["complete"] &= source["complete"]
            row["unsupported"] |= source["unsupported"]
            scope = source.get("scope")
            if scope is not None:
                row["scope"] = scope if row.get("scope", scope) == scope else "multiple_scopes"
