"""Typed models shared by ClickHouse discovery components."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from ....discovery_containers import DiskSequence


@dataclass(frozen=True)
class ColumnInventory:
    database: str
    table: str
    name: str
    type_name: str
    position: int
    compressed_bytes: int = 0
    uncompressed_bytes: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TableInventory:
    database: str
    name: str
    engine: str = ""
    partition_key: str = ""
    sorting_key: str = ""
    primary_key: str = ""
    total_rows: int | None = None
    total_bytes: int | None = None
    columns: list[ColumnInventory] = field(default_factory=list)
    partitions: list[dict[str, Any]] = field(default_factory=list)
    inventory_errors: list[str] = field(default_factory=list)

    _catalog_record: Any = field(default=None, repr=False, compare=False)

    def __setattr__(self, name: str, value: Any) -> None:
        record = getattr(self, "_catalog_record", None)
        if record is not None and name in {"columns", "partitions", "inventory_errors"}:
            from .catalog import ColumnSequence

            if name == "columns":
                payload = record._owner.sequence(column.to_dict() for column in value)
                record[name] = payload
                value = ColumnSequence(payload)
            else:
                record[name] = record._owner.sequence(value)
                value = record[name]
        object.__setattr__(self, name, value)

    @property
    def full_name(self) -> str:
        return f"{self.database}.{self.name}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "database": self.database,
            "table": self.name,
            "engine": self.engine,
            "partition_key": self.partition_key,
            "sorting_key": self.sorting_key,
            "primary_key": self.primary_key,
            "total_rows": self.total_rows,
            "total_bytes": self.total_bytes,
            "columns": self.columns.payload
            if hasattr(self.columns, "payload")
            else [column.to_dict() for column in self.columns],
            "partitions": self.partitions if isinstance(self.partitions, DiskSequence) else list(self.partitions),
            "inventory_errors": self.inventory_errors
            if isinstance(self.inventory_errors, DiskSequence)
            else list(self.inventory_errors),
        }


@dataclass(frozen=True)
class ScanChunk:
    database: str
    table: str
    columns: tuple[str, ...]
    partition_id: str | None
    offset: int
    limit: int

    @property
    def chunk_id(self) -> str:
        partition = self.partition_id if self.partition_id is not None else "<all>"
        return f"{self.database}.{self.table}|{partition}|{self.offset}|{self.limit}"


__all__ = ["ColumnInventory", "ScanChunk", "TableInventory"]
