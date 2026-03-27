"""Base ingest adapter contracts."""

from __future__ import annotations

from typing import Any

from ..dto.ingest import IngestEnvelope, ModuleRunCreate


class BaseModuleIngestor:
    module_name: str = "unknown"
    protocol: str = "unknown"

    def build_run(self, first_record: dict[str, Any]) -> ModuleRunCreate:
        tool_version = str(first_record.get("tool_version") or first_record.get("version") or "").strip() or None
        return ModuleRunCreate(
            module_name=self.module_name,
            protocol=self.protocol,
            source_type="import",
            execution_status="success",
            tool_version=tool_version,
        )

    def ingest_record(self, record: dict[str, Any]) -> IngestEnvelope:
        raise NotImplementedError
