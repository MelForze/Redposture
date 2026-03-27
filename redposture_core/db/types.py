"""Shared enums and type aliases for DB subsystem."""

from __future__ import annotations

from enum import Enum


class SourceType(str, Enum):
    SCAN = "scan"
    COLLECT = "collect"
    TRIGGER = "trigger"
    IMPORT = "import"


class ExecutionStatus(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    RUNNING = "running"


class ArtifactRole(str, Enum):
    RAW_PAYLOAD = "raw_payload"
    EVIDENCE_BLOB = "evidence_blob"
    EXPORT_BLOB = "export_blob"


class EvidenceType(str, Enum):
    OBSERVATION = "observation"
    FINDING = "finding"
    EXPORT = "export"


class ExportFormat(str, Enum):
    JSON = "json"
    CSV = "csv"
