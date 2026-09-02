"""Inventory, planning, scan, finding aggregation and coverage orchestration."""

from __future__ import annotations

import fnmatch
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ....secret_detection import detector_names, fingerprint, mask_secret, scan_value
from .checkpoint import CheckpointStore, InMemoryCheckpointStore
from .inventory import collect_inventory, is_content_type
from .models import ScanChunk, TableInventory
from .reader import build_chunk_query, read_chunk


@dataclass(frozen=True)
class DiscoverConfig:
    checkpoint: Path | None = None
    resume: bool = False
    chunk_rows: int = 1000
    max_query_time: float = 10.0
    max_query_rows: int = 100_000
    max_query_bytes: int = 64 * 1024 * 1024
    max_memory: int = 256 * 1024 * 1024
    max_threads: int = 1
    exclusions: tuple[str, ...] = ()
    detectors: tuple[str, ...] = ()
    redact: bool = True


_SYSTEM_DATABASES = {"system", "information_schema", "INFORMATION_SCHEMA"}


def _excluded(patterns: tuple[str, ...], *names: str) -> bool:
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns for name in names)


def _coverage_key(database: str, table: str, column: str) -> str:
    return f"{database}.{table}.{column}"


def _finding_key(detector: str, value: str) -> str:
    return f"{detector}:{fingerprint(value)}"


def _initial_finding(raw: dict[str, Any]) -> dict[str, Any]:
    value = dict(raw)
    value.setdefault("occurrences", 0)
    value.setdefault("location_count", 0)
    value.setdefault("locations", [])
    return value


def _scan_rows(
    rows: list[list[Any]],
    chunk: ScanChunk,
    findings: dict[str, dict[str, Any]],
    coverage: dict[str, dict[str, Any]],
    *,
    enabled: tuple[str, ...],
    redact: bool,
) -> None:
    for row_index, row in enumerate(rows):
        locator = {"partition": chunk.partition_id, "row_offset": chunk.offset + row_index}
        for column_index, column in enumerate(chunk.columns):
            if column_index >= len(row):
                continue
            raw_value = row[column_index]
            coverage_item = coverage[_coverage_key(chunk.database, chunk.table, column)]
            coverage_item["rows_scanned"] += 1
            coverage_item["bytes_scanned"] += len(str(raw_value).encode("utf-8", errors="replace"))
            for match in scan_value(raw_value, object_path="$", enabled=enabled):
                key = _finding_key(match.detector, match.value)
                location = {
                    "database": chunk.database,
                    "table": chunk.table,
                    "column": column,
                    "object_path": match.object_path,
                    **locator,
                }
                now = time.time()
                finding = findings.get(key)
                if finding is None:
                    finding = {
                        "type": match.detector,
                        "confidence": match.confidence,
                        "database": chunk.database,
                        "table": chunk.table,
                        "column": column,
                        "object_path": match.object_path,
                        "partition": chunk.partition_id,
                        "range": {"offset": chunk.offset, "limit": chunk.limit},
                        "fingerprint": fingerprint(match.value),
                        "masked_value": mask_secret(match.value),
                        "value": None if redact else match.value,
                        "occurrences": 0,
                        "location_count": 0,
                        "locations": [],
                        "first_seen": now,
                        "last_seen": now,
                        "scanned_context": {"chunk_id": chunk.chunk_id},
                    }
                    findings[key] = finding
                finding["occurrences"] += 1
                finding["last_seen"] = now
                if location not in finding["locations"]:
                    finding["location_count"] += 1
                    if len(finding["locations"]) < 100:
                        finding["locations"].append(location)


def _planned_chunks(table: TableInventory, columns: tuple[str, ...], chunk_rows: int) -> list[ScanChunk]:
    chunks: list[ScanChunk] = []
    partitions = table.partitions or [{"partition_id": None, "rows": table.total_rows}]
    for partition in partitions:
        partition_id = partition.get("partition_id")
        raw_rows = partition.get("rows")
        total_rows = int(raw_rows) if isinstance(raw_rows, int) else table.total_rows
        if total_rows is None:
            chunks.append(ScanChunk(table.database, table.name, columns, partition_id, 0, chunk_rows))
            continue
        for offset in range(0, max(0, total_rows), chunk_rows):
            chunks.append(
                ScanChunk(
                    table.database, table.name, columns, partition_id, offset, min(chunk_rows, total_rows - offset)
                )
            )
    return chunks


def _error_kind(error: str) -> str:
    lowered = error.lower()
    if any(token in lowered for token in ("not enough privileges", "access denied", "permission", "required grant")):
        return "permission_denied"
    if any(token in lowered for token in ("timeout", "time limit", "max_execution_time")):
        return "timeout"
    if any(token in lowered for token in ("memory limit", "max_memory")):
        return "memory_limit"
    if any(token in lowered for token in ("max_bytes", "bytes to read", "max_rows")):
        return "resource_limit"
    return "query_error"


def run_discovery(session: Any, *, host: str, port: int, config: DiscoverConfig, query_rows: Any) -> dict[str, Any]:
    started = time.monotonic()
    enabled = config.detectors or detector_names()
    unknown = sorted(set(enabled) - set(detector_names()))
    if unknown:
        raise ValueError(f"unknown detectors: {','.join(unknown)}")
    store: CheckpointStore | InMemoryCheckpointStore = (
        CheckpointStore(config.checkpoint, f"{host}:{port}", resume=config.resume)
        if config.checkpoint is not None
        else InMemoryCheckpointStore(f"{host}:{port}", resume=config.resume)
    )
    state = store.target_state()
    findings = {
        str(key): _initial_finding(value)
        for key, value in (state.get("findings") or {}).items()
        if isinstance(value, dict)
    }
    coverage = {
        str(key): dict(value) for key, value in (state.get("coverage") or {}).items() if isinstance(value, dict)
    }
    inventory, inventory_errors = collect_inventory(query_rows)
    inventory_payload = [table.to_dict() for table in inventory]
    scan_errors: list[dict[str, Any]] = []
    tables_scanned = 0

    for table in inventory:
        table_name = table.full_name
        if table.database in _SYSTEM_DATABASES or _excluded(config.exclusions, table.database, table_name):
            continue
        content_columns: list[str] = []
        for column in table.columns:
            key = _coverage_key(table.database, table.name, column.name)
            if _excluded(config.exclusions, table.database, table_name, key):
                coverage[key] = {"status": "excluded", "type": column.type_name, "rows_scanned": 0, "bytes_scanned": 0}
            elif not is_content_type(column.type_name):
                coverage[key] = {
                    "status": "unsupported_type",
                    "type": column.type_name,
                    "rows_scanned": 0,
                    "bytes_scanned": 0,
                }
            else:
                content_columns.append(column.name)
                coverage.setdefault(
                    key,
                    {
                        "status": "pending",
                        "type": column.type_name,
                        "rows_scanned": 0,
                        "bytes_scanned": 0,
                        "approximate_total_rows": table.total_rows,
                        "total_bytes": column.uncompressed_bytes,
                        "total_partitions": len(table.partitions) if table.partitions else 1,
                        "total_chunks": 0,
                        "completed_chunks": 0,
                        "failed_chunks": 0,
                        "coverage_percent": 0.0,
                    },
                )
        if not content_columns:
            continue
        tables_scanned += 1
        columns = tuple(content_columns)
        work = deque(_planned_chunks(table, columns, max(1, config.chunk_rows)))
        for column_name in columns:
            item = coverage[_coverage_key(table.database, table.name, column_name)]
            if not config.resume or not item.get("total_chunks"):
                item["total_chunks"] = len(work)
        if not work:
            for column_name in columns:
                item = coverage[_coverage_key(table.database, table.name, column_name)]
                item["status"] = "complete"
                item["coverage_percent"] = 100.0
        while work:
            chunk = work.popleft()
            if store.is_complete(chunk.chunk_id):
                continue
            query = build_chunk_query(
                chunk,
                max_query_time=config.max_query_time,
                max_query_rows=config.max_query_rows,
                max_query_bytes=config.max_query_bytes,
                max_memory=config.max_memory,
                max_threads=config.max_threads,
            )
            result = read_chunk(session, query)
            if result.error:
                kind = _error_kind(result.error)
                if kind in {"timeout", "memory_limit", "resource_limit"} and chunk.limit > 1:
                    left_size = max(1, chunk.limit // 2)
                    right_size = chunk.limit - left_size
                    work.appendleft(
                        ScanChunk(
                            chunk.database,
                            chunk.table,
                            chunk.columns,
                            chunk.partition_id,
                            chunk.offset + left_size,
                            right_size,
                        )
                    )
                    work.appendleft(
                        ScanChunk(
                            chunk.database, chunk.table, chunk.columns, chunk.partition_id, chunk.offset, left_size
                        )
                    )
                    for column_name in chunk.columns:
                        coverage[_coverage_key(chunk.database, chunk.table, column_name)]["total_chunks"] += 1
                    store.update(
                        chunk_id=chunk.chunk_id,
                        chunk={
                            "database": chunk.database,
                            "table": chunk.table,
                            "columns": list(chunk.columns),
                            "partition": chunk.partition_id,
                            "offset": chunk.offset,
                            "limit": chunk.limit,
                            "status": "split",
                            "error_kind": kind,
                            "error": result.error,
                        },
                        findings=findings,
                        coverage=coverage,
                    )
                    continue
                error_entry = {
                    "database": chunk.database,
                    "table": chunk.table,
                    "columns": list(chunk.columns),
                    "partition": chunk.partition_id,
                    "offset": chunk.offset,
                    "kind": kind,
                    "error": result.error,
                }
                scan_errors.append(error_entry)
                for column_name in chunk.columns:
                    item = coverage[_coverage_key(chunk.database, chunk.table, column_name)]
                    item["status"] = kind
                    item["failed_chunks"] += 1
                store.update(
                    chunk_id=chunk.chunk_id,
                    chunk={**error_entry, "status": "error"},
                    findings=findings,
                    coverage=coverage,
                )
                continue

            _scan_rows(result.rows, chunk, findings, coverage, enabled=enabled, redact=config.redact)
            for column_name in chunk.columns:
                item = coverage[_coverage_key(chunk.database, chunk.table, column_name)]
                item["completed_chunks"] += 1
                if item["completed_chunks"] >= item["total_chunks"] and item["failed_chunks"] == 0:
                    item["status"] = "complete"
            chunk_payload = {
                "database": chunk.database,
                "table": chunk.table,
                "columns": list(chunk.columns),
                "partition": chunk.partition_id,
                "offset": chunk.offset,
                "limit": chunk.limit,
                "status": "complete",
                "rows_scanned": len(result.rows),
                "bytes_scanned": result.bytes_read,
            }
            store.update(
                chunk_id=chunk.chunk_id,
                chunk=chunk_payload,
                findings=findings,
                coverage=coverage,
                inventory=inventory_payload,
            )
            # Unknown-size fallback continues until the server returns a short page.
            if table.total_rows is None and not table.partitions and len(result.rows) == chunk.limit:
                for column_name in chunk.columns:
                    coverage[_coverage_key(chunk.database, chunk.table, column_name)]["total_chunks"] += 1
                work.append(
                    ScanChunk(
                        chunk.database,
                        chunk.table,
                        chunk.columns,
                        chunk.partition_id,
                        chunk.offset + chunk.limit,
                        chunk.limit,
                    )
                )

    for item in coverage.values():
        total_chunks = int(item.get("total_chunks") or 0)
        completed_chunks = int(item.get("completed_chunks") or 0)
        if item.get("status") in {"excluded", "unsupported_type"}:
            continue
        item["coverage_percent"] = (
            100.0
            if total_chunks == 0 and item.get("status") == "complete"
            else round(100.0 * completed_chunks / total_chunks, 2)
            if total_chunks
            else 0.0
        )
        if item["coverage_percent"] == 100.0 and int(item.get("failed_chunks") or 0) == 0:
            item["status"] = "complete"
    incomplete = bool(inventory_errors or scan_errors)
    searchable = [item for item in coverage.values() if item.get("status") not in {"excluded", "unsupported_type"}]
    total_chunks = sum(int(item.get("total_chunks") or 0) for item in searchable)
    completed_chunks = sum(int(item.get("completed_chunks") or 0) for item in searchable)
    coverage_percent = (
        100.0
        if not searchable and not incomplete
        else round(100.0 * completed_chunks / total_chunks, 2)
        if total_chunks
        else 0.0
    )
    status = "partial" if incomplete else "complete"
    report = {
        "status": status,
        "checkpoint": str(config.checkpoint) if config.checkpoint is not None else None,
        "resumed": config.resume,
        "inventory": inventory_payload,
        "inventory_errors": inventory_errors,
        "tables_inventory_count": len(inventory),
        "tables_scanned": tables_scanned,
        "findings": sorted(findings.values(), key=lambda item: (str(item.get("type")), str(item.get("fingerprint")))),
        "finding_count": len(findings),
        "occurrence_count": sum(int(item.get("occurrences") or 0) for item in findings.values()),
        "coverage": coverage,
        "coverage_percent": coverage_percent,
        "scan_errors": scan_errors,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "redacted": config.redact,
        "detectors": list(enabled),
    }
    store.update(status=status, findings=findings, coverage=coverage, inventory=inventory_payload, report=report)
    return report


__all__ = ["DiscoverConfig", "run_discovery"]
