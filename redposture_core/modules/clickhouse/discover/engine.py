"""Inventory, planning, scan, finding aggregation and coverage orchestration."""

from __future__ import annotations

import fnmatch
import queue
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ....scheduler import NestedSchedulerCancelled
from ....secret_detection import detector_names, fingerprint, mask_secret, scan_value
from .checkpoint import CheckpointStore, InMemoryCheckpointStore
from .inventory import collect_inventory, is_content_type
from .models import ScanChunk, TableInventory
from .reader import ReadResult, build_chunk_query, read_chunk


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
    max_seconds: float | None = None
    max_total_bytes: int | None = None


_SYSTEM_DATABASES = {"system", "information_schema", "INFORMATION_SCHEMA"}
DISCOVER_WORKERS = 4


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
            matches = scan_value(raw_value, object_path="$", enabled=enabled)
            if not matches:
                # Re-key scalar plaintext only when the value itself has no
                # recognizable shape; preserve legacy paths for structured data.
                matches = scan_value({column: raw_value}, object_path="$", enabled=enabled)
            for match in matches:
                object_path = "$" if match.object_path == f"$.{column}" else match.object_path
                key = _finding_key(match.detector, match.value)
                location = {
                    "database": chunk.database,
                    "table": chunk.table,
                    "column": column,
                    "object_path": object_path,
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
                        "object_path": object_path,
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


def run_discovery(
    session: Any,
    *,
    host: str,
    port: int,
    config: DiscoverConfig,
    query_rows: Any,
    sessions: tuple[Any, ...] | None = None,
    nested_scheduler: Any | None = None,
    scheduler_key: Any | None = None,
    on_chunk_findings: Callable[[ScanChunk, list[dict[str, Any]]], None] | None = None,
) -> dict[str, Any]:
    if bool(getattr(nested_scheduler, "cancelled", False)):
        raise NestedSchedulerCancelled("ClickHouse discovery cancelled")
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
    # Completed chunk IDs are meaningful only for the scope/geometry that
    # produced them. Legacy checkpoints cannot prove that identity.
    scan_signature = {
        "version": 1,
        "chunk_rows": max(1, config.chunk_rows),
        "exclusions": sorted(set(config.exclusions)),
        "detectors": sorted(set(enabled)),
        "redact": config.redact,
        "tables": sorted(
            (
                {
                    "database": table.database,
                    "table": table.name,
                    "total_rows": table.total_rows,
                    "partitions": table.partitions,
                    "columns": [[column.name, column.type_name] for column in table.columns],
                }
                for table in inventory
                if table.database not in _SYSTEM_DATABASES
                and not _excluded(config.exclusions, table.database, table.full_name)
            ),
            key=lambda item: (item["database"], item["table"]),
        ),
    }
    if config.resume:
        previous_signature = state.get("scan_signature")
        has_progress = any(state.get(key) for key in ("chunks", "findings", "coverage", "inventory", "report"))
        if previous_signature != scan_signature and (previous_signature is not None or has_progress):
            reason = (
                "scan scope or chunk configuration changed"
                if previous_signature is not None
                else "legacy scan scope is unknown"
            )
            raise ValueError(f"incompatible discovery checkpoint: {reason}; start without --resume")
    store.update(scan_signature=scan_signature)
    inventory_payload = [table.to_dict() for table in inventory]
    scan_errors: list[dict[str, Any]] = []
    inspected_bytes = 0
    budget_reason: str | None = None
    deadline = started + config.max_seconds if config.max_seconds is not None else None
    resumed_parents: dict[str, str] = {}
    table_jobs: list[tuple[TableInventory, tuple[str, ...]]] = []

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
        columns = tuple(content_columns)
        work = _planned_chunks(table, columns, max(1, config.chunk_rows))
        for column_name in columns:
            item = coverage[_coverage_key(table.database, table.name, column_name)]
            if not config.resume or not item.get("total_chunks"):
                item["total_chunks"] = len(work)
        if not work:
            for column_name in columns:
                item = coverage[_coverage_key(table.database, table.name, column_name)]
                item["status"] = "complete"
                item["coverage_percent"] = 100.0
        table_jobs.append((table, columns))

    available_sessions = tuple(sessions or (session,))
    session_queue: queue.Queue[Any] = queue.Queue()
    for available_session in available_sessions:
        session_queue.put(available_session)

    unknown_next: dict[str, ScanChunk] = {}
    resumed_originals: dict[str, ScanChunk] = {}
    saved_chunks = state.get("chunks") or {}

    def following(chunk: ScanChunk) -> ScanChunk:
        return ScanChunk(
            chunk.database, chunk.table, chunk.columns, chunk.partition_id, chunk.offset + chunk.limit, chunk.limit
        )

    def restore(chunk: ScanChunk, successor: ScanChunk | None):
        """Restore completed ranges, split leaves and the unknown-size frontier.

        Split ranges are deterministic, so schema-v1 checkpoints written before
        explicit frontier metadata can also be resumed without replaying leaves.
        Only the rightmost leaf may continue beyond its original parent range.
        """
        saved = saved_chunks.get(chunk.chunk_id)
        while isinstance(saved, dict) and saved.get("status") == "complete":
            if successor is None or saved.get("rows_scanned") != chunk.limit:
                return
            chunk = successor
            successor = following(chunk)
            saved = saved_chunks.get(chunk.chunk_id)
        if isinstance(saved, dict):
            if saved.get("status") == "error":
                for column_name in chunk.columns:
                    item = coverage[_coverage_key(chunk.database, chunk.table, column_name)]
                    item["failed_chunks"] = max(0, int(item.get("failed_chunks") or 0) - 1)
                    item["status"] = "pending"
            if saved.get("status") == "split" and chunk.limit > 1:
                left_size = max(1, chunk.limit // 2)
                left = ScanChunk(
                    chunk.database, chunk.table, chunk.columns, chunk.partition_id, chunk.offset, left_size
                )
                right = ScanChunk(
                    chunk.database,
                    chunk.table,
                    chunk.columns,
                    chunk.partition_id,
                    chunk.offset + left_size,
                    chunk.limit - left_size,
                )
                yield from restore(left, None)
                yield from restore(right, successor)
                return
            if saved.get("status") == "budget_partial":
                next_offset = saved.get("next_offset")
                if isinstance(next_offset, int) and chunk.offset < next_offset < chunk.offset + chunk.limit:
                    remaining = ScanChunk(
                        chunk.database,
                        chunk.table,
                        chunk.columns,
                        chunk.partition_id,
                        next_offset,
                        chunk.offset + chunk.limit - next_offset,
                    )
                    resumed_parents[remaining.chunk_id] = chunk.chunk_id
                    resumed_originals[remaining.chunk_id] = chunk
                    if successor is not None:
                        unknown_next[remaining.chunk_id] = successor
                    yield remaining
                    return
        if successor is not None:
            unknown_next[chunk.chunk_id] = successor
        yield chunk

    def initial_chunks():
        for table, columns in table_jobs:
            for chunk in _planned_chunks(table, columns, max(1, config.chunk_rows)):
                if budget_reason is not None:
                    return
                successor = following(chunk) if table.total_rows is None and not table.partitions else None
                yield from restore(chunk, successor)

    def read_one(chunk: ScanChunk):
        if bool(getattr(nested_scheduler, "cancelled", False)):
            raise NestedSchedulerCancelled("ClickHouse discovery cancelled")
        if deadline is not None and time.monotonic() >= deadline:
            return ReadResult([], 0, "discover_time")
        if config.max_total_bytes is not None and inspected_bytes >= config.max_total_bytes:
            return ReadResult([], 0, "discover_max_bytes")
        query = build_chunk_query(
            chunk,
            max_query_time=config.max_query_time,
            max_query_rows=config.max_query_rows,
            max_query_bytes=config.max_query_bytes,
            max_memory=config.max_memory,
            max_threads=config.max_threads,
        )
        current_session = session_queue.get()
        try:
            if bool(getattr(nested_scheduler, "cancelled", False)):
                raise NestedSchedulerCancelled("ClickHouse discovery cancelled")
            return read_chunk(current_session, query)
        finally:
            session_queue.put(current_session)

    def record_result(chunk: ScanChunk, result: Any) -> tuple[ScanChunk, ...]:
        nonlocal inspected_bytes, budget_reason
        if budget_reason is not None:
            return ()
        if result.error in {"discover_time", "discover_max_bytes"}:
            budget_reason = str(result.error)
            return ()
        if result.error:
            kind = _error_kind(result.error)
            if kind in {"timeout", "memory_limit", "resource_limit"} and chunk.limit > 1:
                left_size = max(1, chunk.limit // 2)
                right_size = chunk.limit - left_size
                children = (
                    ScanChunk(chunk.database, chunk.table, chunk.columns, chunk.partition_id, chunk.offset, left_size),
                    ScanChunk(
                        chunk.database,
                        chunk.table,
                        chunk.columns,
                        chunk.partition_id,
                        chunk.offset + left_size,
                        right_size,
                    ),
                )
                successor = unknown_next.pop(chunk.chunk_id, None)
                if successor is not None:
                    unknown_next[children[-1].chunk_id] = successor
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
                return children
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
            return ()

        rows = result.rows
        bytes_read = result.bytes_read
        if config.max_total_bytes is not None and inspected_bytes + bytes_read > config.max_total_bytes:
            remaining = config.max_total_bytes - inspected_bytes
            accepted: list[list[Any]] = []
            bytes_read = 0
            for row in rows:
                row_bytes = sum(len(str(value).encode("utf-8", errors="replace")) for value in row if value is not None)
                if bytes_read + row_bytes > remaining:
                    break
                accepted.append(row)
                bytes_read += row_bytes
            rows = accepted
            budget_reason = "discover_max_bytes"
        previous_keys = set(findings) if on_chunk_findings is not None else set()
        _scan_rows(rows, chunk, findings, coverage, enabled=enabled, redact=config.redact)
        inspected_bytes += bytes_read
        if on_chunk_findings is not None:
            discovered = [dict(finding) for key, finding in findings.items() if key not in previous_keys]
            if discovered:
                on_chunk_findings(chunk, discovered)
        if budget_reason is not None:
            scan_errors.append(
                {"database": chunk.database, "table": chunk.table, "offset": chunk.offset, "kind": budget_reason}
            )
            for column_name in chunk.columns:
                coverage[_coverage_key(chunk.database, chunk.table, column_name)]["status"] = "partial"
            store.update(
                chunk_id=resumed_parents.get(chunk.chunk_id, chunk.chunk_id),
                chunk={"status": "budget_partial", "next_offset": chunk.offset + len(rows)},
                findings=findings,
                coverage=coverage,
                inventory=inventory_payload,
            )
            return ()
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
            "rows_scanned": len(rows),
            "bytes_scanned": bytes_read,
        }
        store.update(
            chunk_id=chunk.chunk_id,
            chunk=chunk_payload,
            findings=findings,
            coverage=coverage,
            inventory=inventory_payload,
        )
        parent_id = resumed_parents.get(chunk.chunk_id)
        if parent_id is not None:
            original = resumed_originals[chunk.chunk_id]
            parent_payload = {
                **chunk_payload,
                "offset": original.offset,
                "limit": original.limit,
                "rows_scanned": chunk.offset - original.offset + len(rows),
            }
            store.update(chunk_id=parent_id, chunk=parent_payload, findings=findings, coverage=coverage)
        successor = unknown_next.pop(chunk.chunk_id, None)
        if successor is not None and len(result.rows) == chunk.limit:
            for column_name in chunk.columns:
                coverage[_coverage_key(chunk.database, chunk.table, column_name)]["total_chunks"] += 1
            unknown_next[successor.chunk_id] = following(successor)
            # The completed range plus rows_scanned is an explicit durable
            # continuation/EOF marker; restore also understands older records.
            store.update(findings=findings, coverage=coverage, inventory=inventory_payload)
            return (successor,)
        return ()

    if nested_scheduler is None or len(available_sessions) == 1:
        work = list(initial_chunks())
        while work and budget_reason is None:
            chunk = work.pop(0)
            work[0:0] = record_result(chunk, read_one(chunk))
    else:
        nested_scheduler.run_dynamic(
            initial_chunks(),
            read_one,
            record_result,
            key=scheduler_key,
            per_key_limit=min(DISCOVER_WORKERS, len(available_sessions)),
        )

    scan_errors.sort(
        key=lambda item: (
            str(item.get("database") or ""),
            str(item.get("table") or ""),
            str(item.get("partition") or ""),
            int(item.get("offset") or 0),
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
    incomplete = bool(inventory_errors or scan_errors or budget_reason) or any(
        item.get("status") not in {"complete", "excluded", "unsupported_type"} for item in coverage.values()
    )
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
        "tables_scanned": len(table_jobs),
        "findings": sorted(findings.values(), key=lambda item: (str(item.get("type")), str(item.get("fingerprint")))),
        "finding_count": len(findings),
        "occurrence_count": sum(int(item.get("occurrences") or 0) for item in findings.values()),
        "coverage": coverage,
        "coverage_percent": coverage_percent,
        "scan_errors": scan_errors,
        "bytes_scanned": inspected_bytes,
        "partial_reasons": [budget_reason] if budget_reason else [],
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "redacted": config.redact,
        "detectors": list(enabled),
    }
    store.update(status=status, findings=findings, coverage=coverage, inventory=inventory_payload, report=report)
    return report


__all__ = ["DISCOVER_WORKERS", "DiscoverConfig", "run_discovery"]
