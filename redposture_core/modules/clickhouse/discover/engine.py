"""Inventory, planning, scan, finding aggregation and coverage orchestration."""

from __future__ import annotations

import fnmatch
import queue
import time
from collections import deque
from collections.abc import Callable, Iterator, MutableMapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ....data_discovery import _scan_portioned_value
from ....discovery_matches import SpoolingSecretMatches
from ....discovery_options import DEFAULT_DISCOVER_TIME
from ....discovery_paths import concat_discovery_text
from ....discovery_values import DiskBackedText
from ....scheduler import NestedSchedulerCancelled
from ....secret_detection import detector_names, fingerprint
from .catalog import CatalogTree
from .checkpoint import CheckpointStore, InMemoryCheckpointStore
from .findings import FindingStore
from .inventory import collect_inventory, is_content_type
from .models import ScanChunk, TableInventory
from .reader import ReadResult, _estimate_bytes, build_chunk_query, read_chunk


@dataclass(frozen=True)
class DiscoverConfig:
    checkpoint: Path | None = None
    resume: bool = False
    chunk_rows: int = 1000
    max_query_time: float = 10.0
    max_query_rows: int = 100_000
    max_query_bytes: int = 0
    max_memory: int | None = None
    max_threads: int = 1
    exclusions: tuple[str, ...] = ()
    detectors: tuple[str, ...] = ()
    redact: bool = True
    max_seconds: float | None = DEFAULT_DISCOVER_TIME
    max_total_bytes: int | None = None


_SYSTEM_DATABASES = {"system", "information_schema", "INFORMATION_SCHEMA"}
DISCOVER_WORKERS = 4


def _excluded(patterns: tuple[str, ...], *names: str) -> bool:
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns for name in names)


def _coverage_key(database: str, table: str, column: str) -> str:
    return f"{database}.{table}.{column}"


def _finding_key(detector: str, value: str | DiskBackedText) -> str:
    return f"{detector}:{fingerprint(value)}"


def _initial_finding(raw: dict[str, Any]) -> dict[str, Any]:
    value = dict(raw)
    if isinstance(value.get("object_path"), DiskBackedText):
        value["object_path"] = concat_discovery_text("", value["object_path"])
    value.setdefault("occurrences", 0)
    value.setdefault("location_count", 0)
    # Locations are capped at 100 when collected; resume must reopen this
    # small mutable list, not append to a finalized checkpoint array spool.
    value["locations"] = [dict(location) for location in value.get("locations") or []]
    for location in value["locations"]:
        if isinstance(location.get("object_path"), DiskBackedText):
            location["object_path"] = concat_discovery_text("", location["object_path"])
    return value


def _scan_rows(
    rows: list[list[Any]],
    chunk: ScanChunk,
    findings: MutableMapping[str, dict[str, Any]],
    coverage: dict[str, dict[str, Any]],
    *,
    enabled: tuple[str, ...],
    redact: bool,
    deadline: float | None = None,
) -> bool:
    complete = True
    for column in chunk.columns:
        coverage_item = coverage[_coverage_key(chunk.database, chunk.table, column)]
        coverage_item.pop("scan_incomplete", None)
        coverage_item.pop("scan_error", None)
    for row_index, row in enumerate(rows):
        locator = {"partition": chunk.partition_id, "row_offset": chunk.offset + row_index}
        for column_index, column in enumerate(chunk.columns):
            if column_index >= len(row):
                continue
            raw_value = row[column_index]
            coverage_item = coverage[_coverage_key(chunk.database, chunk.table, column)]
            coverage_item["rows_scanned"] += 1
            coverage_item["bytes_scanned"] += _estimate_bytes([raw_value])
            try:
                matches, _, covered = _scan_portioned_value(raw_value, "$", 65_536, _deadline=deadline)
                matches = SpoolingSecretMatches(match for match in matches if match.detector in enabled)
                if not covered:
                    coverage_item["scan_incomplete"] = True
                if not matches:
                    # Keep the column context when enabled value detectors
                    # found nothing. Small legacy results retain their paths.
                    matches, _, covered = _scan_portioned_value({column: raw_value}, "$", 65_536, _deadline=deadline)
                    if not covered:
                        coverage_item["scan_incomplete"] = True
            except (OSError, ValueError, TimeoutError) as exc:
                coverage_item["scan_incomplete"] = True
                coverage_item["scan_error"] = str(exc)
                matches = []
            if coverage_item.get("scan_incomplete"):
                complete = False
            for match in matches:
                if match.detector not in enabled or not isinstance(match.value, (str, DiskBackedText)):
                    continue
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
                        "value": match.value,
                        "occurrences": 0,
                        "location_count": 0,
                        "locations": [],
                        "first_seen": now,
                        "last_seen": now,
                        "scanned_context": {"chunk_id": chunk.chunk_id},
                    }
                finding["last_seen"] = now
                if location not in finding["locations"]:
                    finding["occurrences"] += 1
                    finding["location_count"] += 1
                    if len(finding["locations"]) < 100:
                        finding["locations"].append(location)
                try:
                    findings[key] = finding
                except OSError as exc:
                    coverage_item["scan_incomplete"] = True
                    coverage_item["scan_error"] = str(exc)
                    return False
        if deadline is not None and time.monotonic() >= deadline:
            for column in chunk.columns:
                coverage[_coverage_key(chunk.database, chunk.table, column)]["scan_incomplete"] = True
            return False
    return complete


def _planned_chunks(table: TableInventory, columns: tuple[str, ...], chunk_rows: int) -> Iterator[ScanChunk]:
    partitions = table.partitions or [{"partition_id": None, "rows": table.total_rows}]
    for partition in partitions:
        partition_id = partition.get("partition_id")
        raw_rows = partition.get("rows")
        total_rows = int(raw_rows) if isinstance(raw_rows, int) else table.total_rows
        if total_rows is None:
            yield ScanChunk(table.database, table.name, columns, partition_id, 0, chunk_rows)
            continue
        for offset in range(0, max(0, total_rows), chunk_rows):
            yield ScanChunk(
                table.database, table.name, columns, partition_id, offset, min(chunk_rows, total_rows - offset)
            )


def _planned_chunk_count(table: TableInventory, chunk_rows: int, *, deadline: float | None = None) -> int:
    total = 0
    for partition in table.partitions or [{"rows": table.total_rows}]:
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError("discover_time")
        rows = partition.get("rows")
        rows = rows if isinstance(rows, int) else table.total_rows
        total += 1 if rows is None else (max(0, rows) + chunk_rows - 1) // chunk_rows
    return total


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
    started_at: float | None = None,
) -> dict[str, Any]:
    if bool(getattr(nested_scheduler, "cancelled", False)):
        raise NestedSchedulerCancelled("ClickHouse discovery cancelled")
    started = started_at if started_at is not None else time.monotonic()
    deadline = started + config.max_seconds if config.max_seconds is not None else None
    enabled = config.detectors or detector_names()
    unknown = sorted(set(enabled) - set(detector_names()))
    if unknown:
        raise ValueError(f"unknown detectors: {','.join(unknown)}")
    store: CheckpointStore | InMemoryCheckpointStore = (
        CheckpointStore(config.checkpoint, f"{host}:{port}", resume=config.resume, deadline=deadline)
        if config.checkpoint is not None
        else InMemoryCheckpointStore(f"{host}:{port}", resume=config.resume)
    )
    state = store.target_state()
    findings = FindingStore()
    for key, value in (state.get("findings") or {}).items():
        if isinstance(value, dict):
            findings[str(key)] = _initial_finding(value)
    metadata = CatalogTree()
    coverage = metadata.mapping()
    for key, value in (state.get("coverage") or {}).items():
        if isinstance(value, dict):
            coverage[str(key)] = value

    def query_inventory_with_budget(query: str) -> tuple[list[list[Any]] | None, str | None]:
        if deadline is not None and time.monotonic() >= deadline:
            return None, "discover_time"
        rows, error = query_rows(query)
        if deadline is not None and time.monotonic() >= deadline:
            return None, "discover_time"
        return rows, error

    # Inventory loops read this callable metadata without wrapping/consuming rows.
    query_inventory_with_budget.__dict__["deadline"] = deadline
    inventory, inventory_errors = collect_inventory(query_inventory_with_budget)
    budget_reason: str | None = None

    def deadline_expired() -> bool:
        nonlocal budget_reason
        if deadline is not None and time.monotonic() >= deadline:
            budget_reason = "discover_time"
            return True
        return False

    def signature_columns(table):
        for column in table.columns:
            if deadline_expired():
                return
            yield [column.name, column.type_name]

    # Completed chunk IDs are meaningful only for the scope/geometry that
    # produced them. Legacy checkpoints cannot prove that identity.
    scan_signature = {
        "version": 1,
        "chunk_rows": max(1, config.chunk_rows),
        "exclusions": sorted(set(config.exclusions)),
        "detectors": sorted(set(enabled)),
        "redact": config.redact,
        "tables": metadata.sequence(),
    }
    ordered_inventory = (
        ()
        if deadline_expired()
        else (
            inventory.sorted_tables()
            if hasattr(inventory, "sorted_tables")
            else sorted(inventory, key=lambda table: (table.database, table.name))
        )
    )
    for table in ordered_inventory:
        if deadline_expired():
            break
        if table.database in _SYSTEM_DATABASES or _excluded(config.exclusions, table.database, table.full_name):
            continue
        scan_signature["tables"].append(
            {
                "database": table.database,
                "table": table.name,
                "total_rows": table.total_rows,
                "partitions": table.partitions,
                "columns": metadata.sequence(signature_columns(table)),
            }
        )

    if config.resume and not budget_reason:
        previous_signature = state.get("scan_signature")
        has_progress = any(state.get(key) for key in ("chunks", "findings", "coverage", "inventory", "report"))
        if previous_signature != scan_signature and (previous_signature is not None or has_progress):
            reason = (
                "scan scope or chunk configuration changed"
                if previous_signature is not None
                else "legacy scan scope is unknown"
            )
            raise ValueError(f"incompatible discovery checkpoint: {reason}; start without --resume")
    if not deadline_expired():
        store.update(scan_signature=scan_signature)
    inventory_payload = (
        inventory.records
        if hasattr(inventory, "records")
        else metadata.sequence(table.to_dict() for table in inventory)
    )
    scan_errors = metadata.sequence()
    inspected_bytes = 0
    resumed_parents: dict[str, str] = {}
    table_jobs = metadata.sequence()

    for table_index, table in enumerate(inventory):
        if deadline_expired():
            break
        table_name = table.full_name
        if table.database in _SYSTEM_DATABASES or _excluded(config.exclusions, table.database, table_name):
            continue
        content_columns = metadata.sequence()
        for column in table.columns:
            if deadline_expired():
                break
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
        if deadline_expired():
            break
        if not content_columns:
            continue
        columns = content_columns
        try:
            planned_count = _planned_chunk_count(table, max(1, config.chunk_rows), deadline=deadline)
        except TimeoutError:
            budget_reason = "discover_time"
            break
        for column_name in columns:
            if deadline_expired():
                break
            item = coverage[_coverage_key(table.database, table.name, column_name)]
            if not config.resume or not item.get("total_chunks"):
                item["total_chunks"] = planned_count
        if deadline_expired():
            break
        if not planned_count:
            for column_name in columns:
                if deadline_expired():
                    break
                item = coverage[_coverage_key(table.database, table.name, column_name)]
                item["status"] = "complete"
                item["coverage_percent"] = 100.0
        if deadline_expired():
            break
        table_jobs.append({"index": table_index, "columns": columns})

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
        for job in table_jobs:
            table = inventory[job["index"]]
            # Chunk planning runs on the coordinator. Detach the small set of
            # selected column names before workers start reading chunks:
            # sharing this live SQLite view with result writes can corrupt a
            # concurrent cursor on the same connection.
            columns = tuple(job["columns"])
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
        query = build_chunk_query(
            chunk,
            max_query_time=min(
                config.max_query_time,
                max(0.001, deadline - time.monotonic()) if deadline is not None else config.max_query_time,
            ),
            max_query_rows=config.max_query_rows,
            max_query_bytes=config.max_query_bytes,
            max_memory=config.max_memory,
            max_threads=config.max_threads,
        )
        current_session = session_queue.get()
        try:
            if bool(getattr(nested_scheduler, "cancelled", False)):
                raise NestedSchedulerCancelled("ClickHouse discovery cancelled")
            return read_chunk(current_session, query, max_bytes=config.max_total_bytes, deadline=deadline)
        finally:
            session_queue.put(current_session)

    def record_result_impl(chunk: ScanChunk, result: Any) -> tuple[ScanChunk, ...]:
        nonlocal inspected_bytes, budget_reason

        def scan_and_emit(rows: list[list[Any]]) -> bool:
            nonlocal inspected_bytes, budget_reason
            previous_count = len(findings)
            complete = _scan_rows(
                rows, chunk, findings, coverage, enabled=enabled, redact=config.redact, deadline=deadline
            )
            if on_chunk_findings is not None:
                discovered = findings.created_after(previous_count)
                if discovered:
                    on_chunk_findings(chunk, discovered)
            if complete:
                return True
            expired = deadline is not None and time.monotonic() >= deadline
            kind = "discover_time" if expired else "source_scan_incomplete"
            if expired:
                budget_reason = kind
            inspected_bytes += result.bytes_read
            error = {"database": chunk.database, "table": chunk.table, "offset": chunk.offset, "kind": kind}
            scan_errors.append(error)
            for column in chunk.columns:
                item = coverage[_coverage_key(chunk.database, chunk.table, column)]
                item["status"] = "partial"
                item["failed_chunks"] += 1
            store.update(
                chunk_id=chunk.chunk_id,
                chunk={**error, "status": "error"},
                findings=findings,
                coverage=coverage,
                inventory=inventory_payload,
            )
            return False

        if budget_reason is not None:
            return ()
        if result.error == "discover_time" and not result.rows:
            budget_reason = str(result.error)
            return ()
        if result.error == "discover_max_bytes" and result.rows:
            # A portion filled between rows. Persist its findings and continue
            # at the next offset during this run, with a fresh portion cap.
            if len(result.rows) >= chunk.limit:
                result = ReadResult(result.rows, result.bytes_read)
            else:
                if not scan_and_emit(result.rows):
                    return ()
                inspected_bytes += result.bytes_read
                next_offset = chunk.offset + len(result.rows)
                parent_id = resumed_parents.get(chunk.chunk_id, chunk.chunk_id)
                original = resumed_originals.get(chunk.chunk_id, chunk)
                remaining = ScanChunk(
                    chunk.database,
                    chunk.table,
                    chunk.columns,
                    chunk.partition_id,
                    next_offset,
                    chunk.limit - len(result.rows),
                )
                resumed_parents[remaining.chunk_id] = parent_id
                resumed_originals[remaining.chunk_id] = original
                successor = unknown_next.pop(chunk.chunk_id, None)
                if successor is not None:
                    unknown_next[remaining.chunk_id] = successor
                store.update(
                    chunk_id=parent_id,
                    chunk={"status": "budget_partial", "next_offset": next_offset},
                    findings=findings,
                    coverage=coverage,
                    inventory=inventory_payload,
                )
                return (remaining,)
        if result.error and result.rows:
            # A streaming driver can yield useful rows before its next block
            # fails. Keep those findings and a resume frontier instead of
            # discarding the entire chunk and reporting zero discoveries.
            # The reader already owns complete prefix rows and their byte
            # count. Keep its lazy spool rather than copying every row view.
            accepted = result.rows
            accepted_bytes = result.bytes_read
            if not scan_and_emit(accepted):
                return ()
            inspected_bytes += accepted_bytes
            kind = (
                result.error if result.error in {"discover_time", "discover_max_bytes"} else _error_kind(result.error)
            )
            if result.error in {"discover_time", "discover_max_bytes"}:
                budget_reason = str(result.error)
            scan_errors.append(
                {
                    "database": chunk.database,
                    "table": chunk.table,
                    "columns": chunk.columns,
                    "partition": chunk.partition_id,
                    "offset": chunk.offset,
                    "kind": kind,
                    "error": result.error,
                }
            )
            for column_name in chunk.columns:
                coverage[_coverage_key(chunk.database, chunk.table, column_name)]["status"] = "partial"
            store.update(
                chunk_id=resumed_parents.get(chunk.chunk_id, chunk.chunk_id),
                chunk={"status": "budget_partial", "next_offset": chunk.offset + len(accepted)},
                findings=findings,
                coverage=coverage,
                inventory=inventory_payload,
            )
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
                        "columns": chunk.columns,
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
                "columns": chunk.columns,
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
        if not scan_and_emit(rows):
            return ()
        inspected_bytes += bytes_read
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
            "columns": chunk.columns,
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
        completed_parent_id = resumed_parents.get(chunk.chunk_id)
        if completed_parent_id is not None:
            original = resumed_originals[chunk.chunk_id]
            parent_payload = {
                **chunk_payload,
                "offset": original.offset,
                "limit": original.limit,
                "rows_scanned": chunk.offset - original.offset + len(rows),
            }
            store.update(chunk_id=completed_parent_id, chunk=parent_payload, findings=findings, coverage=coverage)
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

    def record_result(chunk: ScanChunk, result: Any) -> tuple[ScanChunk, ...]:
        children = record_result_impl(chunk, result)
        # Any continuation/split has transferred its live frontier above.
        # Completed/error ranges need no in-memory history: the checkpoint
        # owns the durable resume description.
        resumed_parents.pop(chunk.chunk_id, None)
        resumed_originals.pop(chunk.chunk_id, None)
        unknown_next.pop(chunk.chunk_id, None)
        return children

    if nested_scheduler is None or len(available_sessions) == 1:
        initial = iter(initial_chunks())
        pending: deque[ScanChunk] = deque()
        while budget_reason is None:
            if pending:
                chunk = pending.popleft()
            else:
                try:
                    chunk = next(initial)
                except StopIteration:
                    break
            pending.extendleft(reversed(record_result(chunk, read_one(chunk))))
    else:
        nested_scheduler.run_dynamic(
            initial_chunks(),
            read_one,
            record_result,
            key=scheduler_key,
            per_key_limit=min(DISCOVER_WORKERS, len(available_sessions)),
        )

    scan_errors.sort_errors(
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
        item.get("scan_incomplete") or item.get("status") not in {"complete", "excluded", "unsupported_type"}
        for item in coverage.values()
    )
    searchable_count = total_chunks = completed_chunks = 0
    for item in coverage.values():
        if item.get("status") not in {"excluded", "unsupported_type"}:
            searchable_count += 1
            total_chunks += int(item.get("total_chunks") or 0)
            completed_chunks += int(item.get("completed_chunks") or 0)
    coverage_percent = (
        100.0
        if not searchable_count and not incomplete
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
        "findings": findings.sorted_values(),
        "finding_count": len(findings),
        "occurrence_count": sum(int(item.get("occurrences") or 0) for item in findings.values()),
        "coverage": coverage,
        "coverage_percent": coverage_percent,
        "scan_errors": scan_errors,
        "bytes_scanned": inspected_bytes,
        "partial_reasons": ([budget_reason] if budget_reason else [])
        + (["source_scan_incomplete"] if any(item.get("scan_incomplete") for item in coverage.values()) else []),
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "redacted": False,
        "detectors": list(enabled),
    }
    store.update(status=status, findings=findings, coverage=coverage, inventory=inventory_payload, report=report)
    return report


__all__ = ["DISCOVER_WORKERS", "DiscoverConfig", "run_discovery"]
