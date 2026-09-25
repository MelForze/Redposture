"""Cross-module invariants for bounded parallel discovery."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

import pytest

from redposture_core.clients.minio_api import MinioResponse, S3Error
from redposture_core.modules.clickhouse.discover.engine import DISCOVER_WORKERS as CLICKHOUSE_WORKERS
from redposture_core.modules.elastic.discover import DISCOVER_WORKERS as ELASTIC_WORKERS
from redposture_core.modules.minio.discover import DISCOVER_WORKERS as MINIO_WORKERS
from redposture_core.modules.minio.discover import Budget, discover_secrets
from redposture_core.modules.minio.enumerate import ObjectInfo
from redposture_core.scheduler import SharedNestedScheduler


def test_fixed_discovery_limits_match_the_command_wide_contract() -> None:
    assert MINIO_WORKERS == 8
    assert ELASTIC_WORKERS == 8
    assert CLICKHOUSE_WORKERS == 4


class _RangeClient:
    def __init__(self, bodies: dict[str, bytes]) -> None:
        self.bodies = bodies

    def get_object_range(self, _bucket: str, key: str, *, start: int, length: int, signed: bool) -> MinioResponse:
        assert signed is True
        body = self.bodies[key]
        if start >= len(body):
            return MinioResponse(416, {}, b"", error=S3Error(416, "InvalidRange", ""))
        # Reverse completion order without changing coordinator merge order.
        time.sleep(0.0005 * (8 - int(key.split(".", 1)[0])))
        return MinioResponse(206, {}, body[start : start + length])


@pytest.mark.parametrize("workers", [1, 4, 8])
def test_minio_parallel_discovery_has_exact_budget_and_stable_merge(workers: int) -> None:
    bodies = {f"{index}.env": f"password=Secret-{index:02d}".encode() for index in range(8)}
    objects = [ObjectInfo(bucket="bucket", key=key, size=len(body)) for key, body in bodies.items()]
    scheduler = SharedNestedScheduler(max_workers=workers)
    try:
        result = discover_secrets(
            _RangeClient(bodies),
            objects,
            budget=Budget(max_total_bytes=73, chunk_size=11),
            nested_scheduler=scheduler,
            scheduler_key="target",
        )
    finally:
        scheduler.close()

    assert result.bytes_read == 73
    assert result.partial_reasons == ["max_bytes"]
    assert result.candidates == sorted(
        result.candidates, key=lambda item: objects.index(next(o for o in objects if o.key == item["key"]))
    )
    assert len({(item["type"], item["bucket"], item["key"], item["value"]) for item in result.findings}) == len(
        result.findings
    )


@dataclass(frozen=True)
class _Chunk:
    table: str
    start: int
    rows: int


@pytest.mark.parametrize("workers", [1, 4, 8])
def test_dynamic_discovery_followups_are_coordinator_owned_and_deterministic(workers: int) -> None:
    scheduler = SharedNestedScheduler(max_workers=workers)
    coordinator_thread = threading.get_ident()
    callback_threads: list[int] = []
    completed: list[_Chunk] = []
    total_rows = 0

    def read(chunk: _Chunk) -> int:
        time.sleep(0.0002 if chunk.table == "slow" else 0)
        return chunk.rows

    def merge(chunk: _Chunk, rows: int):
        nonlocal total_rows
        callback_threads.append(threading.get_ident())
        completed.append(chunk)
        total_rows += rows
        if chunk.start + rows < 30:
            return (_Chunk(chunk.table, chunk.start + rows, min(5, 30 - chunk.start - rows)),)
        return ()

    try:
        scheduler.run_dynamic(
            [_Chunk("slow", 0, 5), _Chunk("fast", 0, 5)],
            read,
            merge,
            key="target",
            per_key_limit=workers,
        )
    finally:
        scheduler.close()

    assert total_rows == 60
    assert callback_threads and set(callback_threads) == {coordinator_thread}
    assert sorted((chunk.table, chunk.start) for chunk in completed) == [
        (table, start) for table in ("fast", "slow") for start in range(0, 30, 5)
    ]
