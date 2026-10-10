"""Cross-module invariants for bounded parallel discovery."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
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


@pytest.mark.parametrize("dynamic", [False, True])
def test_slow_discovery_target_does_not_block_another_target(dynamic: bool) -> None:
    scheduler = SharedNestedScheduler(max_workers=2)
    slow_started = threading.Event()
    release_slow = threading.Event()
    fast_finished = threading.Event()
    errors: list[BaseException] = []

    def run(items: range | list[int], worker: Callable[[int], int], key: str) -> list[tuple[int, int]]:
        if not dynamic:
            return list(scheduler.iter_completed(items, worker, key=key, per_key_limit=1))
        completed: list[tuple[int, int]] = []
        scheduler.run_dynamic(
            items,
            worker,
            lambda item, result: completed.append((item, result)),
            key=key,
            per_key_limit=1,
        )
        return completed

    def slow_worker(index: int) -> int:
        if index == 0:
            slow_started.set()
            assert release_slow.wait(3)
        return index

    def slow_discovery() -> None:
        try:
            assert run(range(2), slow_worker, "slow") == [
                (0, 0),
                (1, 1),
            ]
        except BaseException as exc:  # noqa: BLE001 - return worker-thread failures to the test
            errors.append(exc)

    def fast_discovery() -> None:
        try:
            assert run([0], lambda value: value, "fast") == [(0, 0)]
            fast_finished.set()
        except BaseException as exc:  # noqa: BLE001 - return worker-thread failures to the test
            errors.append(exc)

    slow_thread = threading.Thread(target=slow_discovery)
    fast_thread = threading.Thread(target=fast_discovery)
    slow_thread.start()
    try:
        assert slow_started.wait(1), errors
        fast_thread.start()
        assert fast_finished.wait(0.5), "the slow target occupied both nested workers"
    finally:
        release_slow.set()
        slow_thread.join(timeout=3)
        if fast_thread.ident is not None:
            fast_thread.join(timeout=3)
        scheduler.close()
    assert not slow_thread.is_alive() and not fast_thread.is_alive()
    assert not errors


def test_minio_live_finding_from_fast_target_arrives_while_other_target_is_stalled() -> None:
    scheduler = SharedNestedScheduler(max_workers=16)
    release_slow = threading.Event()
    slow_started = threading.Event()
    fast_finding = threading.Event()
    errors: list[BaseException] = []
    started_count = 0
    started_lock = threading.Lock()

    class BlockingClient(_RangeClient):
        def get_object_range(self, bucket: str, key: str, *, start: int, length: int, signed: bool) -> MinioResponse:
            nonlocal started_count
            with started_lock:
                started_count += 1
                if started_count == 8:
                    slow_started.set()
            assert release_slow.wait(3)
            assert signed is True
            body = self.bodies[key]
            if start >= len(body):
                return MinioResponse(416, {}, b"", error=S3Error(416, "InvalidRange", ""))
            return MinioResponse(206, {}, body[start : start + length])

    slow_bodies = {f"{index}.env": f"password=SlowSecret-{index:02d}".encode() for index in range(16)}
    slow_objects = [ObjectInfo(bucket="slow", key=key, size=len(body)) for key, body in slow_bodies.items()]
    fast_body = b"password=FastSecret-2026"
    fast_objects = [ObjectInfo(bucket="fast", key="0.env", size=len(fast_body))]

    def slow_discovery() -> None:
        try:
            result = discover_secrets(
                BlockingClient(slow_bodies),
                slow_objects,
                budget=Budget(max_total_bytes=None, chunk_size=128),
                nested_scheduler=scheduler,
                scheduler_key="slow",
            )
            assert result.objects_scanned == 16
        except BaseException as exc:  # noqa: BLE001 - return worker-thread failures to the test
            errors.append(exc)

    def fast_discovery() -> None:
        try:
            result = discover_secrets(
                _RangeClient({"0.env": fast_body}),
                fast_objects,
                on_finding=lambda _finding: fast_finding.set(),
                nested_scheduler=scheduler,
                scheduler_key="fast",
            )
            assert result.objects_scanned == 1
        except BaseException as exc:  # noqa: BLE001 - return worker-thread failures to the test
            errors.append(exc)

    slow_thread = threading.Thread(target=slow_discovery)
    fast_thread = threading.Thread(target=fast_discovery)
    slow_thread.start()
    try:
        assert slow_started.wait(1), errors
        fast_thread.start()
        assert fast_finding.wait(0.5), "fast discovery finding was delayed by another target"
    finally:
        release_slow.set()
        slow_thread.join(timeout=3)
        if fast_thread.ident is not None:
            fast_thread.join(timeout=3)
        scheduler.close()
    assert not slow_thread.is_alive() and not fast_thread.is_alive()
    assert not errors
