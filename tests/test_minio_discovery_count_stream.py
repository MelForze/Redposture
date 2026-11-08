"""MinIO retains bounded catalogs/results and publishes completed values live."""

from __future__ import annotations

import threading
import tracemalloc

import pytest

from redposture_core.clients.minio_api import MinioResponse
from redposture_core.discovery_occurrences import OccurrenceRegistry
from redposture_core.discovery_spool import SpoolingRecords
from redposture_core.modules.minio import discover
from redposture_core.modules.minio.discover import Budget, discover_secrets
from redposture_core.modules.minio.enumerate import ObjectInfo
from redposture_core.scheduler import SharedNestedScheduler
from scripts.qa_memory_workload import run_memory_workload


def test_minio_sqlite_full_keeps_earlier_findings_and_reads_next_object(monkeypatch: pytest.MonkeyPatch) -> None:
    class LimitedRegistry(OccurrenceRegistry):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            pages = self._db.execute("PRAGMA page_count").fetchone()[0]
            self._db.execute(f"PRAGMA max_page_count={pages}")

    monkeypatch.setattr(discover, "OccurrenceRegistry", LimitedRegistry)
    bodies = {
        "first.env": b'password="first-secret"\n',
        "full.env": b'password="' + b"Ab0" * 15_000 + b'"\n',
        "last.env": b'password="last-secret"\n',
    }

    class Client:
        def get_object_range(self, _bucket, key, *, start, length, signed):
            return MinioResponse(http_status=206, headers={}, body=bodies[key][start : start + length])

    result = discover_secrets(Client(), [ObjectInfo("qa", key, len(body)) for key, body in bodies.items()])
    assert not result.coverage_complete and "storage_failure" in result.partial_reasons
    assert [item["value"] for item in result.findings] == ["first-secret", "last-secret"]


def test_minio_candidate_spool_failure_reports_partial_and_retains_previous_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class LimitedRecords(SpoolingRecords):
        created = 0

        def __init__(self):
            super().__init__()
            if type(self).created == 0:
                pages = self._db.execute("PRAGMA page_count").fetchone()[0]
                self._db.execute(f"PRAGMA max_page_count={pages}")
            type(self).created += 1

    monkeypatch.setattr(discover, "SpoolingRecords", LimitedRecords)

    class Client:
        def get_object_range(self, _bucket, key, *, start, length, signed):
            body = f'password="secret-{key[-12:]}"\n'.encode()
            return MinioResponse(http_status=206, headers={}, body=body[start : start + length])

    objects = [ObjectInfo("qa", "config-" + "a" * 500 + f"-{i:05d}.env", 32) for i in range(100)]
    result = discover_secrets(Client(), objects)
    assert not result.coverage_complete and "storage_failure" in result.partial_reasons
    assert 0 < len(result.findings) == len(result.candidates) < len(objects)


def test_minio_publishes_closed_secret_before_reading_the_next_range() -> None:
    emitted = []
    observed = []
    body = b'password="first-secret"\n' + b"ordinary safe event\n" * 20

    class Client:
        def get_object_range(self, _bucket, _key, *, start, length, signed):
            if start:
                observed.append(bool(emitted))
            return MinioResponse(http_status=206, headers={}, body=body[start : start + length])

    result = discover_secrets(
        Client(),
        [ObjectInfo(bucket="qa", key="config.env", size=len(body))],
        budget=Budget(chunk_size=64),
        on_finding=emitted.append,
    )
    assert result.coverage_complete
    assert len(result.findings) == len(emitted) == 1
    assert emitted[0]["value"] == "first-secret"
    assert observed and observed[0] is True


def test_minio_long_neutral_value_does_not_hide_later_secret_or_mark_partial() -> None:
    body = b"note=" + b"x" * 1_200_000 + b"\npassword=final-secret\n"

    class Client:
        def get_object_range(self, _bucket, _key, *, start, length, signed):
            return MinioResponse(http_status=206, headers={}, body=body[start : start + length])

    result = discover_secrets(
        Client(),
        [ObjectInfo(bucket="qa", key="config.env", size=len(body))],
        budget=Budget(chunk_size=32_768),
    )
    assert result.coverage_complete
    assert result.partial_reasons == []
    assert [item["value"] for item in result.findings] == ["final-secret"]


def test_parallel_minio_publishes_fast_findings_while_first_object_is_blocked() -> None:
    fast_seen = threading.Event()
    emitted = []

    class Client:
        def get_object_range(self, _bucket, key, *, start, length, signed):
            if key == "slow.env":
                assert fast_seen.wait(2), "a fast object's finding was blocked behind the first object"
            body = f'password="secret-{key}"\n'.encode()
            return MinioResponse(http_status=206, headers={}, body=body[start : start + length])

    def publish(finding):
        emitted.append(finding)
        if finding["key"] == "fast.env":
            fast_seen.set()

    scheduler = SharedNestedScheduler(max_workers=2)
    try:
        result = discover_secrets(
            Client(),
            [ObjectInfo(bucket="qa", key=key, size=32) for key in ["slow.env", "fast.env"]],
            on_finding=publish,
            nested_scheduler=scheduler,
        )
    finally:
        scheduler.close()
    assert result.coverage_complete
    assert [item["key"] for item in emitted] == ["fast.env", "slow.env"]
    assert [item["key"] for item in result.findings] == ["slow.env", "fast.env"]


def _check_many_objects(count: int) -> dict[str, int]:

    class Client:
        def get_object_range(self, _bucket, key, *, start, length, signed):
            number = int(key.removeprefix("config-").removesuffix(".env"))
            body = f'password="secret-{number:08d}"\n'.encode()
            return MinioResponse(http_status=206, headers={}, body=body[start : start + length])

    objects = (ObjectInfo(bucket="qa", key=f"config-{number:08d}.env", size=32) for number in range(count))
    tracemalloc.start()
    try:
        result = discover_secrets(Client(), objects, budget=Budget(time_budget=900))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result.coverage_complete and result.objects_scanned == count
    assert len(result.candidates) == len(result.findings) == count
    assert result.findings[0]["value"] == "secret-00000000"
    assert result.findings[-1]["value"] == f"secret-{count - 1:08d}"
    assert peak < 12_000_000, f"MinIO retained {peak} bytes across objects"
    return {"count": count, "peak": peak}


def test_minio_many_objects_do_not_accumulate_candidates_and_findings_in_ram() -> None:
    # Cover the same reader/serialization branches in the parent. Cardinality
    # and tracemalloc are measured in a clean process, without the coverage
    # tracer's allocation/CPU overhead or retained state from earlier tests.
    _check_many_objects(3)
    run_memory_workload(__file__, "_check_many_objects", 100_000)


def test_minio_many_findings_in_one_object_spill_dedup_and_keep_late_duplicate_out() -> None:
    count = 50_000
    body = (
        "".join(f'password="secret-{number:08d}"\n' for number in range(count)) + 'password="secret-00000000"\n'
    ).encode()
    callbacks = 0

    class Client:
        def get_object_range(self, _bucket, _key, *, start, length, signed):
            return MinioResponse(http_status=206, headers={}, body=body[start : start + length])

    def publish(_finding):
        nonlocal callbacks
        callbacks += 1

    tracemalloc.start()
    try:
        result = discover_secrets(
            Client(),
            [ObjectInfo(bucket="qa", key="all.env", size=len(body))],
            budget=Budget(time_budget=900),
            on_finding=publish,
        )
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result.coverage_complete and result.objects_scanned == 1
    assert len(result.findings) == callbacks == count
    assert result.findings[-1]["value"] == "secret-00049999"
    assert peak < 8_000_000
