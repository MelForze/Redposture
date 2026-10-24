"""Discovery failure, checkpoint and backpressure regressions for native spray."""

from __future__ import annotations

import asyncio
import queue
import threading
import time
from types import SimpleNamespace

import pytest

from redposture_core import spray_async_detect as native
from redposture_core.stage_runtime import ModuleAuditSpec
from redposture_core.targeting import ScanTargetSpec


def job():
    return (
        "airflow",
        SimpleNamespace(timeout=1, retries=0, debug=False),
        "127.0.0.1",
        8080,
        ScanTargetSpec("127.0.0.1", explicit_port=8080, raw="127.0.0.1:8080"),
    )


def next_ready(source):
    deadline = time.monotonic() + 3
    while True:
        try:
            return next(source)
        except queue.Empty:
            if time.monotonic() >= deadline:
                pytest.fail("discovery source did not finish")
            time.sleep(0.002)


@pytest.mark.parametrize("reason", ["completed", "cancelled"])
def test_source_skips_finished_or_cancelled_jobs_without_network(monkeypatch, reason):
    async def forbidden(*args):
        pytest.fail("checkpoint/cancellation must prevent discovery")

    monkeypatch.setattr(native, "prepare_target", forbidden)
    event = threading.Event()
    if reason == "cancelled":
        event.set()
    source = native.PreparedSource(
        [job()],
        None,
        SimpleNamespace(cancelled=event),
        SimpleNamespace(job_finished=lambda key: reason == "completed"),
        1,
        1,
    )
    try:
        assert next_ready(source) == (job(), None)
        with pytest.raises(StopIteration):
            next_ready(source)
    finally:
        source.close()
    assert not source._thread.is_alive()


def test_source_reports_detector_error_instead_of_silent_completion(monkeypatch):
    async def fail(*args):
        raise ValueError("bad discovery response")

    monkeypatch.setattr(native, "prepare_target", fail)
    source = native.PreparedSource(
        [job()],
        None,
        SimpleNamespace(cancelled=threading.Event()),
        SimpleNamespace(job_finished=lambda key: False),
        1,
        1,
    )
    try:
        with pytest.raises(ValueError, match="bad discovery response"):
            next_ready(source)
    finally:
        source.close()
    assert not source._thread.is_alive()


def test_backpressure_and_early_close_release_all_prepared_sessions(monkeypatch):
    created = []
    closed = []
    filled = threading.Event()

    async def prepare(*args):
        ident = len(created)
        created.append(ident)
        value = (None, None, SimpleNamespace(_close_all_lifecycle_states=lambda: closed.append(ident)), None, None)
        if len(created) >= 4:
            filled.set()
        return value

    monkeypatch.setattr(native, "prepare_target", prepare)
    source = native.PreparedSource(
        [job()] * 100,
        None,
        SimpleNamespace(cancelled=threading.Event()),
        SimpleNamespace(job_finished=lambda key: False),
        2,
        1,
    )
    try:
        assert filled.wait(2)
        # Let the bounded result queue apply backpressure while no consumer runs.
        time.sleep(0.05)
        assert len(created) < 12
        assert source._queue.qsize() <= 2
    finally:
        source.close()
    assert not source._thread.is_alive()
    assert sorted(closed) == sorted(created)
    source.release(None)


def test_release_removes_consumed_session_from_source_cleanup(monkeypatch):
    closed = []
    value = (None, None, SimpleNamespace(_close_all_lifecycle_states=lambda: closed.append("session")), None, None)

    async def prepare(*args):
        return value

    monkeypatch.setattr(native, "prepare_target", prepare)
    source = native.PreparedSource(
        [job()],
        None,
        SimpleNamespace(cancelled=threading.Event()),
        SimpleNamespace(job_finished=lambda key: False),
        1,
        1,
    )
    try:
        assert next_ready(source)[1] is value
        source.release(value)
        with pytest.raises(StopIteration):
            next_ready(source)
    finally:
        source.close()
    assert closed == ["session"]


def test_missing_native_adapter_retains_legacy_verifier(monkeypatch):
    spec = ModuleAuditSpec(module="airflow", label="AIRFLOW", default_port=8080)
    monkeypatch.setattr(
        native.importlib, "import_module", lambda name: SimpleNamespace(build_airflow_spec=lambda ns: spec)
    )
    assert asyncio.run(native.prepare_target(job(), None)) is None


def test_cancelled_prepare_closes_allocated_lifecycle_state(monkeypatch):
    closed = []
    state = object()

    def detect(ctx):
        pytest.fail("sync detector must not run")

    async def cancel(ctx, http):
        raise asyncio.CancelledError

    spec = ModuleAuditSpec(
        module="airflow",
        label="AIRFLOW",
        default_port=8080,
        detect=detect,
        detect_async=cancel,
        async_detect_sync_hook=detect,
        lifecycle_state_factory=lambda ctx: state,
        lifecycle_state_close=closed.append,
    )
    monkeypatch.setattr(
        native.importlib, "import_module", lambda name: SimpleNamespace(build_airflow_spec=lambda ns: spec)
    )
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(native.prepare_target(job(), None))
    assert closed == [state]


def test_empty_prepare_closes_runner_resources(monkeypatch):
    closed = []

    async def detect(ctx, http):
        pytest.fail("unexpected call")

    spec = ModuleAuditSpec(module="airflow", label="AIRFLOW", default_port=8080, detect_async=detect)
    monkeypatch.setattr(
        native.importlib, "import_module", lambda name: SimpleNamespace(build_airflow_spec=lambda ns: spec)
    )

    class Runner:
        def __init__(self, **kwargs):
            pass

        async def _run_async_detect_with_state(self, *args):
            return None

        def _close_all_lifecycle_states(self):
            closed.append(True)

    monkeypatch.setattr(native, "AuditCommandRunner", Runner)
    assert asyncio.run(native.prepare_target(job(), None)) is None
    assert closed == [True]


def test_keeper_preparation_only_detects_implementation_without_ddl(monkeypatch):
    from redposture_core.clients import async_retained_socket
    from redposture_core.modules.zookeeper import engine

    def detect(ctx):
        pytest.fail("sync Keeper discovery")

    async def original(ctx, http):
        pytest.fail("ordinary Keeper DDL detector must not run in spray")

    spec = ModuleAuditSpec(
        module="keeper",
        label="KEEPER",
        default_port=9181,
        detect=detect,
        detect_async=original,
        async_detect_sync_hook=detect,
    )

    async def protocol(steps, http, registry):
        call = next(steps)
        assert call.function is engine.detect_zookeeper_implementation
        with pytest.raises(StopIteration) as completed:
            steps.send(
                {"host": "127.0.0.1", "port": 9181, "is_zookeeper": True, "is_keeper": True, "status": "open_no_auth"}
            )
        return completed.value.value

    monkeypatch.setattr(async_retained_socket, "detect_native", protocol)
    monkeypatch.setattr(
        native.importlib, "import_module", lambda name: SimpleNamespace(build_keeper_spec=lambda ns: spec)
    )
    work = (
        "keeper",
        SimpleNamespace(timeout=1, retries=0, debug=False),
        "127.0.0.1",
        9181,
        ScanTargetSpec("127.0.0.1", explicit_port=9181, raw="127.0.0.1:9181"),
    )
    prepared = asyncio.run(native.prepare_target(work, None))
    assert prepared is not None
    assert prepared[4].record.extra["is_keeper"] is True
    assert prepared[4].record.extra["expected_implementation"] == "clickhouse-keeper"
    prepared[2]._close_all_lifecycle_states()
