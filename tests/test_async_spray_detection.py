"""Native spray discovery hands off lifecycle state before sync credentials."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from types import SimpleNamespace

from redposture_core import stage_spray as spray
from redposture_core.audit_models import AuditRecord
from redposture_core.spray_async_detect import prepare_target
from redposture_core.stage_runtime import ModuleAuditSpec
from redposture_core.targeting import ScanTargetSpec


def test_prepared_spray_detect_is_not_repeated_and_state_closes(monkeypatch, tmp_path):
    observed = []
    closed = []

    def detect(ctx):
        raise AssertionError("duplicate sync detection")

    async def native(ctx, http):
        observed.append("detect")
        await asyncio.sleep(0)
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="airflow",
            service="airflow",
            status="auth_required",
            auth_required=True,
            extra={"is_airflow": True},
        )

    def auth(ctx, record):
        observed.append(("auth", ctx.lifecycle_state))
        return replace(record, status="valid_credentials", extra={**record.extra, "provided_credentials_ok": True})

    state = object()
    spec = ModuleAuditSpec(
        module="airflow",
        label="AIRFLOW",
        default_port=8080,
        detect=detect,
        detect_async=native,
        async_detect_sync_hook=detect,
        auth=auth,
        lifecycle_state_factory=lambda ctx: state,
        lifecycle_state_close=closed.append,
        is_detected=lambda r: r.extra.get("is_airflow") is True,
    )
    monkeypatch.setattr(
        spray.importlib, "import_module", lambda name: SimpleNamespace(build_airflow_spec=lambda ns: spec)
    )
    ns = SimpleNamespace(timeout=1, retries=0, debug=False)
    target = ScanTargetSpec("127.0.0.1", explicit_port=8080, raw="127.0.0.1:8080")
    job = ("airflow", ns, "127.0.0.1", 8080, target)
    prepared = asyncio.run(prepare_target(job, None))
    assert prepared is not None and observed == ["detect"]
    journal = spray.AttemptJournal(str(tmp_path / "spray.sqlite3"), "fixed", False)
    token = spray._PREFETCHED_SPRAY.set(prepared)
    try:
        spray._run_target(
            *job[:1],
            job[1],
            job[2],
            job[3],
            job[4],
            (spray.Candidate("pair", "qa", "pass"),),
            journal,
            spray.RateGate(1000, 0),
            None,
        )
    finally:
        spray._PREFETCHED_SPRAY.reset(token)
        journal.close()
    assert observed == ["detect", ("auth", state)]
    assert closed == [state]


def test_paused_scheduler_polls_source_without_waiting_for_detection():
    import queue

    from redposture_core.scheduler import BoundedScheduler

    class Source:
        def __init__(self):
            self.calls = 0
            self.closed = False

        def __iter__(self):
            return self

        def __next__(self):
            self.calls += 1
            if self.calls == 1:
                raise queue.Empty
            if self.calls == 2:
                return "job"
            raise StopIteration

        def close(self):
            self.closed = True

    source = Source()

    def worker(item):
        yield 0.001
        return item + " done"

    assert list(BoundedScheduler(max_workers=1, max_inflight=2).iter_paused(source, worker, poll_source=True)) == [
        ("job", "job done")
    ]
    assert source.closed


def test_closing_source_cancels_inflight_native_detection(monkeypatch):
    import threading
    import time

    from redposture_core import spray_async_detect

    started = threading.Event()
    cancelled = threading.Event()

    async def prepare(job, logger):
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    monkeypatch.setattr(spray_async_detect, "prepare_target", prepare)
    gate = SimpleNamespace(cancelled=threading.Event())
    journal = SimpleNamespace(job_finished=lambda key: False)
    target = ScanTargetSpec("127.0.0.1", raw="127.0.0.1:8080", explicit_port=8080)
    source = spray_async_detect.PreparedSource(
        [("airflow", SimpleNamespace(), "127.0.0.1", 8080, target)], None, gate, journal, 1, 1
    )
    assert started.wait(1)
    before = time.monotonic()
    source.close()
    assert cancelled.wait(0.3)
    assert time.monotonic() - before < 1.5
