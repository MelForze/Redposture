"""Automatic probe time must be attributable without changing execution."""

from __future__ import annotations

import json
import threading
from dataclasses import replace
from types import SimpleNamespace

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.runtime_diagnostics import RuntimeDiagnostics
from redposture_core.stage_runtime import AuditCommandPlan, AuditCommandRunner, ModuleAuditSpec


@pytest.mark.parametrize("failed", [False, True])
def test_probe_duration_active_worker_and_failure_cleanup_are_observed(failed, tmp_path):
    clock = [0]
    observer = RuntimeDiagnostics(clock_ns=lambda: clock[0])
    during = []
    invocations = []

    def detect(ctx):
        return AuditRecord(host=ctx.host, port=ctx.port, module="test", service="test", status="open_no_auth")

    def probe(ctx, record):
        invocations.append(ctx.host)
        during.append(observer.progress_line())
        clock[0] += 123_456_789
        if failed:
            raise ValueError("probe unavailable")
        return replace(record, extra={**record.extra, "rce": True})

    lines = []
    spec = ModuleAuditSpec(
        module="test",
        label="TEST",
        default_port=9,
        detect=detect,
        rce_probe=probe,
        render=lambda record: [f"TEST service rce={record.extra.get('rce')}"],
        is_detected=lambda record: record.status == "open_no_auth",
    )
    runner = AuditCommandRunner(
        args=SimpleNamespace(debug=True, no_color=True, timeout=1, retries=0, _runtime_observer=observer),
        spec=spec,
        emit_line=lines.append,
    )
    output = tmp_path / "results.json"
    result = runner.run_plan(
        AuditCommandPlan(
            targets_by_port={9: ("local-test",)}, ports=(9,), workers=1, output_format="json", output_path=str(output)
        )
    )
    assert invocations == ["local-test"] and result.detected_count == 1
    record = result.records[0]
    assert record["rce"] is (None if failed else True)
    if failed:
        assert record["rce_probe_error"] == "probe unavailable"
    phase = observer.snapshot()["phases"].get("rce_probe")
    assert phase is not None, "probe time disappeared from phase attribution"
    assert phase["calls"] == 1 and phase["active"] == 0 and phase["peak_active"] == 1
    assert phase["total_ns"] == phase["max_ns"] == 123_456_789
    assert "rce_jobs=1" in during[0] and "rce_jobs=0" in observer.progress_line()
    assert any("phase=rce_probe calls=1" in line and "service_ms=123.457" in line for line in observer.debug_lines())
    saved = output.read_text()
    assert "\x1b" not in saved
    assert [json.loads(line)["rce"] for line in saved.splitlines() if line.strip()] == [record["rce"]]


def test_probe_without_debug_keeps_single_call_and_no_observer():
    calls = []

    def detect(ctx):
        return AuditRecord(host=ctx.host, port=ctx.port, module="test", service="test", status="open_no_auth")

    def probe(ctx, record):
        calls.append(ctx.host)
        return replace(record, extra={"rce": False})

    runner = AuditCommandRunner(
        args=SimpleNamespace(debug=False),
        spec=ModuleAuditSpec(
            module="test",
            label="TEST",
            default_port=9,
            detect=detect,
            rce_probe=probe,
            render=lambda _: (),
            is_detected=lambda record: record.status == "open_no_auth",
        ),
        emit_line=lambda _: None,
    )
    result = runner.run_plan(AuditCommandPlan(targets_by_port={9: ("local-test",)}, ports=(9,), workers=1))
    assert runner._runtime_stats is None and calls == ["local-test"]
    assert result.records[0]["rce"] is False


def test_async_pipeline_attributes_concurrent_probe_workers_and_releases_them():
    observer = RuntimeDiagnostics()
    full, release = threading.Event(), threading.Event()
    lock = threading.Lock()
    calls, results, failures = [], [], []
    active = [0]

    def detect(ctx):
        return AuditRecord(host=ctx.host, port=ctx.port, module="test", service="test", status="open_no_auth")

    async def native(ctx, http):
        return detect(ctx)

    def probe(ctx, record):
        with lock:
            active[0] += 1
            calls.append(ctx.host)
            if active[0] == 4:
                full.set()
        try:
            assert release.wait(5), "test did not release blocked probe workers"
            return replace(record, extra={**record.extra, "rce": False})
        finally:
            with lock:
                active[0] -= 1

    args = SimpleNamespace(
        debug=False, timeout=1, retries=0, _runtime_observer=observer, _async_detect_concurrency=8, inflight=16
    )
    spec = ModuleAuditSpec(
        module="test",
        label="TEST",
        default_port=9,
        detect=detect,
        detect_async=native,
        async_detect_sync_hook=detect,
        rce_probe=probe,
        render=lambda _: (),
        is_detected=lambda record: record.status == "open_no_auth",
    )
    runner = AuditCommandRunner(args=args, spec=spec, emit_line=lambda _: None)
    hosts = tuple(f"127.32.0.{i}" for i in range(1, 41))

    def run():
        try:
            results.append(runner.run_plan(AuditCommandPlan(targets_by_port={9: hosts}, ports=(9,), workers=4)))
        except BaseException as exc:
            failures.append(exc)

    worker = threading.Thread(target=run)
    worker.start()
    try:
        assert full.wait(5), "native pipeline did not start all four probe workers"
        assert "rce_jobs=4" in observer.progress_line()
        assert observer.snapshot()["phases"]["rce_probe"]["active"] == 4
    finally:
        release.set()
        worker.join(10)
    assert not worker.is_alive() and failures == []
    assert set(calls) == set(hosts) and len(calls) == 40
    assert len(results) == 1 and {r["host"] for r in results[0].records} == set(hosts)
    phase = observer.snapshot()["phases"]["rce_probe"]
    assert phase["calls"] == 40 and phase["active"] == 0 and phase["peak_active"] == 4
    assert "rce_jobs=0" in observer.progress_line()
