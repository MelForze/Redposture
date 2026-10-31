"""Timeout recovery must not serialize native PostgreSQL discovery on deep workers."""

from __future__ import annotations

import asyncio
import threading
from types import SimpleNamespace

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.stage_runtime import AuditCommandPlan, AuditCommandRunner, ModuleAuditSpec


@pytest.mark.parametrize("succeeds_on,expected", [(1, [5]), (2, [5, 5]), (3, [5, 5, 7]), (4, [5, 5, 7])])
def test_postgres_timeout_recovery_stays_native_with_original_attempt_budgets(succeeds_on, expected):
    calls = {}
    states = []
    closed = []
    downstream = []
    args = SimpleNamespace(timeout=5, retries=0, debug=False)

    def factory(ctx):
        state = object()
        states.append(state)
        return state

    def legacy(ctx):
        pytest.fail("supported native timeout was serialized on a synchronous worker")

    async def native(ctx, http):
        assert threading.current_thread().name == "redposture-async-detect"
        seen = calls.setdefault(ctx.host, [])
        seen.append((ctx.args.timeout, http.timeout))
        await asyncio.sleep(0.001)
        success = len(seen) == succeeds_on
        return AuditRecord(
            host=ctx.host,
            port=5432,
            module="postgres",
            service="postgres",
            status="open_no_auth" if success else "fail",
            extra={"is_postgres": success, "error": None if success else "connection timed out"},
        )

    def capabilities(ctx, record):
        downstream.append((ctx.args.timeout, ctx.args is args, threading.current_thread().name))
        return record

    spec = ModuleAuditSpec(
        module="postgres",
        label="POSTGRES",
        default_port=5432,
        detect=legacy,
        detect_async=native,
        async_detect_sync_hook=legacy,
        is_detected=lambda record: record.extra.get("is_postgres") is True,
        capabilities=capabilities,
        lifecycle_state_factory=factory,
        lifecycle_state_close=closed.append,
    )
    result = AuditCommandRunner(args=args, spec=spec, emit_line=lambda _: None).run_plan(
        AuditCommandPlan(
            targets_by_port={5432: tuple(str(i) for i in range(40))}, ports=(5432,), workers=2, output_format="json"
        )
    )
    assert result.record_count == 40
    assert result.detected_count == (40 if succeeds_on <= 3 else 0)
    assert len(calls) == 40 and all(seen == [(value, value) for value in expected] for seen in calls.values())
    assert args.timeout == 5
    assert len(states) == len(closed) == 40 * len(expected) and set(states) == set(closed)
    assert all(
        timeout == 5 and original and name.startswith("redposture-scheduler-") for timeout, original, name in downstream
    )
    assert len(downstream) == (40 if succeeds_on <= 3 else 0)
    for record in result.records:
        trace = record["stages"][0]
        assert trace["stage_name"] == "detect_protocol"
        assert trace["attempt"] == len(expected)
        assert trace["duration_ms"] >= len(expected)


@pytest.mark.parametrize(
    "timeout,status,error",
    [(5, "not_service", "connection refused"), (7, "fail", "timed out"), (10, "fail", "timed out")],
)
def test_definite_negatives_and_longer_user_timeouts_are_not_retried(timeout, status, error):
    calls = []

    async def native(ctx, http):
        calls.append(ctx.args.timeout)
        return AuditRecord(
            host=ctx.host, port=5432, module="postgres", service="postgres", status=status, extra={"error": error}
        )

    args = SimpleNamespace(timeout=timeout, retries=0)
    runner = AuditCommandRunner(
        args=args,
        spec=ModuleAuditSpec(
            module="postgres",
            label="POSTGRES",
            default_port=5432,
            detect=lambda ctx: pytest.fail("unexpected sync detect"),
            detect_async=native,
        ),
    )
    result = asyncio.run(runner._run_async_detect_with_state("host", 5432, None, None))
    assert result is not None and result.record.status == status
    assert calls == [timeout] and args.timeout == timeout


def test_cancel_during_native_retry_closes_fresh_state_and_stops_attempts():
    created, closed, calls = [], [], []

    def factory(ctx):
        state = object()
        created.append(state)
        return state

    async def run():
        retry_entered = asyncio.Event()

        async def native(ctx, http):
            calls.append(ctx.args.timeout)
            if len(calls) == 1:
                return AuditRecord(
                    host=ctx.host,
                    port=5432,
                    module="postgres",
                    service="postgres",
                    status="fail",
                    extra={"error": "timed out"},
                )
            retry_entered.set()
            await asyncio.Future()

        args = SimpleNamespace(timeout=5, retries=0)
        runner = AuditCommandRunner(
            args=args,
            spec=ModuleAuditSpec(
                module="postgres",
                label="POSTGRES",
                default_port=5432,
                detect=lambda ctx: pytest.fail("unexpected sync detect"),
                detect_async=native,
                lifecycle_state_factory=factory,
                lifecycle_state_close=closed.append,
            ),
        )
        task = asyncio.create_task(runner._run_async_detect_with_state("host", 5432, None, None))
        try:
            await asyncio.wait_for(retry_entered.wait(), 1)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        finally:
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
        assert args.timeout == 5

    asyncio.run(run())
    assert calls == [5, 5]
    assert len(created) == len(closed) == 2 and set(created) == set(closed)


def test_other_modules_keep_sync_timeout_handoff():
    calls = []

    async def native(ctx, http):
        calls.append(ctx.args.timeout)
        return AuditRecord(
            host=ctx.host, port=9999, module="probe", service="probe", status="fail", extra={"error": "timed out"}
        )

    runner = AuditCommandRunner(
        args=SimpleNamespace(timeout=5, retries=0),
        spec=ModuleAuditSpec(
            module="probe",
            label="PROBE",
            default_port=9999,
            detect=lambda ctx: pytest.fail("unexpected sync detect"),
            detect_async=native,
        ),
    )
    assert asyncio.run(runner._run_async_detect_with_state("host", 9999, None, None)) is None
    assert calls == [5]
