"""PostgreSQL host pacing is preserved while unrelated hosts use the worker."""

from __future__ import annotations

import asyncio
import threading
import time
from contextlib import contextmanager
from dataclasses import replace

import pytest

from redposture_core import async_detection
from redposture_core.audit_models import AuditRecord
from redposture_core.cli_args import parse_args
from redposture_core.modules.postgres import stage
from redposture_core.scheduler import run_paused_sync
from redposture_core.stage_runtime import AuditCommandPlan, AuditCommandRunner, AuditCredentialRun


@pytest.mark.parametrize("engine", ["sync", "async"])
@pytest.mark.parametrize("skipped_ledger", [False, True])
def test_unrelated_host_progresses_during_pacing_without_losing_any_credential(monkeypatch, engine, skipped_ledger):
    args = parse_args(
        ["postgres", "-t", "127.0.0.1:5432", "--defcreds", "--workers", "1", "--no-color", "--format", "json"]
    )
    stage._normalize_postgres_action_args(args)
    args._disable_async_detection = engine == "sync"
    args._async_detect_concurrency = 4
    args._postgres_credential_coordinator = stage._PostgresCredentialCoordinator(uniform=lambda low, high: low)
    calls = []

    def detect(ctx):
        return AuditRecord.from_mapping(
            {
                "host": ctx.host,
                "port": ctx.port,
                "service": "postgres",
                "module": "postgres",
                "is_postgres": True,
                "status": "auth_required",
                "auth_required": True,
            },
            module="postgres",
            service="postgres",
        )

    async def native_detect(ctx, http):
        await asyncio.sleep(0)
        return detect(ctx)

    def probe(ctx):
        calls.append((ctx.host, ctx.credential.password))
        assert stage._POSTGRES_CREDENTIAL_SLOT.get().host_key == ctx.host
        return AuditRecord.from_mapping(
            {
                **detect(ctx).to_dict(),
                "credential_verified": False,
                "credential_verification": "rejected",
                "sqlstate": "28P01",
                "error_kind": "authentication_failed",
                "error": "password authentication failed",
                "provided_credentials": True,
                "provided_username": ctx.credential.username,
                "provided_password": ctx.credential.password,
            },
            module="postgres",
            service="postgres",
        )

    monkeypatch.setattr(stage, "_postgres_probe_credential", probe)
    spec = replace(
        stage.build_postgres_spec(args),
        detect=detect,
        detect_async=native_detect,
        async_detect_sync_hook=detect,
        record_skipped_credential_attempts=skipped_ledger,
    )
    hosts = tuple(f"127.0.0.{i + 1}" for i in range(34 if engine == "async" else 2))
    runner = AuditCommandRunner(args=args, spec=spec, emit_line=lambda line: None)
    result = runner.run_plan(
        AuditCommandPlan(
            targets_by_port={5432: hosts},
            workers=1,
            output_format="json",
            credential_runs=(
                AuditCredentialRun(username="reader", password="one", source="default"),
                AuditCredentialRun(username="reader", password="two", source="default"),
            ),
        )
    )
    assert result.record_count == result.detected_count == len(hosts)
    assert sorted(calls) == sorted((host, password) for host in hosts for password in ("one", "two"))
    assert calls[0][0] != calls[1][0]
    for record in result.records:
        payload = record if isinstance(record, dict) else record.to_dict()
        assert [row["password"] for row in payload["attempted_credentials"]] == ["one", "two"]
        assert all(row["credential_verification"] == "rejected" for row in payload["attempted_credentials"])
    assert stage._POSTGRES_CREDENTIAL_SLOT.get() is None
    assert not runner._active_credential_ledgers and not runner._completed_credential_ledgers


def test_fifo_slot_cancel_keeps_normalized_host_serial_and_preserves_overload_delay():
    now = [0.0]
    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        now[0] += seconds

    coordinator = stage._PostgresCredentialCoordinator(
        monotonic=lambda: now[0], sleep=sleep, uniform=lambda low, high: low
    )
    first = coordinator.admission("DB.EXAMPLE.")
    run_paused_sync(first.steps(), sleep=sleep)
    second = coordinator.admission("db.example")
    third = coordinator.admission("Db.Example")
    assert not second.granted.done() and not third.granted.done()
    second.close()
    assert second.granted.cancelled()
    overloaded = AuditRecord.from_mapping(
        {"status": "fail", "sqlstate": "53300"}, module="postgres", service="postgres"
    )
    assert coordinator.observe("db.example", overloaded) == 0.5
    first.close()
    assert third.granted.done()
    run_paused_sync(third.steps(), sleep=sleep)
    assert sleeps == [0.5] and third.wait_seconds == 0.5
    third.close()
    assert third.state.owner is None and not third.state.waiters


def test_cancel_before_paced_probe_does_not_advance_last_finished_or_block_followers():
    coordinator = stage._PostgresCredentialCoordinator(monotonic=lambda: 0, uniform=lambda low, high: low)
    first = coordinator.admission("127.0.0.1")
    run_paused_sync(first.steps())
    first.close()
    second = coordinator.admission("127.0.0.1")
    waiting = second.steps()
    assert next(waiting) == 0.1
    third = coordinator.admission("127.0.0.1")
    waiting.close()
    second.close()
    assert third.state.last_finished_at == 0 and third.granted.done()
    third_steps = third.steps()
    assert next(third_steps) == 0.1
    third_steps.close()
    third.close()
    assert third.state.owner is None and not third.state.waiters


@pytest.mark.parametrize("skipped_ledger", [False, True])
def test_fatal_auth_error_survives_delayed_delivery_from_the_finish_worker(monkeypatch, skipped_ledger):
    """A failure-ledger flag must not turn a programming error into normal cancellation."""
    args = parse_args(["postgres", "-t", "127.0.0.1:5432", "-u", "reader", "-p", "bad", "--no-color"])
    stage._normalize_postgres_action_args(args)
    args._async_detect_concurrency = 4
    args._postgres_credential_coordinator = stage._PostgresCredentialCoordinator()

    def detect(ctx):
        return AuditRecord.from_mapping(
            {"host": ctx.host, "port": ctx.port, "is_postgres": True, "status": "auth_required"},
            module="postgres",
            service="postgres",
        )

    async def native_detect(ctx, http):
        return detect(ctx)

    def probe(ctx):
        raise TypeError("credential hook contract violation")

    original_pool = async_detection._PausedWorkerPool

    def delayed_pool(**options):
        worker = options["worker"]

        def delayed(pair):
            try:
                return (yield from worker(pair))
            except TypeError:
                # Model a scheduling gap between the worker's error and its
                # delivery. An internal ledger flag is not an operator cancel.
                time.sleep(0.05)
                raise

        return original_pool(**{**options, "worker": delayed})

    monkeypatch.setattr(async_detection, "_PausedWorkerPool", delayed_pool)
    monkeypatch.setattr(stage, "_postgres_probe_credential", probe)
    spec = replace(
        stage.build_postgres_spec(args),
        detect=detect,
        detect_async=native_detect,
        async_detect_sync_hook=detect,
        record_skipped_credential_attempts=skipped_ledger,
    )
    runner = AuditCommandRunner(args=args, spec=spec, emit_line=lambda line: None)
    with pytest.raises(TypeError, match="credential hook contract violation"):
        runner.run_plan(
            AuditCommandPlan(
                targets_by_port={5432: tuple(f"127.0.0.{i + 1}" for i in range(32))},
                workers=1,
                credential_runs=(AuditCredentialRun(username="reader", password="bad", source="provided"),),
            )
        )


def test_same_host_ports_remain_serial_and_paced_while_different_hosts_overlap(monkeypatch):
    args = parse_args(["postgres", "-t", "127.0.0.1:5432", "--defcreds", "--no-color", "--format", "json"])
    stage._normalize_postgres_action_args(args)
    args._disable_async_detection = True
    args._postgres_credential_coordinator = stage._PostgresCredentialCoordinator(uniform=lambda low, high: low)
    entered, lock = threading.Event(), threading.Lock()
    active, last_finished, calls, seen = {}, {}, [], set()

    def detect(ctx):
        return AuditRecord.from_mapping(
            {"host": ctx.host, "port": ctx.port, "is_postgres": True, "status": "auth_required"},
            module="postgres",
            service="postgres",
        )

    def probe(ctx):
        with lock:
            assert not active.get(ctx.host)
            if ctx.host in last_finished:
                assert time.monotonic() - last_finished[ctx.host] >= 0.10
            active[ctx.host] = True
            seen.add(ctx.host)
            if len(seen) == 2:
                entered.set()
        try:
            assert entered.wait(2), "one host blocked a worker needed by another host"
            return AuditRecord.from_mapping(
                {**detect(ctx).to_dict(), "credential_verified": False, "credential_verification": "rejected"},
                module="postgres",
                service="postgres",
            )
        finally:
            with lock:
                calls.append((ctx.host, ctx.port, ctx.credential.password))
                last_finished[ctx.host] = time.monotonic()
                active[ctx.host] = False

    monkeypatch.setattr(stage, "_postgres_probe_credential", probe)
    spec = replace(stage.build_postgres_spec(args), detect=detect)
    runner = AuditCommandRunner(args=args, spec=spec, emit_line=lambda line: None)
    hosts = ("127.0.0.1", "127.0.0.2")
    result = runner.run_plan(
        AuditCommandPlan(
            targets_by_port={5432: hosts, 6432: hosts},
            workers=4,
            output_format="json",
            credential_runs=tuple(
                AuditCredentialRun(username="reader", password=p, source="default") for p in ("a", "b")
            ),
        )
    )
    assert result.record_count == result.detected_count == 4
    assert sorted(calls) == sorted((h, port, p) for h in hosts for port in (5432, 6432) for p in ("a", "b"))
    assert not any(active.values())
    assert all(s.owner is None and not s.waiters for s in args._postgres_credential_coordinator._states.values())


def test_operator_interrupt_releases_parked_admissions_and_all_prepared_lifecycles(monkeypatch):
    args = parse_args(["postgres", "-t", "127.0.0.1:5432", "-u", "reader", "-p", "bad", "--no-color"])
    stage._normalize_postgres_action_args(args)
    args._async_detect_concurrency = 4
    coordinator = args._postgres_credential_coordinator = stage._PostgresCredentialCoordinator()
    hosts = tuple(f"127.0.0.{i + 1}" for i in range(32))
    for host in hosts:
        coordinator._state(host).cooldown_until = time.monotonic() + 60
    parked, cleanup_done = threading.Event(), threading.Event()
    created, closed, probes = [], [], []
    original_pool = async_detection._PausedWorkerPool

    class InterruptingResults:
        def __init__(self, queue):
            self.queue = queue

        def put(self, value):
            self.queue.put(value)

        def get(self):
            assert parked.wait(2)
            raise KeyboardInterrupt

    def interrupted_pool(**options):
        pool = original_pool(**options)
        monkeypatch.setattr(pool, "results", InterruptingResults(pool.results))
        original_cancel = pool.cancel

        def cancel():
            original_cancel()
            pool._thread.join(2)
            cleanup_done.set()

        monkeypatch.setattr(pool, "cancel", cancel)
        return pool

    def detect(ctx):
        return AuditRecord.from_mapping(
            {"host": ctx.host, "port": ctx.port, "is_postgres": True, "status": "auth_required"},
            module="postgres",
            service="postgres",
        )

    async def native_detect(ctx, http):
        return detect(ctx)

    @contextmanager
    def wait(ctx, record):
        with stage._postgres_auth_wait(ctx, record) as pauses:

            def steps():
                for pause in pauses:
                    parked.set()
                    yield pause

            yield steps()

    original_spec = stage.build_postgres_spec(args)
    state_factory, state_close = original_spec.lifecycle_state_factory, original_spec.lifecycle_state_close
    assert state_factory is not None and state_close is not None

    def make_state(ctx):
        state = state_factory(ctx)
        created.append(state)
        return state

    def close_state(state):
        closed.append(state)
        state_close(state)

    monkeypatch.setattr(async_detection, "_PausedWorkerPool", interrupted_pool)
    monkeypatch.setattr(stage, "_postgres_probe_credential", lambda ctx: probes.append(ctx.host))
    spec = replace(
        original_spec,
        detect=detect,
        detect_async=native_detect,
        async_detect_sync_hook=detect,
        auth_wait=wait,
        lifecycle_state_factory=make_state,
        lifecycle_state_close=close_state,
    )
    runner = AuditCommandRunner(args=args, spec=spec, emit_line=lambda line: None)
    with pytest.raises(KeyboardInterrupt):
        runner.run_plan(
            AuditCommandPlan(
                targets_by_port={5432: hosts},
                workers=1,
                credential_runs=(AuditCredentialRun(username="reader", password="bad", source="provided"),),
            )
        )
    assert cleanup_done.wait(2) and created and not probes
    assert sorted(map(id, closed)) == sorted(map(id, created))
    assert all(state.owner is None and not state.waiters for state in coordinator._states.values())
    assert stage._POSTGRES_CREDENTIAL_SLOT.get() is None
