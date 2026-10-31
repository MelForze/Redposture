"""Real module adapters retain full detect attempts instead of queueing sync retries."""

from __future__ import annotations

import asyncio
import importlib
from dataclasses import replace

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.clients.async_http_detect import AsyncDetectionHttp
from redposture_core.clients.http_api import HttpResponse
from redposture_core.stage_runtime import AuditCommandRunner
from redposture_core.targeting import ScanTargetSpec

MODULES = (
    "grafana",
    "qdrant",
    "rabbitmq",
    "etcd",
    "proxmox",
    "docker-registry",
    "consul",
    "kubeapi",
    "minio",
    "elastic",
    "gitlab",
)


def make_runner(module):
    stage = importlib.import_module(f"redposture_core.modules.{module.replace('-', '_')}.stage")
    args = parse_args([module, "-t", "127.0.0.1:9999", "--timeout", "5", "--retries", "0", "--no-color"])
    spec = getattr(stage, f"build_{module.replace('-', '_')}_spec")(args)
    return args, spec


@pytest.mark.parametrize("module", MODULES)
@pytest.mark.parametrize("recovers_on,expected", [(2, [5, 5]), (3, [5, 5, 7]), (4, [5, 5, 7])])
def test_real_adapter_timeout_recovery_keeps_native_attempts(module, recovers_on, expected, monkeypatch):
    args, spec = make_runner(module)
    attempts = []
    requests = []
    original = spec.detect_async

    async def tracked(ctx, http):
        attempts.append(ctx.args.timeout)
        assert ctx.args.retries == 0
        return await original(ctx, http)

    async def wire(self, url, timeout, headers, **options):
        requests.append((len(attempts), url, timeout))
        if len(attempts) < recovers_on:
            raise TimeoutError("timed out")
        return HttpResponse(404, b'{"ordinary":"unrelated service"}', {}, request_url=url, final_url=url)

    monkeypatch.setattr(AsyncDetectionHttp, "_once", wire)
    runner = AuditCommandRunner(args=args, spec=replace(spec, detect_async=tracked), emit_line=lambda _: None)
    target = ScanTargetSpec(host="127.0.0.1", explicit_port=spec.default_port)
    try:
        outcome = asyncio.run(runner._run_async_detect_with_state(target.host, spec.default_port, target, None))
        assert outcome is not None, "supported timeout incorrectly handed to sync workers"
        assert not runner._is_detected(outcome.record)
        assert attempts == expected
        assert args.timeout == 5 and args.retries == 0
        if recovers_on > 2:
            assert [url for attempt, url, _ in requests if attempt == 1] == [
                url for attempt, url, _ in requests if attempt == 2
            ]
        assert set(attempt for attempt, _, _ in requests) == set(range(1, len(expected) + 1))
    finally:
        runner._close_all_lifecycle_states()


@pytest.mark.parametrize("module", MODULES)
def test_actual_http_success_after_two_timeouts(module, monkeypatch):
    """Final recovery uses real HTTP framing and the unchanged product detector."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from tests.http_detect_fixtures import detection_response

    received = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_GET(self):
            received.append((self.command, self.path))
            size = int(self.headers.get("Content-Length", "0"))
            if size:
                self.rfile.read(size)
            response = detection_response(module, f"http://127.0.0.1:{server.server_port}" + self.path)
            self.send_response(response.status)
            for key, value in response.headers.items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(response.body)))
            self.end_headers()
            self.wfile.write(response.body)

        do_POST = do_GET

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
    thread.start()
    args, spec = make_runner(module)
    attempts = []
    original_wire = AsyncDetectionHttp._once

    class Runner(AuditCommandRunner):
        async def _run_async_detect_attempt(self, *a, **kw):
            attempts.append(a[4].timeout)
            return await super()._run_async_detect_attempt(*a, **kw)

    async def wire(self, *a, **kw):
        if len(attempts) < 3:
            raise TimeoutError("timed out")
        return await original_wire(self, *a, **kw)

    monkeypatch.setattr(AsyncDetectionHttp, "_once", wire)
    runner = Runner(args=args, spec=spec, emit_line=lambda _: None)
    target = ScanTargetSpec(host="127.0.0.1", explicit_port=server.server_port, scheme="http")
    try:
        outcome = asyncio.run(runner._run_async_detect_with_state(target.host, server.server_port, target, None))
        assert outcome is not None and runner._is_detected(outcome.record)
        assert attempts == [5, 5, 7]
        assert received and all(method in {"GET", "POST"} for method, _ in received)
    finally:
        runner._close_all_lifecycle_states()
        server.shutdown()
        server.server_close()
        thread.join(2)
        assert not thread.is_alive()


@pytest.mark.parametrize("module", MODULES)
def test_compatibility_fallback_is_not_retried_natively(module, monkeypatch):
    from redposture_core.clients.async_http_detect import AsyncHttpFallback

    args, spec = make_runner(module)
    calls = []

    async def incompatible(self, *a, **kw):
        calls.append(a)
        raise AsyncHttpFallback("redirect or unsupported framing")

    monkeypatch.setattr(AsyncDetectionHttp, "_once", incompatible)
    runner = AuditCommandRunner(args=args, spec=spec, emit_line=lambda _: None)
    target = ScanTargetSpec(host="127.0.0.1", explicit_port=spec.default_port)
    try:
        outcome = asyncio.run(runner._run_async_detect_with_state(target.host, spec.default_port, target, None))
        assert outcome is None and len(calls) == 1
    finally:
        runner._close_all_lifecycle_states()


@pytest.mark.parametrize("module", MODULES)
@pytest.mark.parametrize("case", ["cancel", "refused", "extended_timeout", "confirmed"])
def test_retry_policy_preserves_state_args_and_cancellation(module, case):
    from types import SimpleNamespace

    from redposture_core.audit_models import AuditRecord
    from redposture_core.stage_runtime import ModuleAuditSpec

    created, closed, timeouts = [], [], []
    args = SimpleNamespace(timeout=10 if case == "extended_timeout" else 5, retries=0)

    def factory(ctx):
        state = object()
        created.append(state)
        return state

    async def run():
        entered_retry = asyncio.Event()

        async def native(ctx, http):
            timeouts.append(ctx.args.timeout)
            if case == "cancel" and len(timeouts) > 1:
                entered_retry.set()
                await asyncio.Future()
            return AuditRecord(
                host=ctx.host,
                port=9999,
                service=module,
                module=module,
                status="open_no_auth" if case == "confirmed" else "fail",
                extra={"error": "connection refused" if case == "refused" else "timed out"},
            )

        spec = ModuleAuditSpec(
            module=module,
            label=module.upper(),
            default_port=9999,
            detect=lambda ctx: pytest.fail("unexpected sync detect"),
            detect_async=native,
            lifecycle_state_factory=factory,
            lifecycle_state_close=closed.append,
            is_detected=lambda record: record.status == "open_no_auth",
        )
        runner = AuditCommandRunner(args=args, spec=spec, emit_line=lambda _: None)
        task = asyncio.create_task(runner._run_async_detect_with_state("127.0.0.1", 9999, None, None))
        try:
            if case == "cancel":
                await asyncio.wait_for(entered_retry.wait(), 1)
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
            else:
                assert await task is not None
        finally:
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            runner._close_all_lifecycle_states()

    asyncio.run(run())
    assert timeouts == ([5, 5] if case == "cancel" else [args.timeout])
    assert len(created) == len(closed) == len(timeouts) and set(created) == set(closed)
    assert args.timeout == (10 if case == "extended_timeout" else 5)


@pytest.mark.parametrize("module", MODULES)
def test_successful_retries_keep_capabilities_and_data_on_original_sync_args(module):
    import threading
    from types import SimpleNamespace

    from redposture_core.audit_models import AuditRecord
    from redposture_core.stage_runtime import AuditCommandPlan, ModuleAuditSpec

    seen, downstream, states, closed = {}, [], [], []
    args = SimpleNamespace(timeout=5, retries=0, debug=False)

    def factory(ctx):
        state = object()
        states.append(state)
        return state

    def legacy(ctx):
        pytest.fail("supported timeout occupied a sync detect worker")

    async def native(ctx, http):
        attempts = seen.setdefault(ctx.host, [])
        attempts.append(ctx.args.timeout)
        success = len(attempts) == 3
        return AuditRecord(
            host=ctx.host,
            port=9999,
            service=module,
            module=module,
            status="open_no_auth" if success else "fail",
            extra={"error": None if success else "timed out"},
        )

    def phase(ctx, record):
        downstream.append((ctx.phase, ctx.args is args, ctx.args.timeout, threading.current_thread().name))
        return record

    spec = ModuleAuditSpec(
        module=module,
        label=module.upper(),
        default_port=9999,
        detect=legacy,
        detect_async=native,
        async_detect_sync_hook=legacy,
        capabilities=phase,
        data=phase,
        is_detected=lambda rec: rec.status == "open_no_auth",
        lifecycle_state_factory=factory,
        lifecycle_state_close=closed.append,
    )
    result = AuditCommandRunner(args=args, spec=spec, emit_line=lambda _: None).run_plan(
        AuditCommandPlan(
            targets_by_port={9999: tuple(str(i) for i in range(40))}, ports=(9999,), workers=2, output_format="json"
        )
    )
    assert result.detected_count == result.record_count == 40
    assert len(seen) == 40 and all(attempts == [5, 5, 7] for attempts in seen.values())
    assert len(downstream) == 80 and {phase for phase, *_ in downstream} == {"capabilities", "data"}
    assert all(
        original and timeout == 5 and name.startswith("redposture-scheduler-")
        for _, original, timeout, name in downstream
    )
    assert len(states) == len(closed) == 120 and set(states) == set(closed)
    assert args.timeout == 5


@pytest.mark.parametrize("module", MODULES)
def test_nonzero_request_retries_survive_native_recovery(module, monkeypatch):
    args, _ = make_runner(module)
    args.retries = 1
    stage = importlib.import_module(f"redposture_core.modules.{module.replace('-', '_')}.stage")
    spec = getattr(stage, f"build_{module.replace('-', '_')}_spec")(args)
    attempts, requests, backoffs = [], [], []
    original = spec.detect_async
    real_sleep = asyncio.sleep

    async def skip_backoff(delay, *a, **kw):
        backoffs.append(delay)
        return await real_sleep(0)

    async def native(ctx, http):
        attempts.append((ctx.args.timeout, ctx.args.retries))
        return await original(ctx, http)

    async def wire(self, url, timeout, headers, **kw):
        requests.append((len(attempts), url))
        if len(attempts) < 3:
            raise TimeoutError("timed out")
        return HttpResponse(404, b"{}", {}, request_url=url, final_url=url)

    monkeypatch.setattr(AsyncDetectionHttp, "_once", wire)
    monkeypatch.setattr(asyncio, "sleep", skip_backoff)
    runner = AuditCommandRunner(args=args, spec=replace(spec, detect_async=native), emit_line=lambda _: None)
    target = ScanTargetSpec(host="127.0.0.1", explicit_port=spec.default_port)
    try:
        outcome = asyncio.run(runner._run_async_detect_with_state(target.host, spec.default_port, target, None))
        assert outcome is not None and not runner._is_detected(outcome.record)
        assert attempts == [(5, 1), (5, 1), (7, 1)]
        assert [url for attempt, url in requests if attempt == 1] == [url for attempt, url in requests if attempt == 2]
        assert any(delay > 0 for delay in backoffs)
        assert args.retries == 1 and args.timeout == 5
    finally:
        runner._close_all_lifecycle_states()
