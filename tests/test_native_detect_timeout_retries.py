"""Native protocol timeout recovery must preserve proof, ownership and sync data."""

from __future__ import annotations

import asyncio
import importlib
from dataclasses import replace

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.clients.async_http_detect import AsyncDetectionHttp, AsyncHttpFallback
from redposture_core.clients.async_retained_socket import RetainedSocketIO
from redposture_core.stage_runtime import AuditCommandRunner
from redposture_core.targeting import ScanTargetSpec

MODULES = ("redis", "zookeeper", "grpc", "clickhouse", "kafka", "keeper", "mongodb")


def make_runner(module, *, retries=0, timeout=5):
    stage = importlib.import_module(f"redposture_core.modules.{module}.stage")
    args = parse_args([module, "-t", "127.0.0.1:9999", "--timeout", str(timeout), "--retries", str(retries)])
    spec = getattr(stage, f"build_{module}_spec")(args)
    return args, spec


@pytest.mark.parametrize("module", MODULES)
@pytest.mark.parametrize("retries", [0, 1])
@pytest.mark.parametrize("recovers_on,expected", [(2, [5, 5]), (3, [5, 5, 7]), (4, [5, 5, 7])])
def test_real_protocol_adapter_timeout_recovery_stays_native(module, retries, recovers_on, expected, monkeypatch):
    from redposture_core.modules.mongodb import async_detect as mongo

    args, spec = make_runner(module, retries=retries)
    attempts, requests, states, closed = [], [], [], []
    original_sleep = asyncio.sleep

    async def skip_backoff(*a, **kw):
        return await original_sleep(0)

    monkeypatch.setattr(asyncio, "sleep", skip_backoff)
    original = spec.detect_async

    async def native(ctx, http):
        attempts.append(ctx.args.timeout)
        states.append(ctx.lifecycle_state)
        return await original(ctx, http)

    def close(state):
        closed.append(state)
        spec.lifecycle_state_close(state)

    def fail(kind, address):
        requests.append((len(attempts), kind, address))
        if len(attempts) < recovers_on:
            raise TimeoutError("timed out")
        raise ConnectionRefusedError("connection refused")

    async def raw(self, address, *a, **kw):
        return fail("raw", address)

    async def http(self, url, *a, **kw):
        return fail("http", url)

    def client(host, port, **kw):
        return fail("mongodb", (host, port))

    monkeypatch.setattr(RetainedSocketIO, "open", raw)
    monkeypatch.setattr(AsyncDetectionHttp, "_once", http)
    monkeypatch.setattr(mongo, "open_client", client)
    runner = AuditCommandRunner(args=args, spec=replace(spec, detect_async=native, lifecycle_state_close=close))
    target = ScanTargetSpec(host="127.0.0.1", explicit_port=spec.default_port)
    try:
        result = asyncio.run(runner._run_async_detect_with_state(target.host, spec.default_port, target, None))
        assert result is not None, "supported timeout unexpectedly handed to sync workers"
        assert not runner._is_detected(result.record)
        assert attempts == expected
        assert args.timeout == 5 and args.retries == retries
        if recovers_on > 2:
            assert [(kind, address) for n, kind, address in requests if n == 1] == [
                (kind, address) for n, kind, address in requests if n == 2
            ]
    finally:
        runner._close_all_lifecycle_states()
    if spec.lifecycle_state_factory is not None:
        assert len(states) == len(closed) == len(expected)
        assert len({id(state) for state in states}) == len(states)


@pytest.mark.parametrize("module", MODULES)
def test_real_protocol_compatibility_fallback_does_not_retry(module, monkeypatch):
    from redposture_core.modules.mongodb import async_detect as mongo

    args, spec = make_runner(module)
    calls = []

    async def raw(self, *a, **kw):
        calls.append("raw")
        raise AsyncHttpFallback("unsupported platform or framing")

    def client(*a, **kw):
        calls.append("mongo")
        raise AsyncHttpFallback("installed driver has no native async client")

    monkeypatch.setattr(RetainedSocketIO, "open", raw)
    monkeypatch.setattr(mongo, "open_client", client)
    runner = AuditCommandRunner(args=args, spec=spec)
    try:
        assert asyncio.run(runner._run_async_detect_with_state("127.0.0.1", spec.default_port, None, None)) is None
        assert len(calls) == 1
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


async def recover_real_protocol(spec, ctx, monkeypatch):
    """Real final wire scan after two failed native attempts; return adopted state."""
    attempts, final_records, discarded = [], [], []
    original_detect = spec.detect_async
    original_open = RetainedSocketIO.open
    original_http = AsyncDetectionHttp._once

    async def tracked(context, http):
        attempts.append(context.args.timeout)
        record = await original_detect(context, http)
        final_records.append(record)
        return record

    async def raw(self, *a, **kw):
        if len(attempts) < 3:
            raise TimeoutError("timed out")
        return await original_open(self, *a, **kw)

    async def http(self, *a, **kw):
        if len(attempts) < 3:
            raise TimeoutError("timed out")
        return await original_http(self, *a, **kw)

    def close(state):
        discarded.append(state)
        spec.lifecycle_state_close(state)

    monkeypatch.setattr(RetainedSocketIO, "open", raw)
    monkeypatch.setattr(AsyncDetectionHttp, "_once", http)
    runner = AuditCommandRunner(args=ctx.args, spec=replace(spec, detect_async=tracked, lifecycle_state_close=close))
    # Caller owns the returned live state, matching the ordinary runtime handoff.
    spec.lifecycle_state_close(ctx.lifecycle_state)
    try:
        debug = []
        outcome = await runner._run_async_detect_with_state(ctx.host, ctx.port, ctx.target, debug.append)
        assert outcome is not None and runner._is_detected(outcome.record), debug
        assert attempts == [ctx.args.timeout, ctx.args.timeout, 7.0]
        assert len(discarded) == 2
        return final_records[-1], replace(ctx, lifecycle_state=outcome.lifecycle_state)
    except BaseException:
        runner._close_all_lifecycle_states()
        raise


@pytest.mark.parametrize("verdict", ["open", "auth_required", "foreign", "cancel"])
def test_mongodb_sdk_timeout_recovery_closes_every_client(verdict, monkeypatch):
    from redposture_core.modules.mongodb import async_detect as mongo

    args, spec = make_runner("mongodb")
    opened, closed, calls = [], [], []
    retry_entered = None

    class Client:
        def __init__(self, index):
            self.index = index

        async def hello(self):
            calls.append((self.index, "hello"))
            if self.index < 3:
                if verdict == "cancel" and self.index == 2:
                    retry_entered.set()
                    await asyncio.Future()
                raise TimeoutError("timed out")
            if verdict == "foreign":
                raise mongo.client_helpers.MongoNotMongoError("hello response is not MongoDB-like")
            return {"ok": 1, "minWireVersion": 0, "maxWireVersion": 17, "isWritablePrimary": True}

        async def server_info(self):
            calls.append((self.index, "buildInfo"))
            return {"version": "7.0.1"}

        async def list_database_names(self):
            calls.append((self.index, "listDatabases"))
            if verdict == "auth_required":
                raise RuntimeError("not authorized")
            return ["admin", "app"]

        async def close(self):
            closed.append(self.index)

    def open_client(host, port, **kw):
        opened.append(kw["timeout"])
        return Client(len(opened))

    monkeypatch.setattr(mongo, "open_client", open_client)
    runner = AuditCommandRunner(args=args, spec=spec)

    async def run():
        nonlocal retry_entered
        retry_entered = asyncio.Event()
        task = asyncio.create_task(runner._run_async_detect_with_state("127.0.0.1", 27017, None, None))
        try:
            if verdict == "cancel":
                await asyncio.wait_for(retry_entered.wait(), 1)
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
            else:
                result = await task
                assert result is not None
                assert runner._is_detected(result.record) is (verdict != "foreign")
                if verdict != "foreign":
                    assert result.record.status == ("auth_required" if verdict == "auth_required" else "open_no_auth")
                    assert result.record.extra["server_version"] == "7.0.1"
        finally:
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            runner._close_all_lifecycle_states()

    asyncio.run(run())
    assert opened == ([5, 5] if verdict == "cancel" else [5, 5, 7])
    assert closed == list(range(1, len(opened) + 1))
    assert calls[:2] == [(1, "hello"), (2, "hello")]
    if verdict in {"open", "auth_required"}:
        assert calls[2:] == [(3, "hello"), (3, "buildInfo"), (3, "listDatabases")]


def test_clickhouse_explicit_http_preserves_driver_transport_retry_policy(monkeypatch):
    from redposture_core.modules.clickhouse.stage import build_clickhouse_spec

    args, _ = make_runner("clickhouse")
    args.protocol = "http"
    spec = build_clickhouse_spec(args)
    calls, debug = [], []

    async def raw(self, address, *a, **kw):
        calls.append(address)
        raise TimeoutError("timed out")

    monkeypatch.setattr(RetainedSocketIO, "open", raw)
    runner = AuditCommandRunner(args=args, spec=spec)
    try:
        assert asyncio.run(runner._run_async_detect_with_state("127.0.0.1", 8123, None, debug.append)) is None
        assert calls == [("127.0.0.1", 8123)]
        assert any("original retry policy" in line for line in debug)
    finally:
        runner._close_all_lifecycle_states()


@pytest.mark.parametrize("recover", [False, True])
@pytest.mark.parametrize("authorized", [False, True])
def test_mongodb_recovery_uses_real_async_driver_and_complete_wire_proof(recover, authorized, monkeypatch):
    import socketserver
    import struct
    import threading

    from bson import BSON

    from redposture_core.clients.async_mongodb_detect import AsyncMongoDetectClient

    requests, failures, connections = [], [], set()
    lock = threading.Lock()

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    class Handler(socketserver.BaseRequestHandler):
        def read(self, size):
            data = bytearray()
            while len(data) < size:
                part = self.request.recv(size - len(data))
                if not part:
                    return None
                data.extend(part)
            return bytes(data)

        def handle(self):
            with lock:
                connections.add(self.request)
            try:
                self.request.settimeout(2)
                while True:
                    header = self.read(16)
                    if header is None:
                        break
                    length, request_id, _, opcode = struct.unpack("<iiii", header)
                    assert 16 <= length <= 1_048_576
                    body = self.read(length - 16)
                    if body is None:
                        break
                    if opcode == 2004:
                        offset = body.index(b"\0", 4) + 9
                    else:
                        assert opcode == 2013 and body[4] == 0
                        offset = 5
                    size = struct.unpack("<i", body[offset : offset + 4])[0]
                    document = BSON(body[offset : offset + size]).decode()
                    command = next(iter(document)).lower()
                    with lock:
                        requests.append(command)
                    reply: dict[str, object]
                    if command in {"hello", "ismaster"}:
                        reply = {
                            "ok": 1,
                            "ismaster": True,
                            "isWritablePrimary": True,
                            "minWireVersion": 0,
                            "maxWireVersion": 17,
                            "maxBsonObjectSize": 16_777_216,
                            "maxMessageSizeBytes": 48_000_000,
                            "maxWriteBatchSize": 100_000,
                        }
                    elif command == "buildinfo":
                        reply = {"ok": 1, "version": "7.0.1"}
                    elif command == "listdatabases":
                        reply = (
                            {"ok": 1, "databases": [{"name": "admin"}, {"name": "app"}]}
                            if authorized
                            else {"ok": 0, "code": 13, "codeName": "Unauthorized", "errmsg": "not authorized"}
                        )
                    else:
                        raise AssertionError(f"unexpected command: {command}")
                    encoded = BSON.encode(reply)
                    payload = struct.pack("<iqii", 0, 0, 0, 1) + encoded if opcode == 2004 else bytes(5) + encoded
                    self.request.sendall(
                        struct.pack("<iiii", 16 + len(payload), 1, request_id, 1 if opcode == 2004 else 2013) + payload
                    )
            except (ConnectionError, TimeoutError):
                pass
            except BaseException as exc:
                failures.append(exc)
            finally:
                with lock:
                    connections.discard(self.request)

    server = Server(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
    thread.start()
    args, spec = make_runner("mongodb")
    runner = AuditCommandRunner(args=args, spec=spec)
    hello, close = AsyncMongoDetectClient.hello, AsyncMongoDetectClient.close
    attempts, closed = [], []

    async def tracked_hello(self):
        attempts.append(self)
        if recover and len(attempts) < 3:
            raise TimeoutError("timed out")
        return await hello(self)

    async def tracked_close(self):
        closed.append(self)
        await close(self)

    monkeypatch.setattr(AsyncMongoDetectClient, "hello", tracked_hello)
    monkeypatch.setattr(AsyncMongoDetectClient, "close", tracked_close)
    try:
        result = asyncio.run(runner._run_async_detect_with_state("127.0.0.1", server.server_address[1], None, None))
        assert result is not None and runner._is_detected(result.record)
        assert result.record.status == ("open_no_auth" if authorized else "auth_required")
        assert result.record.auth_required is not authorized
        assert result.record.extra["server_version"] == "7.0.1"
        assert len(attempts) == (3 if recover else 1)
        assert attempts == closed
        assert "buildinfo" in requests and requests.count("listdatabases") == 1
        assert not failures
    finally:
        runner._close_all_lifecycle_states()
        server.shutdown()
        server.server_close()
        thread.join(2)
        with lock:
            remaining = list(connections)
        for connection in remaining:
            connection.close()
        assert not thread.is_alive()
