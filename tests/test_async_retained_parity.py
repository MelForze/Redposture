"""Real sync/native scans must preserve complete records and request order."""

from __future__ import annotations

import asyncio
import json
import socketserver
import struct
import threading
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from redposture_core.clients.async_http_detect import AsyncDetectionHttp
from redposture_core.clients.zookeeper import _decode_zk_string
from redposture_core.modules.kafka.stage import build_kafka_spec
from redposture_core.modules.keeper.stage import build_keeper_spec
from redposture_core.modules.redis.stage import build_redis_spec
from redposture_core.modules.zookeeper.stage import build_zookeeper_spec
from redposture_core.modules.zookeeper.types import ZooKeeperFingerprintCache
from redposture_core.stage_runtime import AuditCredentialRun, AuditHookContext


def normalize(value):
    if isinstance(value, dict):
        return {
            key: normalize(item)
            for key, item in value.items()
            if key not in {"timestamp", "elapsed_ms", "duration_ms", "stage_durations_ms", "stage_timing_total_ms"}
        }
    if isinstance(value, list):
        return [normalize(item) for item in value]
    return value


def framed(payload):
    return struct.pack(">i", len(payload)) + payload


def make_context(builder, port, target=None):
    args = SimpleNamespace(timeout=1.0, retries=0)
    spec = builder(args)
    ctx = AuditHookContext(
        args=args,
        logger=None,
        host="127.0.0.1",
        port=port,
        target=target,
        credential=AuditCredentialRun(),
        phase="detect",
    )
    return spec, replace(ctx, lifecycle_state=spec.lifecycle_state_factory(ctx))


class ProtocolServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


@pytest.mark.parametrize(
    "module,builder",
    [
        ("redis", build_redis_spec),
        ("kafka", build_kafka_spec),
        ("zookeeper", build_zookeeper_spec),
        ("keeper", build_keeper_spec),
    ],
)
def test_full_record_and_wire_request_parity(module, builder):
    requests = []
    lock = threading.Lock()

    class Handler(socketserver.BaseRequestHandler):
        def read(self, size):
            value = bytearray()
            while len(value) < size:
                chunk = self.request.recv(size - len(value))
                if not chunk:
                    return None
                value.extend(chunk)
            return bytes(value)

        def frame(self):
            prefix = self.read(4)
            return None if prefix is None else self.read(struct.unpack(">i", prefix)[0])

        def log(self, value):
            with lock:
                requests.append(value)

        def handle(self):
            if module == "redis":
                stream = self.request.makefile("rb")
                while True:
                    prefix = stream.readline()
                    if not prefix:
                        break
                    parts = []
                    for _ in range(int(prefix[1:])):
                        size = int(stream.readline()[1:])
                        parts.append(stream.read(size))
                        assert stream.read(2) == b"\r\n"
                    self.log(tuple(parts))
                    self.request.sendall(b"+PONG\r\n" if parts == [b"PING"] else b"$21\r\nredis_version:7.4.0\r\n\r\n")
                return
            if module == "kafka":
                while True:
                    payload = self.frame()
                    if payload is None:
                        break
                    self.log(payload)
                    api, _, correlation = struct.unpack(">hhi", payload[:8])
                    answer = (
                        struct.pack(">ihi", correlation, 0, 1) + struct.pack(">hhh", 3, 0, 0)
                        if api == 18
                        else struct.pack(">iii", correlation, 0, 0)
                    )
                    self.request.sendall(framed(answer))
                return
            prefix = self.read(4)
            if prefix is None:
                return
            if prefix in (b"srvr", b"stat", b"mntr", b"isro"):
                self.log(prefix)
                self.request.sendall(
                    (b"ClickHouse Keeper version: 25.8.1\n" if module == "keeper" else b"Zookeeper version: 3.9.2\n")
                    if prefix == b"srvr"
                    else b"zk_server_state\tleader\n"
                    if prefix == b"mntr"
                    else b"rw"
                )
                return
            hello = self.read(struct.unpack(">i", prefix)[0])
            self.log(hello)
            self.request.sendall(framed(struct.pack(">iiqi", 0, 1000, 1, 16) + bytes(16)))
            while True:
                payload = self.frame()
                if payload is None:
                    break
                xid, opcode = struct.unpack(">ii", payload[:8])
                # Cleanup can arrive after the scan result; compare detection
                # requests and retain its independent real-socket tests above.
                if opcode == -11:
                    break
                self.log(payload)
                path, _ = _decode_zk_string(payload, 8)
                err = -101 if path == "/clickhouse/task_queue/ddl" else 0
                self.request.sendall(
                    framed(struct.pack(">iqi", xid, 0, err) + (struct.pack(">i", 0) + bytes(68) if err == 0 else b""))
                )

    server = ProtocolServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        spec, ctx = make_context(builder, server.server_address[1])
        if module in {"zookeeper", "keeper"}:
            ctx.lifecycle_state.requested_config = replace(ctx.lifecycle_state.requested_config, mode="plaintext")
        sync = spec.detect(ctx).to_dict()
        spec.lifecycle_state_close(ctx.lifecycle_state)
        with lock:
            sync_requests = requests[:]
            requests.clear()

        async def native():
            spec, ctx = make_context(builder, server.server_address[1])
            if module in {"zookeeper", "keeper"}:
                ctx.lifecycle_state.requested_config = replace(ctx.lifecycle_state.requested_config, mode="plaintext")
            record = await spec.detect_async(ctx, None)
            spec.lifecycle_state_close(ctx.lifecycle_state)
            return record.to_dict()

        actual = asyncio.run(native())
        with lock:
            native_requests = requests[:]
        for record in (actual, sync):
            if record.get("elapsed_ms") is not None:
                assert isinstance(record["elapsed_ms"], int) and record["elapsed_ms"] >= 0
            if "stage_timing_total_ms" in record:
                assert isinstance(record["stage_timing_total_ms"], int) and record["stage_timing_total_ms"] >= 0
        assert normalize(actual) == normalize(sync)
        assert native_requests == sync_requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()


def test_kafka_http_ui_exact_schemas_request_and_record_parity():
    requests = []
    responses = {
        "/": "<title>Kafbat UI</title>",
        "/api/info": {"build": {"version": "1.2.3", "commitId": "abcdef"}, "name": "kafbat"},
        "/api/config/authentication": {"authType": "DISABLED"},
        "/api/authorization": {"rbacEnabled": False, "userInfo": None},
        "/api/clusters": [],
    }

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            requests.append(self.path)
            value = responses.get(self.path)
            body = value.encode() if isinstance(value, str) else json.dumps(value).encode()
            self.send_response(200 if value is not None else 404)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    target = SimpleNamespace(scheme="http", path="", explicit_port=server.server_port)
    try:
        spec, ctx = make_context(build_kafka_spec, server.server_port, target)
        expected = spec.detect(ctx).to_dict()
        spec.lifecycle_state_close(ctx.lifecycle_state)
        old_requests = requests[:]
        requests.clear()

        async def native():
            spec, ctx = make_context(build_kafka_spec, server.server_port, target)
            http = AsyncDetectionHttp(timeout=1, retries=0, max_bytes=128 * 1024)
            try:
                record = await spec.detect_async(ctx, http)
                assert ctx.lifecycle_state.ui_base == f"http://127.0.0.1:{server.server_port}"
                assert ctx.lifecycle_state.ui_anonymous_clusters == []
                return record.to_dict()
            finally:
                await http.close()
                spec.lifecycle_state_close(ctx.lifecycle_state)

        actual = asyncio.run(native())
        assert actual["is_kafka_ui"] is True
        assert normalize(actual) == normalize(expected)
        assert requests == old_requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_async_fingerprint_single_flight_and_owner_cancellation_cleanup():
    async def run():
        cache = ZooKeeperFingerprintCache()
        entered, release = asyncio.Event(), asyncio.Event()
        calls = 0

        async def probe():
            nonlocal calls
            calls += 1
            entered.set()
            await release.wait()
            return object()

        owner = asyncio.create_task(cache.get_or_probe_async(("same",), probe))
        await entered.wait()
        follower = asyncio.create_task(cache.get_or_probe_async(("same",), probe))
        await asyncio.sleep(0)
        owner.cancel()
        with pytest.raises(asyncio.CancelledError):
            await owner
        release.set()
        value = await asyncio.wait_for(follower, 1)
        assert calls == 2
        assert cache.get_or_probe(("same",), lambda: pytest.fail("cache missed")) is value
        assert not cache._pending and not cache._async_pending

    asyncio.run(run())
