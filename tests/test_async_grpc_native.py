"""Native gRPC retains the exact H2/HPACK session for synchronous phases."""

from __future__ import annotations

import asyncio
import socketserver
import ssl
import threading
from dataclasses import replace
from types import SimpleNamespace

import pytest
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, RequestReceived, StreamEnded

from redposture_core.clients import grpc
from redposture_core.modules.grpc import stage
from redposture_core.proto import grpc_health_pb2, grpc_reflection_pb2
from redposture_core.stage_runtime import AuditCredentialRun, AuditHookContext


def context(port, secure=False):
    args = SimpleNamespace(timeout=1.0, retries=0, tls=secure, plaintext=not secure)
    spec = stage.build_grpc_spec(args)
    ctx = AuditHookContext(
        args=args, logger=None, host="127.0.0.1", port=port, credential=AuditCredentialRun(), phase="detect"
    )
    assert spec.lifecycle_state_factory is not None
    return spec, replace(ctx, lifecycle_state=spec.lifecycle_state_factory(ctx))


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def native_server(*, secure=False, material=None, web=False, stall=False):
    requests = []
    closed = threading.Event()
    entered = threading.Event()
    connections = []

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            conn = H2Connection(config=H2Configuration(client_side=False, header_encoding="utf-8"))
            conn.initiate_connection()
            connections.append(conn)
            paths = {}
            try:
                prefix = bytearray()
                while len(prefix) < 24:
                    data = self.request.recv(24 - len(prefix))
                    if not data:
                        return
                    prefix.extend(data)
                if not bytes(prefix).startswith(b"PRI * HTTP/2.0"):
                    data = bytes(prefix)
                    while b"\r\n\r\n" not in data:
                        data += self.request.recv(65536)
                    headers, body = data.split(b"\r\n\r\n", 1)
                    size = next(
                        int(line.split(b":", 1)[1])
                        for line in headers.split(b"\r\n")
                        if line.lower().startswith(b"content-length:")
                    )
                    while len(body) < size:
                        body += self.request.recv(65536)
                    requests.append((0, headers.split(b"\r\n", 1)[0].decode()))
                    health = grpc._encode_grpc_frame(grpc_health_pb2.HealthCheckResponse(status=1).SerializeToString())
                    trailers = b"grpc-status: 0\r\n"
                    payload = health + b"\x80" + len(trailers).to_bytes(4, "big") + trailers
                    self.request.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/grpc-web+proto\r\nContent-Length: "
                        + str(len(payload)).encode()
                        + b"\r\nConnection: close\r\n\r\n"
                        + payload
                    )
                    return
                data = bytes(prefix)
                self.request.sendall(conn.data_to_send())
                while True:
                    for event in conn.receive_data(data):
                        if isinstance(event, RequestReceived):
                            path = dict(event.headers)[":path"]
                            paths[event.stream_id] = path
                            requests.append((event.stream_id, path))
                            entered.set()
                        elif isinstance(event, DataReceived):
                            conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                        elif isinstance(event, StreamEnded):
                            if stall:
                                continue
                            path = paths[event.stream_id]
                            if web:
                                conn.send_headers(
                                    event.stream_id,
                                    [(":status", "404"), ("content-type", "text/plain")],
                                    end_stream=True,
                                )
                                continue
                            conn.send_headers(
                                event.stream_id,
                                [
                                    (":status", "200"),
                                    ("content-type", "application/grpc"),
                                    ("x-retained-hpack", "reused-table-value"),
                                ],
                            )
                            status = "0"
                            if path == "/grpc.health.v1.Health/Check":
                                message = grpc_health_pb2.HealthCheckResponse(status=1).SerializeToString()
                                conn.send_data(event.stream_id, grpc._encode_grpc_frame(message))
                            elif "/grpc.reflection.v1." in path:
                                status = "12"
                            else:
                                response = grpc_reflection_pb2.ServerReflectionResponse()
                                response.error_response.error_code = 5
                                response.error_response.error_message = "not found"
                                conn.send_data(event.stream_id, grpc._encode_grpc_frame(response.SerializeToString()))
                            conn.send_headers(event.stream_id, [("grpc-status", status)], end_stream=True)
                    pending = conn.data_to_send()
                    if pending:
                        self.request.sendall(pending)
                    data = self.request.recv(65536)
                    if not data:
                        return
            except (OSError, ValueError):
                return
            finally:
                closed.set()

    server = Server(("127.0.0.1", 0), Handler)
    if secure:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(material["server_cert"], material["server_key"])
        tls.set_alpn_protocols(["h2"])
        server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, requests, entered, closed, connections


def cleanup(server, thread):
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)
    assert not thread.is_alive()


def test_grpc_registers_native_hook_with_original_sync_pair():
    spec = stage.build_grpc_spec(SimpleNamespace())
    assert spec.detect_async is not None
    assert spec.async_detect_sync_hook is spec.detect


@pytest.mark.parametrize("secure", [False, True])
def test_grpc_full_h2_reflection_fallback_and_sync_reuse(secure, mtls_material, monkeypatch):
    server, thread, requests, entered, closed, connections = native_server(secure=secure, material=mtls_material)
    try:

        async def run():
            monkeypatch.setattr(
                asyncio.get_running_loop(), "run_in_executor", lambda *a, **k: pytest.fail("executor called")
            )
            spec, ctx = context(server.server_address[1], secure)
            record = await spec.detect_async(ctx, None)
            state = ctx.lifecycle_state
            assert record.extra["is_grpc"] is True
            assert record.auth_required is None
            assert record.extra["reflection_version"] == "v1alpha"
            assert state.detect_result is not None
            assert len(state.sessions) == 1
            session = next(iter(state.sessions.values()))
            assert type(session) is grpc._GrpcH2Session
            assert session._reflection_version == "v1alpha"
            assert session._sock.gettimeout() == 1.0
            assert isinstance(session._sock, ssl.SSLSocket) is secure
            original_h2, original_sock = session._conn, session._sock
            result = session.call(
                path="/grpc.health.v1.Health/Check", payload=grpc._grpc_health_payload(), authorization=None
            )
            assert result["grpc_status"] == 0
            assert session._conn is original_h2 and session._sock is original_sock
            state.close()

        asyncio.run(run())
        assert len(connections) == 1
        assert requests == [
            (1, "/grpc.health.v1.Health/Check"),
            (3, "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo"),
            (5, "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"),
            (7, "/grpc.health.v1.Health/Check"),
        ]
    finally:
        cleanup(server, thread)


def test_grpc_web_normal_fallback_uses_complete_status_proof():
    server, thread, requests, entered, closed, connections = native_server(web=True)
    try:

        async def run():
            spec, ctx = context(server.server_address[1])
            result = await spec.detect_async(ctx, None)
            assert result.extra["protocol_flavor"] == "grpc-web"
            assert result.extra["grpc_web_detected"] is True
            ctx.lifecycle_state.close()

        asyncio.run(run())
        assert requests[-1] == (0, "POST /grpc.health.v1.Health/Check HTTP/1.1")
    finally:
        cleanup(server, thread)


def test_grpc_cancel_closes_retained_h2_socket():
    server, thread, requests, entered, closed, connections = native_server(stall=True)
    try:

        async def run():
            spec, ctx = context(server.server_address[1])
            task = asyncio.create_task(spec.detect_async(ctx, None))
            while not entered.is_set():
                await asyncio.sleep(0.001)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            session = next(iter(ctx.lifecycle_state.sessions.values()))
            assert session._sock is None or session._sock.fileno() == -1
            ctx.lifecycle_state.close()

        asyncio.run(run())
        assert closed.wait(1)
    finally:
        cleanup(server, thread)


def normalized(value):
    if isinstance(value, dict):
        return {key: normalized(item) for key, item in value.items() if key != "timestamp" and not key.endswith("_ms")}
    if isinstance(value, list):
        return [normalized(item) for item in value]
    return value


@pytest.mark.parametrize("secure", [False, True])
@pytest.mark.parametrize("web", [False, True])
def test_grpc_complete_record_and_order_parity(secure, web, mtls_material):
    server, thread, requests, entered, closed, connections = native_server(
        secure=secure, material=mtls_material, web=web
    )
    try:
        spec, ctx = context(server.server_address[1], secure)
        expected = spec.detect(ctx).to_dict()
        ctx.lifecycle_state.close()
        expected_requests = requests[:]
        requests.clear()

        async def run():
            spec, ctx = context(server.server_address[1], secure)
            result = await spec.detect_async(ctx, None)
            ctx.lifecycle_state.close()
            return result.to_dict()

        actual = asyncio.run(run())
        assert normalized(actual) == normalized(expected)
        assert requests == expected_requests
        assert actual["is_grpc"] is True
    finally:
        cleanup(server, thread)


@pytest.mark.parametrize(
    "body,declared_extra,positive",
    [
        (b"", 0, False),
        (b"\x80\x00\x00\x00\x10grpc-status: 0\r\n", 0, True),
        (b"\x80\x00\x00\x00\x10grpc-status: 0\r\n", 5, False),
        (b"\x80\x00\x00\x00\x11grpc-status: 17\r\n", 0, False),
    ],
)
def test_native_grpc_web_requires_complete_valid_trailer_status(body, declared_extra, positive):
    from redposture_core.clients.async_retained_socket import detect_native

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            data = b""
            while b"\r\n\r\n" not in data:
                data += self.request.recv(65536)
            self.request.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/grpc-web+proto\r\nContent-Length: "
                + str(len(body) + declared_extra).encode()
                + b"\r\nConnection: close\r\n\r\n"
                + body
            )

    server = Server(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:

        async def run():
            result = await detect_native(
                grpc._grpc_web_call_detect_steps(
                    "127.0.0.1",
                    server.server_address[1],
                    path="/grpc.health.v1.Health/Check",
                    payload=b"",
                    timeout=1,
                    use_tls=False,
                    authorization=None,
                ),
                None,
                grpc._ASYNC_RETAINED_STEPS,
            )
            assert result["is_grpc_web"] is positive

        asyncio.run(run())
    finally:
        cleanup(server, thread)


def test_native_h2_early_terminal_flow_control_drains_pending_settings_ack():
    from h2.events import SettingsAcknowledged

    from redposture_core.clients.async_retained_socket import detect_native
    from redposture_core.detection_io import DetectCall

    acknowledged = threading.Event()

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            conn = H2Connection(config=H2Configuration(client_side=False))
            conn.initiate_connection()
            self.request.sendall(conn.data_to_send())
            try:
                while True:
                    data = self.request.recv(65536)
                    if not data:
                        break
                    for event in conn.receive_data(data):
                        if isinstance(event, RequestReceived):
                            # Respond before the large request body can exhaust
                            # its normal 65,535-byte outbound flow window.
                            conn.send_headers(
                                event.stream_id, [(":status", "200"), ("content-type", "application/grpc")]
                            )
                            conn.send_headers(event.stream_id, [("grpc-status", "0")], end_stream=True)
                        elif isinstance(event, DataReceived):
                            # Deliberately withhold request WINDOW_UPDATE. The
                            # client must read this early response while blocked.
                            pass
                        elif isinstance(event, SettingsAcknowledged):
                            acknowledged.set()
                    pending = conn.data_to_send()
                    if pending:
                        self.request.sendall(pending)
            except OSError:
                pass

    server = Server(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:

        async def run():
            session = grpc._GrpcH2Session("127.0.0.1", server.server_address[1], timeout=1, use_tls=False)

            def steps():
                return (
                    yield DetectCall(
                        session.call,
                        (),
                        {"path": "/application.Service/Large", "payload": bytes(100_000), "authorization": None},
                    )
                )

            result = await detect_native(steps(), None, grpc._ASYNC_RETAINED_STEPS)
            assert result["is_grpc"] is True
            assert result["grpc_status"] == 0
            assert session._conn.data_to_send() == b""
            assert acknowledged.wait(1)
            session.close()

        asyncio.run(run())
    finally:
        cleanup(server, thread)
