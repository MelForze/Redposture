"""Wire controls for the bounded execution WebSocket transport."""

from __future__ import annotations

import base64
import hashlib
import json
import socketserver
import ssl
import threading
from contextlib import closing, contextmanager

import pytest

from redposture_core.clients.http_session import HttpSessionPool
from redposture_core.clients.websocket import WebSocket


def frame(value, opcode=1, fin=True):
    body = value if isinstance(value, bytes) else json.dumps(value).encode()
    return (
        bytes([(128 if fin else 0) | opcode])
        + (bytes([len(body)]) if len(body) < 126 else b"\x7e" + len(body).to_bytes(2, "big"))
        + body
    )


@contextmanager
def server(frames, *, bad_accept=False, tls=None, wait=False):
    connected = threading.Event()
    release = threading.Event()
    requests = []

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(2)
            raw = b""
            while b"\r\n\r\n" not in raw:
                part = self.request.recv(4096)
                if not part:
                    return
                raw += part
            requests.append(raw.decode())
            key = next(
                row.split(":", 1)[1].strip()
                for row in raw.decode().splitlines()
                if row.lower().startswith("sec-websocket-key:")
            )
            accept = base64.b64encode(
                hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
            ).decode()
            if bad_accept:
                accept = "incorrect"
            self.request.sendall(
                (
                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "
                    + accept
                    + "\r\n\r\n"
                ).encode()
                + b"".join(frames)
            )
            connected.set()
            if wait:
                release.wait(3)

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    srv = Server(("127.0.0.1", 0), Handler)
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(tls[0], tls[1])
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"{'https' if tls else 'http'}://127.0.0.1:{srv.server_address[1]}/prefix/stream", connected, requests
    finally:
        release.set()
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=2)


def test_fragment_ping_and_prefetched_body_are_preserved():
    with server([frame(b'{"value":', fin=False), frame(b"ping", opcode=9), frame(b"7}", opcode=0)]) as (
        url,
        _,
        requests,
    ):
        with closing(HttpSessionPool(timeout=1)) as pool:
            with WebSocket(pool, url, headers={"Authorization": "token qa"}, timeout=1, max_bytes=1024) as ws:
                assert ws.recv_json() == {"value": 7}
        assert "GET /prefix/stream HTTP/1.1" in requests[0]
        assert "Authorization: token qa" in requests[0]


@pytest.mark.parametrize(
    "packets,error",
    [
        ([frame(b"x" * 200)], "byte limit"),
        ([frame({}, opcode=0)], "message type"),
        ([frame({}, opcode=8)], "closed"),
        ([b"\x81\xff" + (1 << 40).to_bytes(8, "big")], "flags"),
    ],
)
def test_bad_or_oversized_stream_does_not_prove_completion(packets, error):
    with server(packets) as (url, _, _):
        with closing(HttpSessionPool(timeout=1)) as pool:
            with WebSocket(pool, url, headers={}, timeout=1, max_bytes=100) as ws:
                with pytest.raises((ValueError, ConnectionError), match=error):
                    ws.recv_json()


def test_bad_handshake_never_sends_command():
    with server([], bad_accept=True) as (url, _, requests):
        with closing(HttpSessionPool(timeout=1)) as pool:
            with pytest.raises(ConnectionError, match="upgrade"):
                with WebSocket(pool, url, headers={}, timeout=1, max_bytes=1024):
                    pytest.fail("must not execute after invalid upgrade")
            assert not pool._connections
        assert len(requests) == 1


def test_pool_close_interrupts_execution_read():
    errors = []
    with server([], wait=True) as (url, connected, _):
        pool = HttpSessionPool(timeout=2)
        with WebSocket(pool, url, headers={}, timeout=2, max_bytes=1024) as ws:

            def read():
                try:
                    ws.recv_json()
                except (OSError, ConnectionError) as exc:
                    errors.append(exc)

            reader = threading.Thread(target=read, daemon=True)
            reader.start()
            assert connected.wait(1)
            pool.close()
            reader.join(timeout=1)
            assert not reader.is_alive() and errors


def test_pool_shutdown_keeps_websocket_fd_until_reader_context_exits():
    # Closing a descriptor while another thread waits in select() is undefined
    # on macOS. Retain a socket file reference until the WebSocket is released.
    with server([], wait=True) as (url, _, _):
        pool = HttpSessionPool(timeout=2)
        with WebSocket(pool, url, headers={}, timeout=2, max_bytes=1024) as ws:
            sock = ws.sock
            pool.close()
            assert sock.fileno() >= 0
            with pytest.raises((OSError, ConnectionError)):
                ws.recv_json()
        assert sock.fileno() == -1


def test_tls_uses_http_pool_trust_configuration(mtls_material):
    with server([frame({"tls": True})], tls=(mtls_material["server_cert"], mtls_material["server_key"])) as (url, _, _):
        url = url.replace("127.0.0.1", "localhost")
        with closing(HttpSessionPool(timeout=1, ca_file=str(mtls_material["ca_cert"]), insecure=False)) as pool:
            with WebSocket(pool, url, headers={}, timeout=2, max_bytes=1024) as ws:
                assert ws.recv_json() == {"tls": True}
