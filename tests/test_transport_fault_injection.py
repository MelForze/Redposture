"""Wire-level fault injection for truncated, stalled and reset connections."""

from __future__ import annotations

import socket
import socketserver
import struct
import threading
import time
from collections.abc import Iterator
from contextlib import closing, contextmanager
from typing import cast

import pytest

from redposture_core.clients import kafka
from redposture_core.clients.http_session import HttpSessionPool
from redposture_core.modules.elastic.actions import _load_json_dict_loose


class _FaultServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, mode: str) -> None:
        super().__init__(("127.0.0.1", 0), _FaultHandler)
        self.mode = mode
        self.request_seen = threading.Event()

    def handle_error(self, _request: object, _client_address: object) -> None:
        return


class _FaultHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server = cast(_FaultServer, self.server)
        conn = cast(socket.socket, self.request)
        if server.mode == "disconnect":
            return
        data = bytearray()
        while b"\r\n\r\n" not in data and len(data) < 64 * 1024:
            chunk = conn.recv(4096)
            if not chunk:
                return
            data.extend(chunk)
        server.request_seen.set()
        if server.mode == "rst":
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            return
        if server.mode == "truncated":
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\npartial")
            return
        if server.mode == "stalled":
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nx")
            time.sleep(1.0)
            return
        if server.mode == "chunked":
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nzz\r\ninvalid\r\n0\r\n\r\n"
            )
            return
        if server.mode == "gzip":
            body = b"\x1f\x8bcorrupt-gzip-stream"
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: "
                + str(len(body)).encode("ascii")
                + b"\r\nConnection: close\r\n\r\n"
                + body
            )


@contextmanager
def _serve_fault(mode: str) -> Iterator[_FaultServer]:
    server = _FaultServer(mode)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        assert not thread.is_alive()


@pytest.mark.parametrize("mode", ["disconnect", "truncated", "rst", "chunked"])
def test_http_pool_normalizes_wire_failures_without_leaking_connections(mode: str) -> None:
    with _serve_fault(mode) as server:
        with closing(HttpSessionPool(timeout=0.25)) as pool:
            response = pool.request("GET", f"http://127.0.0.1:{server.server_address[1]}/", retries=0)
            stats = pool.stats()

    assert response.status == 0
    assert response.error
    assert stats["connections"] == 1


def test_http_pool_enforces_body_read_timeout() -> None:
    started = time.monotonic()
    with _serve_fault("stalled") as server:
        with closing(HttpSessionPool(timeout=0.15)) as pool:
            response = pool.request("GET", f"http://127.0.0.1:{server.server_address[1]}/", retries=0)
    elapsed = time.monotonic() - started

    assert response.status == 0
    assert "timed out" in str(response.error).casefold()
    assert elapsed < 0.8


def test_corrupt_gzip_is_rejected_after_real_http_read() -> None:
    with _serve_fault("gzip") as server:
        with closing(HttpSessionPool(timeout=0.5)) as pool:
            response = pool.request("GET", f"http://127.0.0.1:{server.server_address[1]}/", retries=0)

    assert response.status == 200 and response.error is None
    assert _load_json_dict_loose(response.body, response.headers) is None


def test_kafka_partial_frame_fails_closed_on_real_socket() -> None:
    reader, writer = socket.socketpair()
    reader.settimeout(0.5)
    try:
        writer.sendall(struct.pack(">i", 12) + b"abc")
        writer.close()
        with pytest.raises(ConnectionError, match="unexpected EOF"):
            kafka._recv_kafka_frame(reader)
    finally:
        reader.close()
        writer.close()
