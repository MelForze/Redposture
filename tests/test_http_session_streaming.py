"""One HTTP response can be consumed in bounded portions."""

from __future__ import annotations

import threading
import time
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from redposture_core.clients.http_session import HttpSessionPool


def test_http_pool_streams_one_response_in_bounded_chunks() -> None:
    payload = b"ordinary " * 200 + b"API_TOKEN=glpat-abcdefghijklmnopqrst\n"

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            assert self.path == "/raw"
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    chunks: list[bytes] = []
    response_headers: list[tuple[int, dict[str, str]]] = []
    try:
        with closing(HttpSessionPool(timeout=1)) as pool:
            response = pool.request_stream(
                "GET",
                f"http://127.0.0.1:{server.server_address[1]}/raw",
                on_chunk=chunks.append,
                on_response=lambda status, headers: response_headers.append((status, dict(headers))),
                chunk_size=128,
            )
            assert response.status == 200 and response.error is None and not response.truncated
            assert response.body == b""
            assert b"".join(chunks) == payload
            assert max(map(len, chunks)) <= 128
            assert len(chunks) > 1
            assert response_headers and response_headers[0][0] == 200
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


def test_http_pool_streams_post_response_with_request_body() -> None:
    request_body = b'{"query":{"match_all":{}},"size":1}'
    payload = b"ordinary output\n" * 200_000

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            assert self.path == "/_search"
            assert self.rfile.read(int(self.headers["Content-Length"])) == request_body
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    chunks: list[bytes] = []
    try:
        with closing(HttpSessionPool(timeout=3)) as pool:
            response = pool.request_stream(
                "POST",
                f"http://127.0.0.1:{server.server_address[1]}/_search",
                body=request_body,
                on_chunk=chunks.append,
                chunk_size=32 * 1024,
            )
        assert response.status == 200 and response.error is None and not response.truncated
        assert b"".join(chunks) == payload
        assert max(map(len, chunks)) <= 32 * 1024
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


def test_http_pool_stream_marks_interrupted_body_incomplete() -> None:
    payload = b"API_TOKEN=glpat-abcdefghijklmnopqrst\n"

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload) + 100))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    chunks: list[bytes] = []
    try:
        with closing(HttpSessionPool(timeout=1)) as pool:
            response = pool.request_stream(
                "GET",
                f"http://127.0.0.1:{server.server_address[1]}/raw",
                on_chunk=chunks.append,
                chunk_size=16,
            )
            assert b"".join(chunks) == payload
            assert response.status == 200 and response.error and response.truncated
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


def test_http_pool_stream_deadline_interrupts_slow_body() -> None:
    release = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Length", "10")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b"first")
            self.wfile.flush()
            release.wait(1)
            try:
                self.wfile.write(b"later")
            except OSError:
                pass

        def log_message(self, *_args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    chunks: list[bytes] = []
    try:
        with closing(HttpSessionPool(timeout=1)) as pool:
            start = time.monotonic()
            response = pool.request_stream(
                "GET",
                f"http://127.0.0.1:{server.server_address[1]}/raw",
                on_chunk=chunks.append,
                chunk_size=5,
                deadline=start + 0.15,
            )
            assert b"".join(chunks) == b"first"
            assert response.error and response.truncated
            assert time.monotonic() - start < 0.75
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(2)


def test_http_pool_close_interrupts_active_stream() -> None:
    release = threading.Event()
    first_chunk = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Length", "10")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b"first")
            self.wfile.flush()
            release.wait(2)

        def log_message(self, *_args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    pool = HttpSessionPool(timeout=5)
    responses = []

    def read_stream() -> None:
        def on_chunk(_chunk: bytes) -> None:
            first_chunk.set()

        responses.append(
            pool.request_stream(
                "GET", f"http://127.0.0.1:{server.server_address[1]}/raw", on_chunk=on_chunk, chunk_size=5
            )
        )

    reader = threading.Thread(target=read_stream, daemon=True)
    reader.start()
    try:
        assert first_chunk.wait(1)
        pool.close()
        reader.join(1)
        assert not reader.is_alive()
        assert responses and responses[0].error
    finally:
        release.set()
        pool.close()
        server.shutdown()
        server.server_close()
        server_thread.join(2)
