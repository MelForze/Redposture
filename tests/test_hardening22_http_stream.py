"""Actual HTTP framing failures during a Kafka UI SSE page."""

from __future__ import annotations

import gzip
import json
import socketserver
import threading
from contextlib import closing

import pytest

from redposture_core.clients.http_session import HttpSessionPool
from redposture_core.modules.kafka import ui


@pytest.mark.parametrize("mode", ["length", "chunk", "timeout", "gzip"])
@pytest.mark.parametrize("done_before_failure", [False, True])
def test_http_interruption_keeps_valid_sse_events_but_never_commits_done(mode: str, done_before_failure: bool) -> None:
    message = {"type": "MESSAGE", "message": {"partition": 0, "offset": 7, "value": "known-before-wire-failure"}}
    event = ("data: " + json.dumps(message) + "\n\n").encode()
    if done_before_failure:
        event += b'data: {"type":"DONE","cursor":{"id":"must-not-commit"}}\n\n'
    wire_event = gzip.compress(event)[:-4] if mode == "gzip" else event
    stop = threading.Event()

    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            self.request.settimeout(1)
            self.request.recv(65536)
            headers = (
                b"Transfer-Encoding: chunked\r\n"
                if mode == "chunk"
                else b"Content-Length: " + str(len(wire_event) + 100).encode() + b"\r\n"
            )
            if mode == "gzip":
                headers += b"Content-Encoding: gzip\r\n"
            self.request.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n" + headers + b"Connection: close\r\n\r\n"
            )
            self.request.sendall(
                hex(len(event))[2:].encode() + b"\r\n" + event + b"\r\n5\r\nx" if mode == "chunk" else wire_event
            )
            if mode == "timeout":
                stop.wait(2)

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True

    server = Server(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        with closing(HttpSessionPool(timeout=0.15, retries=0)) as pool:
            rows, done, error, cursor, _v2 = ui._read_ui_messages(
                pool,
                f"http://127.0.0.1:{server.server_address[1]}",
                "qa",
                "events",
                vendor="kafbat",
                cookie="",
                limit=100,
            )
            assert rows == [
                {
                    "partition": 0,
                    "offset": 7,
                    "timestamp": None,
                    "key": None,
                    "value": "known-before-wire-failure",
                    "headers": None,
                }
            ]
            assert not done and error and cursor is None
            assert pool.stats()["connections"] == 1
    finally:
        stop.set()
        server.shutdown()
        server.server_close()
        thread.join(2)
        assert not thread.is_alive()
