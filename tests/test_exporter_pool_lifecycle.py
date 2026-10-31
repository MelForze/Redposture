"""Pooling must preserve routing, zero-retry profiles and deterministic cleanup."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from redposture_core.exporters.http_pool import HTTPConnectionPool
from redposture_core.exporters.trigger import scan_exporters_and_trigger
from tests.test_exporter_pipeline_performance import EXPORTER


def server_for(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
    thread.start()
    return server, thread


def finish(server, thread):
    server.shutdown()
    server.server_close()
    thread.join(2)
    assert not thread.is_alive()


def test_trigger_zero_retry_actions_discard_server_closed_idle_connection():
    paths = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def do_GET(self):
            paths.append(urlsplit(self.path).path)
            body = b"mysql_exporter_build_info 1\n" if paths[-1] == "/metrics" else b"probe_success 1\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            self.wfile.flush()
            # No Connection: close header: the client cached a once-live socket.
            self.close_connection = True

    server, thread = server_for(Handler)
    try:
        result = scan_exporters_and_trigger(
            None,
            ["127.0.0.1"],
            ["127.0.0.1", "127.0.0.2", "127.0.0.3"],
            1,
            workers=1,
            retries=0,
            trigger_exporters=[{**EXPORTER, "port": server.server_port}],
            profile_delay=0.05,
        )
        assert result["triggered"] == result["attempted"] == 3
        assert paths == ["/metrics", "/probe", "/probe", "/probe"]
    finally:
        finish(server, thread)


def test_closed_pool_cannot_be_repopulated_by_a_late_release():
    pool = HTTPConnectionPool()
    connection = pool._acquire("http", "127.0.0.1", 9104, 1)
    pool.close()
    pool._release("http", "127.0.0.1", 9104, connection, True)
    try:
        assert pool._idle_total == 0 and not pool._idle
    finally:
        pool.close()


def test_pool_close_interrupts_active_body_and_prevents_reuse():
    entered, release = threading.Event(), threading.Event()
    results = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "10000")
            self.end_headers()
            self.wfile.write(b"prefix")
            self.wfile.flush()
            entered.set()
            release.wait(3)
            self.close_connection = True

    server, thread = server_for(Handler)
    pool = HTTPConnectionPool()
    worker = threading.Thread(
        target=lambda: results.append(pool.get(f"http://127.0.0.1:{server.server_port}/", 3)), daemon=True
    )
    worker.start()
    try:
        assert entered.wait(1)
        pool.close()
        worker.join(0.5)
        assert not worker.is_alive(), "pool close left its active body reader blocked"
        assert results and results[0][3] is not None
        assert pool._idle_total == 0
    finally:
        release.set()
        worker.join(4)
        pool.close()
        finish(server, thread)


def test_trigger_honors_environment_http_proxy(monkeypatch):
    paths = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            paths.append(self.path)
            body = b"mysql_exporter_build_info 1\n" if self.path.endswith("/metrics") else b"probe_success 1\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server, thread = server_for(Handler)
    for name in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("http_proxy", f"http://127.0.0.1:{server.server_port}")
    monkeypatch.setenv("no_proxy", "")
    try:
        result = scan_exporters_and_trigger(
            None, ["198.18.0.1"], ["127.0.0.1"], 0.1, workers=1, retries=0, trigger_exporters=[EXPORTER]
        )
        assert result["triggered"] == 1
        assert len(paths) == 2 and all(path.startswith("http://198.18.0.1:9104/") for path in paths)
    finally:
        finish(server, thread)


def test_pool_eviction_keeps_replacement_connection_reachable():
    pool = HTTPConnectionPool(max_idle_total=1, max_idle_per_host=2)
    first = pool._acquire("http", "127.0.0.1", 9104, 1)
    second = pool._acquire("http", "127.0.0.1", 9104, 1)
    try:
        pool._release("http", "127.0.0.1", 9104, first, True)
        pool._release("http", "127.0.0.1", 9104, second, True)
        assert sum(map(len, pool._idle.values())) == pool._idle_total == 1
        assert pool._acquire("http", "127.0.0.1", 9104, 1) is second
    finally:
        pool.close()
