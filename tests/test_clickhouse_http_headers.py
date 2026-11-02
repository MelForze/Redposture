from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from redposture_core.http_headers import custom_http_headers
from redposture_core.modules.clickhouse import actions
from tests.test_async_clickhouse_http import BLOCK_INFO, native


@pytest.fixture
def sdk_requests():
    requests = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            sql = body.decode()
            requests.append(("POST", f"http://127.0.0.1:{self.server.server_port}{self.path}", dict(self.headers)))
            if sql == "SELECT version(), timezone()":
                response = b"24.8.14.39\tUTC\n"
            elif "FROM system.settings LIMIT 10000" in sql:
                response = native([("name", "String"), ("value", "String"), ("readonly", "UInt8")], [])
            elif "SELECT 1 AS check" in sql:
                response = BLOCK_INFO + native([("check", "UInt8")], [[1]])
            else:
                response = b"ok"
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            self.wfile.write(f"{len(response):x}\r\n".encode() + response + b"\r\n0\r\n\r\n")
            self.wfile.flush()

    # Retain the real constructor and transport across SDK versions; only the
    # HTTP peer is emulated, without patching private metadata initialization.
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
    thread.start()
    try:
        yield requests, server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
        assert not thread.is_alive()


def test_installed_clickhouse_sdk_receives_headers_during_constructor(sdk_requests):
    requests, port = sdk_requests
    with custom_http_headers([("authorization", "Bearer operator"), ("X-QA", "checked")]):
        client = actions._open_clickhouse_client("http", "127.0.0.1", port, 5, "builtin", "builtin-pass", "default")
        initialized_requests = len(requests)
        assert initialized_requests > 0
        with client.raw_stream("SELECT 1", fmt="Native") as stream:
            assert stream.read() == b"ok"
    assert len(requests) == initialized_requests + 1
    for _, url, headers in requests:
        from urllib.parse import urlsplit

        assert urlsplit(url).hostname == "127.0.0.1" and urlsplit(url).port == port
        assert {k.lower(): v for k, v in headers.items()}["authorization"] == "Bearer operator"
        assert sum(k.lower() == "authorization" for k in headers) == 1
        assert headers["X-QA"] == "checked"
    client.close()


def test_installed_sdk_lowercase_user_agent_overrides_its_default(sdk_requests):
    requests, port = sdk_requests
    with custom_http_headers([("user-agent", "operator-agent"), ("authorization", "Bearer operator")]):
        client = actions._open_clickhouse_client("http", "127.0.0.1", port, 5, "builtin", "builtin-pass", "default")
        with client.raw_stream("SELECT 1", fmt="Native") as stream:
            assert stream.read() == b"ok"
    for _, _, headers in requests:
        matching = [value for name, value in headers.items() if name.lower() == "user-agent"]
        assert matching == ["operator-agent"]
    client.close()


@pytest.mark.parametrize("authorization", ["Authorization", "authorization"])
def test_header_compatibility_snapshots_operator_and_overrides_request_auth(sdk_requests, authorization):
    from redposture_core.clients.clickhouse_http import create_http_client_with_headers

    requests, port = sdk_requests
    headers = {authorization: "Bearer operator", "Cookie": "session=operator"}
    client = create_http_client_with_headers(
        {
            "interface": "http",
            "secure": False,
            "host": "127.0.0.1",
            "port": port,
            "username": "builtin",
            "password": "builtin-pass",
            "database": "default",
        },
        headers,
    )
    headers[authorization] = "mutated"
    client._raw_request(b"query", {}, headers={"Authorization": "Basic other", "Cookie": "session=other"}).close()
    for _, _, sent in requests:
        assert {name.lower(): value for name, value in sent.items()}["authorization"] == "Bearer operator"
        assert sent["Cookie"] == "session=operator"
        assert sum(name.lower() == "authorization" for name in sent) == 1
    client.close()
