"""A peer closing before HTTP headers must not keep fixture cleanup alive."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize("fixture", ["_fixed_http_server", "_redirect_server"])
@pytest.mark.parametrize("prefix", [b"", b"GET / HTTP/1.1\r\nHost:"])
def test_fingerprint_fixture_stops_after_eof(fixture: str, prefix: bytes) -> None:
    root = Path(__file__).resolve().parents[1]
    program = """
import runpy, socket, sys
scope = runpy.run_path('tests/test_network_fingerprint_matrix.py')
fixture, prefix = sys.argv[1], bytes.fromhex(sys.argv[2])
args = (200, b'{}', 'application/json') if fixture == '_fixed_http_server' else (1,)
with scope[fixture](*args) as result:
    port = result if isinstance(result, int) else result[0]
    with socket.create_connection(('127.0.0.1', port), timeout=1) as client:
        if prefix:
            client.sendall(prefix)
        client.shutdown(socket.SHUT_WR)
        assert client.recv(1) == b'', 'an incomplete request must receive no fabricated response'
"""
    completed = subprocess.run(
        [sys.executable, "-c", program, fixture, prefix.hex()],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=6,
    )
    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize("kind", ["grpc_headers", "grpc_body", "proxy_connect"])
def test_related_protocol_fixtures_stop_after_eof(kind: str) -> None:
    root = Path(__file__).resolve().parents[1]
    program = """
import runpy, socket, sys
kind = sys.argv[1]
if kind == 'proxy_connect':
    scope = runpy.run_path('tests/test_proxy_end_to_end.py')
    server = scope['_TunnelProxy']('http')
    with scope['_running'](server):
        with socket.create_connection(server.server_address, timeout=1) as client:
            client.sendall(b'CONNECT host:443 HTTP/1.1\\r\\nHost:')
            client.shutdown(socket.SHUT_WR)
            assert client.recv(1) == b''
    assert server.requested_hosts == []
else:
    scope = runpy.run_path('tests/test_async_grpc_native.py')
    server, thread, requests, entered, closed, connections = scope['native_server']()
    payload = b'GET /long-test HTTP/1.1\\r\\nHost:' if kind == 'grpc_headers' else b'POST / HTTP/1.1\\r\\nHost: qa\\r\\nContent-Length: 5\\r\\n\\r\\nab'
    try:
        with socket.create_connection(server.server_address, timeout=1) as client:
            client.sendall(payload)
            client.shutdown(socket.SHUT_WR)
            assert client.recv(1) == b''
        assert closed.wait(1)
        assert not requests
    finally:
        scope['cleanup'](server, thread)
"""
    completed = subprocess.run(
        [sys.executable, "-c", program, kind], cwd=root, capture_output=True, text=True, timeout=6
    )
    assert completed.returncode == 0, completed.stderr
