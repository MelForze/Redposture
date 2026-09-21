"""End-to-end proxy QA with remote DNS, redirects and verified TLS."""

from __future__ import annotations

import json
import select
import shutil
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
from collections.abc import Iterator
from contextlib import closing, contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import cast

import pytest

from redposture_core.clients.http_session import HttpSessionPool
from redposture_core.network_proxy import ProxyConfig


class _HttpServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, handler: type[BaseHTTPRequestHandler]) -> None:
        super().__init__(("127.0.0.1", 0), handler)
        self.redirect_url = ""
        self.calls: list[str] = []


class _SourceHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        server = cast(_HttpServer, self.server)
        server.calls.append(self.path)
        self.send_response(302)
        self.send_header("Location", server.redirect_url)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    def log_message(self, *_args: object) -> None:
        return


class _DestinationHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        cast(_HttpServer, self.server).calls.append(self.path)
        body = b"proxy-tls-ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return


class _GrafanaDestinationHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        cast(_HttpServer, self.server).calls.append(self.path)
        if self.path == "/api/health":
            body = b'{"database":"ok","version":"11.0.0","commit":"proxychains-qa"}'
            content_type = "application/json"
        elif self.path == "/api/datasources":
            body = b"[]"
            content_type = "application/json"
        else:
            body = b"<html><title>Grafana</title></html>"
            content_type = "text/html"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return


class _TunnelProxy(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, scheme: str) -> None:
        super().__init__(("127.0.0.1", 0), _TunnelHandler)
        self.scheme = scheme
        self.requested_hosts: list[tuple[str, int]] = []
        self.lock = threading.Lock()

    def record(self, host: str, port: int) -> None:
        with self.lock:
            self.requested_hosts.append((host, port))

    def handle_error(self, _request: object, _client_address: object) -> None:
        return


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    output = bytearray()
    while len(output) < size:
        chunk = sock.recv(size - len(output))
        if not chunk:
            raise ConnectionError("proxy client closed")
        output.extend(chunk)
    return bytes(output)


def _relay(left: socket.socket, right: socket.socket) -> None:
    peers = {left: right, right: left}
    while peers:
        readable, _, _ = select.select(list(peers), [], [], 1.0)
        if not readable:
            continue
        for source in readable:
            try:
                payload = source.recv(64 * 1024)
            except OSError:
                payload = b""
            if not payload:
                return
            peers[source].sendall(payload)


class _TunnelHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server = cast(_TunnelProxy, self.server)
        client = cast(socket.socket, self.request)
        client.settimeout(2)
        upstream: socket.socket | None = None
        try:
            if server.scheme == "socks5h":
                version, count = _recv_exact(client, 2)
                assert version == 5
                _recv_exact(client, count)
                client.sendall(b"\x05\x00")
                version, command, _reserved, atyp = _recv_exact(client, 4)
                assert (version, command, atyp) == (5, 1, 3)
                host = _recv_exact(client, _recv_exact(client, 1)[0]).decode("idna")
                port = int.from_bytes(_recv_exact(client, 2), "big")
                server.record(host, port)
                upstream = socket.create_connection(("127.0.0.1", port), timeout=2)
                client.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
            else:
                request = bytearray()
                while b"\r\n\r\n" not in request and len(request) < 64 * 1024:
                    request.extend(client.recv(4096))
                first_line = bytes(request).partition(b"\r\n")[0].decode("ascii")
                method, authority, _version = first_line.split(" ", 2)
                assert method == "CONNECT"
                host, port_text = authority.rsplit(":", 1)
                port = int(port_text)
                server.record(host, port)
                upstream = socket.create_connection(("127.0.0.1", port), timeout=2)
                client.sendall(b"HTTP/1.1 200 Connection Established\r\nContent-Length: 0\r\n\r\n")
            _relay(client, upstream)
        finally:
            if upstream is not None:
                upstream.close()


@contextmanager
def _running(server: socketserver.BaseServer) -> Iterator[None]:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        assert not thread.is_alive()


@pytest.mark.parametrize("proxy_scheme", ["socks5h", "http"])
def test_proxy_resolves_dns_and_follows_http_to_verified_https_redirect(
    mtls_material: dict[str, Path],
    proxy_scheme: str,
) -> None:
    destination = _HttpServer(_DestinationHandler)
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.load_cert_chain(mtls_material["server_cert"], mtls_material["server_key"])
    destination.socket = tls_context.wrap_socket(destination.socket, server_side=True)
    source = _HttpServer(_SourceHandler)
    source.redirect_url = f"https://secure.service.test:{destination.server_port}/final?via=proxy"
    proxy = _TunnelProxy(proxy_scheme)
    config = ProxyConfig(
        scheme=proxy_scheme,
        host="127.0.0.1",
        port=proxy.server_address[1],
        username=None,
        password=None,
        raw_url=f"{proxy_scheme}://127.0.0.1:{proxy.server_address[1]}",
    )

    with _running(destination), _running(source), _running(proxy):
        with closing(HttpSessionPool(timeout=1, ca_file=str(mtls_material["ca_cert"]), proxy=config)) as pool:
            response = pool.request(
                "GET",
                f"http://service.test:{source.server_port}/start",
                retries=0,
            )

    assert response.status == 200 and response.error is None
    assert response.body == b"proxy-tls-ok"
    assert source.calls == ["/start"]
    assert destination.calls == ["/final?via=proxy"]
    assert proxy.requested_hosts == [
        ("service.test", source.server_port),
        ("secure.service.test", destination.server_port),
    ]


@pytest.mark.skipif(shutil.which("proxychains4") is None, reason="proxychains4 is not installed")
def test_proxychains4_cli_uses_proxy_dns_and_keeps_redirect_tls_inside_chain(
    mtls_material: dict[str, Path],
    tmp_path: Path,
) -> None:
    destination = _HttpServer(_GrafanaDestinationHandler)
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.load_cert_chain(mtls_material["server_cert"], mtls_material["server_key"])
    destination.socket = tls_context.wrap_socket(destination.socket, server_side=True)
    source = _HttpServer(_SourceHandler)
    source.redirect_url = f"https://secure.service.test:{destination.server_port}/api/health"
    proxy = _TunnelProxy("socks5h")
    config = tmp_path / "proxychains.conf"
    config.write_text(
        "strict_chain\nproxy_dns\nquiet_mode\ntcp_read_time_out 5000\ntcp_connect_time_out 3000\n"
        f"[ProxyList]\nsocks5 127.0.0.1 {proxy.server_address[1]}\n",
        encoding="utf-8",
    )

    with _running(destination), _running(source), _running(proxy):
        completed = subprocess.run(
            [
                str(shutil.which("proxychains4")),
                "-q",
                "-f",
                str(config),
                sys.executable,
                "redposture.py",
                "grafana",
                "-t",
                f"http://service.test:{source.server_port}",
                "--timeout",
                "2",
                "--retries",
                "0",
                "--format",
                "json",
            ],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    records = []
    for line in completed.stdout.splitlines():
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if payload.get("type") != "summary":
            records.append(payload)
    assert len(records) == 1
    assert records[0]["is_grafana"] is True
    assert records[0]["server_version"] == "11.0.0"
    assert ("service.test", source.server_port) in proxy.requested_hosts
    assert ("secure.service.test", destination.server_port) in proxy.requested_hosts
