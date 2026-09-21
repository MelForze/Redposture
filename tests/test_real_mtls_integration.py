"""Real TLS handshakes for shared HTTP and native-protocol transports."""

from __future__ import annotations

import socket
import socketserver
import ssl
import threading
from collections.abc import Iterator
from contextlib import closing, contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import cast

import pytest

from redposture_core.clients import grpc, kafka, zookeeper
from redposture_core.clients.http_session import HttpSessionPool


class _QuietTlsHttpServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, _request: object, _client_address: object) -> None:
        return


class _OkHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return


def _server_context(material: dict[str, Path]) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(material["server_cert"], material["server_key"])
    context.load_verify_locations(cafile=str(material["ca_cert"]))
    context.verify_mode = ssl.CERT_REQUIRED
    context.set_alpn_protocols(["h2", "http/1.1"])
    return context


@contextmanager
def _serve_mtls_http(material: dict[str, Path]) -> Iterator[int]:
    server = _QuietTlsHttpServer(("127.0.0.1", 0), _OkHandler)
    server.socket = _server_context(material).wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        assert not thread.is_alive()


def _request(port: int, material: dict[str, Path], *, client: bool, ca: str, host: str):
    with closing(
        HttpSessionPool(
            timeout=0.5,
            ca_file=str(material[ca]),
            cert_file=str(material["client_cert"]) if client else None,
            key_file=str(material["client_key"]) if client else None,
        )
    ) as pool:
        return pool.request("GET", f"https://{host}:{port}/", retries=0)


def test_real_mtls_accepts_valid_client_identity(mtls_material: dict[str, Path]) -> None:
    with _serve_mtls_http(mtls_material) as port:
        response = _request(port, mtls_material, client=True, ca="ca_cert", host="localhost")

    assert response.status == 200
    assert response.error is None
    assert response.body == b'{"ok":true}'


def test_real_mtls_rejects_missing_client_certificate(mtls_material: dict[str, Path]) -> None:
    with _serve_mtls_http(mtls_material) as port:
        response = _request(port, mtls_material, client=False, ca="ca_cert", host="localhost")

    assert response.status == 0
    assert response.error


def test_real_mtls_rejects_wrong_ca(mtls_material: dict[str, Path]) -> None:
    with _serve_mtls_http(mtls_material) as port:
        response = _request(port, mtls_material, client=True, ca="wrong_ca_cert", host="localhost")

    assert response.status == 0
    assert "certificate" in str(response.error).casefold()


def test_real_mtls_rejects_hostname_mismatch(mtls_material: dict[str, Path]) -> None:
    with _serve_mtls_http(mtls_material) as port:
        response = _request(port, mtls_material, client=True, ca="ca_cert", host="127.0.0.1")

    assert response.status == 0
    assert any(marker in str(response.error).casefold() for marker in ("hostname", "ip address", "certificate"))


class _TlsProbeServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, material: dict[str, Path]) -> None:
        super().__init__(("127.0.0.1", 0), _TlsProbeHandler)
        self.context = _server_context(material)
        self.peer_seen = threading.Event()

    def handle_error(self, _request: object, _client_address: object) -> None:
        return


class _TlsProbeHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server = cast(_TlsProbeServer, self.server)
        try:
            wrapped = server.context.wrap_socket(cast(socket.socket, self.request), server_side=True)
        except ssl.SSLError:
            return
        with wrapped:
            if wrapped.getpeercert():
                server.peer_seen.set()


@pytest.mark.parametrize("transport", ["kafka", "zookeeper", "grpc"])
def test_native_transports_present_real_client_certificate(
    mtls_material: dict[str, Path],
    transport: str,
) -> None:
    server = _TlsProbeServer(mtls_material)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    ca = str(mtls_material["ca_cert"])
    cert = str(mtls_material["client_cert"])
    key = str(mtls_material["client_key"])
    sock: socket.socket | None = None
    try:
        if transport == "kafka":
            sock, mode = kafka.open_kafka_socket(
                "localhost",
                server.server_address[1],
                1.0,
                use_tls=True,
                tls_config=kafka.KafkaTlsConfig(ca_file=ca, cert_file=cert, key_file=key),
            )
            assert mode == "tls"
        elif transport == "zookeeper":
            sock = zookeeper._open_zk_socket(
                "localhost",
                server.server_address[1],
                1.0,
                transport="tls",
                config=zookeeper.ZkTransportConfig(
                    mode="tls",
                    ca_file=ca,
                    cert_file=cert,
                    key_file=key,
                ),
            )
        else:
            sock = grpc._open_grpc_socket(
                "localhost",
                server.server_address[1],
                1.0,
                use_tls=True,
                tls_config=grpc.GrpcTlsConfig(ca_file=ca, cert_file=cert, key_file=key),
            )
        assert server.peer_seen.wait(timeout=2)
    finally:
        if sock is not None:
            sock.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        assert not thread.is_alive()
