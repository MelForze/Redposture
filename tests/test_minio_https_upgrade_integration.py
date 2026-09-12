from __future__ import annotations

import socket
import socketserver
import ssl
import subprocess
import sys
import threading
from pathlib import Path
from typing import cast

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def self_signed_certificate(tmp_path: Path) -> tuple[Path, Path]:
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        check=True,
        capture_output=True,
        timeout=15,
    )
    return cert, key


class DualProtocolMinioServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        handler: type[socketserver.BaseRequestHandler],
        tls_context: ssl.SSLContext,
    ) -> None:
        super().__init__(address, handler)
        self.tls_context = tls_context
        self.plaintext_requests = 0
        self.tls_requests: list[tuple[str, str]] = []


class DualProtocolMinioHandler(socketserver.BaseRequestHandler):
    @staticmethod
    def _read_request(conn: socket.socket) -> tuple[str, dict[str, str]]:
        data = bytearray()
        while b"\r\n\r\n" not in data and len(data) < 64 * 1024:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data.extend(chunk)
        lines = bytes(data).decode("iso-8859-1", errors="replace").split("\r\n")
        request = lines[0].split(" ", 2) if lines else []
        path = request[1] if len(request) > 1 else "/"
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line or ":" not in line:
                continue
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
        return path, headers

    @staticmethod
    def _reply(conn: socket.socket, status: int, body: bytes, headers: dict[str, str] | None = None) -> None:
        reasons = {200: "OK", 400: "Bad Request", 403: "Forbidden"}
        response_headers = {
            "Content-Length": str(len(body)),
            "Connection": "close",
            **(headers or {}),
        }
        head = [f"HTTP/1.1 {status} {reasons[status]}"]
        head.extend(f"{name}: {value}" for name, value in response_headers.items())
        conn.sendall(("\r\n".join(head) + "\r\n\r\n").encode("ascii") + body)

    def handle(self) -> None:
        server = cast(DualProtocolMinioServer, self.server)
        first = self.request.recv(1, socket.MSG_PEEK)
        if first != b"\x16":
            self._read_request(self.request)
            server.plaintext_requests += 1
            self._reply(self.request, 400, b"Client sent an HTTP request to an HTTPS server.")
            return

        try:
            conn = server.tls_context.wrap_socket(self.request, server_side=True)
        except ssl.SSLError:
            return
        with conn:
            raw_path, headers = self._read_request(conn)
            path = raw_path.partition("?")[0]
            authorization = headers.get("authorization", "")
            server.tls_requests.append((path, authorization))
            if path == "/minio/health/live":
                self._reply(conn, 200, b"", {"Server": "MinIO"})
            elif path == "/" and authorization and "Credential=minioadmin/" in authorization:
                self._reply(conn, 200, b"<ListAllMyBucketsResult><Buckets/></ListAllMyBucketsResult>")
            elif path == "/" and authorization:
                self._reply(
                    conn,
                    403,
                    b"<Error><Code>InvalidAccessKeyId</Code></Error>",
                    {"Server": "MinIO"},
                )
            else:
                self._reply(conn, 403, b"<Error><Code>AccessDenied</Code></Error>", {"Server": "MinIO"})


def test_http_tls_required_upgrades_to_self_signed_https_for_defcreds(
    self_signed_certificate: tuple[Path, Path],
) -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(*self_signed_certificate)
    server = DualProtocolMinioServer(("127.0.0.1", 0), DualProtocolMinioHandler, context)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    target = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        result = subprocess.run(
            [
                sys.executable,
                "redposture.py",
                "minio",
                "-t",
                target,
                "--defcreds",
                "--retries",
                "0",
                "--timeout",
                "2",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "minioadmin:minioadmin" in result.stdout
        assert "S3 API:unverified" not in result.stdout
        assert "credential verification unavailable" not in result.stdout
        assert server.plaintext_requests == 1
        assert any(authorization for _path, authorization in server.tls_requests)
        assert any("Credential=minioadmin/" in authorization for _path, authorization in server.tls_requests)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
