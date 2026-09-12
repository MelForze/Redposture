from __future__ import annotations

import json
import shutil
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
def kubeapi_self_signed_certificate(tmp_path: Path) -> tuple[Path, Path]:
    if shutil.which("openssl") is None:
        pytest.skip("openssl is required for the loopback TLS fixture")
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


class DualProtocolKubeApiServer(socketserver.ThreadingTCPServer):
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
        self.tls_requests: list[str] = []


class DualProtocolKubeApiHandler(socketserver.BaseRequestHandler):
    @staticmethod
    def _read_request(conn: socket.socket) -> str:
        data = bytearray()
        while b"\r\n\r\n" not in data and len(data) < 64 * 1024:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data.extend(chunk)
        first_line = bytes(data).decode("iso-8859-1", errors="replace").partition("\r\n")[0]
        parts = first_line.split(" ", 2)
        return parts[1] if len(parts) > 1 else "/"

    @staticmethod
    def _reply(conn: socket.socket, status: int, body: bytes, content_type: str = "text/plain") -> None:
        reasons = {200: "OK", 400: "Bad Request", 403: "Forbidden"}
        headers = {
            "Content-Length": str(len(body)),
            "Content-Type": content_type,
            "Connection": "close",
        }
        head = [f"HTTP/1.1 {status} {reasons[status]}"]
        head.extend(f"{name}: {value}" for name, value in headers.items())
        conn.sendall(("\r\n".join(head) + "\r\n\r\n").encode("ascii") + body)

    @staticmethod
    def _forbidden(resource: str) -> bytes:
        return json.dumps(
            {
                "kind": "Status",
                "apiVersion": "v1",
                "status": "Failure",
                "message": (f'{resource} is forbidden: User "system:anonymous" cannot list resource "{resource}"'),
                "reason": "Forbidden",
                "code": 403,
            },
            separators=(",", ":"),
        ).encode()

    def handle(self) -> None:
        server = cast(DualProtocolKubeApiServer, self.server)
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
            raw_path = self._read_request(conn)
            path = raw_path.partition("?")[0]
            server.tls_requests.append(path)
            if path == "/version":
                body = json.dumps(
                    {"major": "1", "minor": "27", "gitVersion": "v1.27.5"},
                    separators=(",", ":"),
                ).encode()
                self._reply(conn, 200, body, "application/json")
            elif path == "/api/v1/namespaces":
                self._reply(conn, 403, self._forbidden("namespaces"), "application/json")
            elif path == "/api/v1/pods":
                self._reply(conn, 403, self._forbidden("pods"), "application/json")
            else:
                self._reply(conn, 403, self._forbidden("resource"), "application/json")


def test_kubeapi_http_tls_required_upgrades_and_reuses_self_signed_https(
    kubeapi_self_signed_certificate: tuple[Path, Path],
) -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(*kubeapi_self_signed_certificate)
    server = DualProtocolKubeApiServer(("127.0.0.1", 0), DualProtocolKubeApiHandler, context)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    target = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        result = subprocess.run(
            [
                sys.executable,
                "redposture.py",
                "kubeapi",
                "-t",
                target,
                "--namespaces",
                "--pods",
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
        assert "Kubernetes API (anonymous access:limited) (version:v1.27.5)" in result.stdout
        assert "namespaces unavailable: anonymous access denied" in result.stdout
        assert "pods unavailable: anonymous access denied" in result.stdout
        assert "auth required:False" not in result.stdout
        assert server.plaintext_requests == 1
        assert server.tls_requests == ["/version", "/api/v1/namespaces", "/api/v1/pods"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
