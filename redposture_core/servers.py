"""Server runtime and protocol handlers for listener emulation."""

from __future__ import annotations

import json
import os
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from .constants import (
    BLACKBOX_COMPAT_MODULES,
    BLACKBOX_DEFAULT_MODULE,
    DEFAULT_CERT_PEM,
    DEFAULT_KEY_PEM,
    POSTGRES_AUTH_CLEAR_TEXT,
    POSTGRES_SSL_REQUEST_CODE,
)
from .logger import AttemptLogger
from .utils import (
    is_http_inline_command,
    is_http_request_prefix,
    parse_basic_auth,
    parse_proxmox_api_token_auth,
    prometheus_label_escape,
    safe_decode,
)


def server_listen_port(server: Any) -> int:
    """Return the listening port from a socketserver instance's address tuple."""
    return int(server.server_address[1])


def build_http_ok_response(body: bytes = b"ok\n") -> bytes:
    return (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"Connection: close\r\n"
        b"\r\n" + body
    )


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("unexpected EOF")
        data += chunk
    return data


def parse_postgres_startup_params(payload: bytes) -> dict[str, str]:
    fields: dict[str, str] = {}
    parts = payload.split(b"\x00")
    if parts and parts[-1] == b"":
        parts = parts[:-1]
    for idx in range(0, len(parts) - 1, 2):
        key = safe_decode(parts[idx])
        value = safe_decode(parts[idx + 1])
        if key is not None and value is not None:
            fields[key] = value
    return fields


def encode_pg_error(user: str | None) -> bytes:
    msg_user = user if user else "unknown"
    payload = b"SERROR\x00C28P01\x00" + f'Mpassword authentication failed for user "{msg_user}"\x00'.encode() + b"\x00"
    return b"E" + (len(payload) + 4).to_bytes(4, "big") + payload


class ThreadingTCPReuseServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


# C4 fix: hard cap on the number of bytes any listener will read from a request
# body. Real probes send at most a few kilobytes; anything above this is either
# a slow-client DoS or a probe smuggling in an oversized payload. Keeps the
# blackbox / proxmox handlers from committing to a multi-GB Content-Length.
MAX_LISTENER_REQUEST_BODY_BYTES = 1 * 1024 * 1024


class ThreadingHTTPReuseServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True
    # C4 fix: BaseHTTPServer never sets a per-request socket timeout, so a slow
    # client that opens a connection and never finishes headers permanently
    # parks a handler thread — process leaks threads until server_close().
    timeout = 30

    def process_request(  # type: ignore[override]  # narrowed to socket.socket by intent
        self, request: socket.socket, client_address: Any
    ) -> None:
        # Apply the timeout to the accepted socket immediately so BaseHTTPRequestHandler's
        # rfile/wfile inherit it. Without this the class-level `timeout` only
        # applies to the accept() call, not to the handler socket.
        try:
            request.settimeout(self.timeout)
        except OSError:
            pass
        super().process_request(request, client_address)


def _read_bounded_body(rfile: Any, content_length: int, *, cap: int = MAX_LISTENER_REQUEST_BODY_BYTES) -> bytes:
    """Read at most `cap` bytes of the body, ignoring the advertised length beyond that.

    C5 fix: `self.rfile.read(Content-Length)` used to trust whatever the client
    advertised, so a 2 GB Content-Length would try to buffer 2 GB (or block
    forever on a slow client without a socket timeout). Now we clamp reads and
    silently drop the rest.
    """
    if content_length <= 0:
        return b""
    return rfile.read(min(int(content_length), max(0, int(cap))))


class PostgresListenerHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        sock = self.request
        assert isinstance(sock, socket.socket)

        sock.settimeout(20)
        remote = self.client_address
        listen_port = server_listen_port(self.server)
        params: dict[str, str] = {}
        user: str | None = None

        try:
            first = recv_exact(sock, 8)
            if is_http_request_prefix(first):
                response = build_http_ok_response()
                sock.sendall(response)
                self.server.attempt_logger.log(  # type: ignore[attr-defined]
                    "postgres",
                    remote,
                    protocol="http",
                    listen_port=listen_port,
                )
                return

            first_len = int.from_bytes(first[:4], "big")
            first_code = int.from_bytes(first[4:8], "big")

            if first_len < 8:
                return

            if first_code == POSTGRES_SSL_REQUEST_CODE:
                if self.server.postgres_tls:  # type: ignore[attr-defined]
                    sock.sendall(b"S")
                    sock = self.server.ssl_context.wrap_socket(sock, server_side=True)  # type: ignore[attr-defined]
                    sock.settimeout(20)
                else:
                    sock.sendall(b"N")

                startup_len_raw = recv_exact(sock, 4)
                startup_len = int.from_bytes(startup_len_raw, "big")
                startup_body = recv_exact(sock, startup_len - 4)
                startup = startup_len_raw + startup_body
            else:
                startup = first + recv_exact(sock, first_len - 8)

            if len(startup) < 8:
                return

            params = parse_postgres_startup_params(startup[8:])
            user = params.get("user")

            sock.sendall(b"R" + (8).to_bytes(4, "big") + POSTGRES_AUTH_CLEAR_TEXT.to_bytes(4, "big"))

            msg_type = recv_exact(sock, 1)
            length = int.from_bytes(recv_exact(sock, 4), "big")
            if length < 4:
                return
            body = recv_exact(sock, length - 4)

            if msg_type != b"p":
                return

            password_bytes = body[:-1] if body.endswith(b"\x00") else body
            password = safe_decode(password_bytes) or ""

            self.server.attempt_logger.log(  # type: ignore[attr-defined]
                "postgres",
                remote,
                username=user,
                password=password,
                startup=params,
                listen_port=listen_port,
            )

            sock.sendall(encode_pg_error(user))
        except (TimeoutError, ConnectionError, ssl.SSLError):
            return
        finally:
            try:
                sock.close()
            except OSError:
                pass


def make_postgres_server(
    bind: str,
    port: int,
    logger: AttemptLogger,
    postgres_tls: bool,
    ssl_context: ssl.SSLContext | None,
) -> ThreadingTCPReuseServer:
    server = ThreadingTCPReuseServer((bind, port), PostgresListenerHandler)
    server.attempt_logger = logger  # type: ignore[attr-defined]
    server.postgres_tls = postgres_tls  # type: ignore[attr-defined]
    server.ssl_context = ssl_context  # type: ignore[attr-defined]
    return server


def read_redis_cmd(rfile: Any) -> list[str] | None:
    line = rfile.readline(65536)
    if not line:
        return None
    if not line.endswith(b"\r\n"):
        return []

    line = line[:-2]
    if not line:
        return []

    if line.startswith(b"*"):
        try:
            argc = int(line[1:])
        except ValueError:
            return []
        if argc < 1 or argc > 128:
            return []

        result: list[str] = []
        for _ in range(argc):
            marker = rfile.readline(65536)
            if not marker or not marker.endswith(b"\r\n") or not marker.startswith(b"$"):
                return []
            try:
                item_len = int(marker[1:-2])
            except ValueError:
                return []
            if item_len < 0 or item_len > 1024 * 1024:
                return []
            data = rfile.read(item_len + 2)
            if len(data) != item_len + 2 or not data.endswith(b"\r\n"):
                return []
            result.append(data[:-2].decode("utf-8", errors="replace"))
        return result

    return line.decode("utf-8", errors="replace").split()


def parse_redis_auth(command: list[str]) -> tuple[str | None, str | None]:
    if not command:
        return None, None
    op = command[0].upper()

    if op == "AUTH":
        if len(command) == 2:
            return "default", command[1]
        if len(command) >= 3:
            return command[1], command[2]

    if op == "HELLO":
        upper = [item.upper() for item in command]
        if "AUTH" in upper:
            idx = upper.index("AUTH")
            if idx + 2 < len(command):
                return command[idx + 1], command[idx + 2]

    return None, None


class RedisListenerHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.connection.settimeout(20)
        remote = self.client_address
        listen_port = server_listen_port(self.server)

        while True:
            try:
                command = read_redis_cmd(self.rfile)
            except TimeoutError:
                break

            if command is None:
                break
            if not command:
                self.wfile.write(b"-ERR protocol error\r\n")
                self.wfile.flush()
                continue

            op = command[0].upper()
            if is_http_inline_command(command):
                self.server.attempt_logger.log(  # type: ignore[attr-defined]
                    "redis",
                    remote,
                    protocol="http",
                    listen_port=listen_port,
                )
                self.wfile.write(build_http_ok_response())
                self.wfile.flush()
                break

            username, password = parse_redis_auth(command)
            if password is not None:
                self.server.attempt_logger.log(  # type: ignore[attr-defined]
                    "redis",
                    remote,
                    username=username,
                    password=password,
                    command=command[0],
                    listen_port=listen_port,
                )
                self.wfile.write(b"-WRONGPASS invalid username-password pair or user is disabled.\r\n")
            else:
                # A connection that speaks RESP is already callback evidence,
                # even when the exporter never sends AUTH.  Previously PING
                # and INFO were answered but omitted from callback stats,
                # producing a false negative in --with-listen mode.
                self.server.attempt_logger.log(  # type: ignore[attr-defined]
                    "redis",
                    remote,
                    command=command[0],
                    listen_port=listen_port,
                )
                if op == "PING":
                    self.wfile.write(b"+PONG\r\n")
                elif op == "QUIT":
                    self.wfile.write(b"+OK\r\n")
                    self.wfile.flush()
                    break
                else:
                    self.wfile.write(b"-NOAUTH Authentication required.\r\n")
            self.wfile.flush()


def make_redis_server(bind: str, port: int, logger: AttemptLogger) -> ThreadingTCPReuseServer:
    server = ThreadingTCPReuseServer((bind, port), RedisListenerHandler)
    server.attempt_logger = logger  # type: ignore[attr-defined]
    return server


def make_proxmox_handler(logger: AttemptLogger) -> type[BaseHTTPRequestHandler]:
    class ProxmoxListenerHandler(BaseHTTPRequestHandler):
        server_version = "pve-api-daemon/3.0"

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _send_json(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _client_addr(self) -> tuple[str, int]:
            return self.client_address[0], self.client_address[1]

        def _listen_port(self) -> int:
            return server_listen_port(self.server)

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path in {"/", "/index.html"}:
                html = (
                    b"<html><head><title>Proxmox VE Login</title></head>"
                    b"<body><h1>Proxmox VE</h1><p>API endpoint available.</p></body></html>"
                )
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(html)))
                self.end_headers()
                self.wfile.write(html)
                return

            if parsed.path.startswith("/api2/"):
                auth_header = self.headers.get("Authorization")
                basic_user, basic_pass = parse_basic_auth(self.headers.get("Authorization"))
                token_id, token_secret = parse_proxmox_api_token_auth(auth_header)
                auth_scheme: str | None = "pveapitoken" if token_id is not None else None
                username = basic_user if basic_user is not None else token_id
                password = basic_pass if basic_pass is not None else token_secret
                logger.log(
                    "proxmox",
                    self._client_addr(),
                    username=username,
                    password=password,
                    auth_scheme=auth_scheme,
                    user_agent=self.headers.get("User-Agent"),
                    path=parsed.path,
                    method="GET",
                    listen_port=self._listen_port(),
                )
                self._send_json(HTTPStatus.UNAUTHORIZED, {"data": None, "message": "authentication failure"})
                return

            self._send_json(HTTPStatus.NOT_FOUND, {"data": None, "message": "not found"})

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            length = int(self.headers.get("Content-Length", "0") or "0")
            # C5 fix: reject oversized/slow bodies instead of allocating whatever
            # Content-Length claims — a malicious/misconfigured client could pin
            # a handler thread and drive memory pressure.
            if length > MAX_LISTENER_REQUEST_BODY_BYTES:
                self.send_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
                return
            body = _read_bounded_body(self.rfile, length)
            content_type = (self.headers.get("Content-Type") or "").lower()

            fields: dict[str, Any] = {}
            if "application/json" in content_type:
                try:
                    parsed_json = json.loads(body.decode("utf-8", errors="replace"))
                    if isinstance(parsed_json, dict):
                        fields = parsed_json
                except json.JSONDecodeError:
                    fields = {}
            else:
                form = parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True)
                fields = {k: v[0] for k, v in form.items()}

            username = fields.get("username")
            password = fields.get("password")

            auth_header = self.headers.get("Authorization")
            basic_user, basic_pass = parse_basic_auth(auth_header)
            token_id, token_secret = parse_proxmox_api_token_auth(auth_header)
            auth_scheme: str | None = "pveapitoken" if token_id is not None else None
            if username is None and basic_user is not None:
                username = basic_user
            if password is None and basic_pass is not None:
                password = basic_pass
            if username is None and token_id is not None:
                username = token_id
            if password is None and token_secret is not None:
                password = token_secret

            if parsed.path.rstrip("/") in {"/api2/json/access/ticket", "/api2/extjs/access/ticket"}:
                logger.log(
                    "proxmox",
                    self._client_addr(),
                    username=username,
                    password=password,
                    auth_scheme=auth_scheme,
                    user_agent=self.headers.get("User-Agent"),
                    path=parsed.path,
                    listen_port=self._listen_port(),
                )
                self._send_json(HTTPStatus.UNAUTHORIZED, {"data": None, "message": "authentication failure"})
                return

            self._send_json(HTTPStatus.NOT_FOUND, {"data": None, "message": "not found"})

    return ProxmoxListenerHandler


def make_blackbox_handler(logger: AttemptLogger) -> type[BaseHTTPRequestHandler]:
    class BlackboxListenerHandler(BaseHTTPRequestHandler):
        server_version = "blackbox_exporter"

        def log_message(self, format: str, *args: Any) -> None:
            return

        def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
            # BaseHTTPRequestHandler may reject malformed HTTP before do_GET/do_POST.
            logger.log(
                "blackbox",
                self._client_addr(),
                method="PARSE_ERROR",
                status=code,
                requestline=getattr(self, "requestline", None),
                error_message=message,
                user_agent=self.headers.get("User-Agent") if hasattr(self, "headers") else None,
                listen_port=self._listen_port(),
            )
            super().send_error(code, message, explain)

        def _text(self, status: int, content: str, headers: dict[str, str] | None = None) -> None:
            body = content.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            if headers:
                for key, value in headers.items():
                    self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def _client_addr(self) -> tuple[str, int]:
            return self.client_address[0], self.client_address[1]

        def _listen_port(self) -> int:
            return server_listen_port(self.server)

        def _extract_probe_params(self, parsed_path: Any) -> tuple[str | None, str]:
            query = parse_qs(parsed_path.query)
            target = query.get("target", [None])[0]
            module = query.get("module", [None])[0]
            if not module:
                module = BLACKBOX_DEFAULT_MODULE
            if module not in BLACKBOX_COMPAT_MODULES:
                module = BLACKBOX_DEFAULT_MODULE
            return target, module

        def _extract_exporter_params(self, parsed_path: Any) -> dict[str, str | None]:
            query = parse_qs(parsed_path.query)
            return {
                "target": query.get("target", [None])[0],
                "job": query.get("job", [None])[0],
                "instance": query.get("instance", [None])[0],
                "exporter": query.get("exporter", [None])[0],
                "module": query.get("module", [None])[0],
            }

        def _metrics_labels(self, labels: dict[str, str | None]) -> str:
            parts: list[str] = []
            for key, value in labels.items():
                if value:
                    parts.append(f'{key}="{prometheus_label_escape(value)}"')
            if not parts:
                return ""
            return "{" + ",".join(parts) + "}"

        def _log_probe(self, parsed_path: Any, target: str | None, module: str, method: str, body_len: int = 0) -> None:
            username, password = parse_basic_auth(self.headers.get("Authorization"))

            logger.log(
                "blackbox",
                self._client_addr(),
                method=method,
                path=parsed_path.path,
                query=parsed_path.query,
                content_length=body_len if body_len > 0 else None,
                target=target,
                module=module,
                username=username,
                password=password,
                user_agent=self.headers.get("User-Agent"),
                listen_port=self._listen_port(),
            )

        def _log_exporter_metrics(self, parsed_path: Any, method: str, body_len: int = 0) -> None:
            username, password = parse_basic_auth(self.headers.get("Authorization"))
            labels = self._extract_exporter_params(parsed_path)
            logger.log(
                "blackbox",
                self._client_addr(),
                endpoint_type="exporter_metrics",
                method=method,
                path=parsed_path.path,
                query=parsed_path.query,
                content_length=body_len if body_len > 0 else None,
                target=labels["target"],
                job=labels["job"],
                instance=labels["instance"],
                exporter=labels["exporter"],
                module=labels["module"],
                username=username,
                password=password,
                user_agent=self.headers.get("User-Agent"),
                listen_port=self._listen_port(),
            )

        def _log_non_probe(self, parsed_path: Any, method: str, body_len: int = 0) -> None:
            username, password = parse_basic_auth(self.headers.get("Authorization"))
            logger.log(
                "blackbox",
                self._client_addr(),
                method=method,
                path=parsed_path.path,
                query=parsed_path.query,
                content_length=body_len if body_len > 0 else None,
                username=username,
                password=password,
                user_agent=self.headers.get("User-Agent"),
                listen_port=self._listen_port(),
            )

        def _probe_metrics(self, target: str | None, module: str) -> str:
            lines = [
                "# HELP probe_success Displays whether or not the probe was a success",
                "# TYPE probe_success gauge",
                "probe_success 0",
                "# HELP probe_duration_seconds Returns how long the probe took to complete in seconds",
                "# TYPE probe_duration_seconds gauge",
                "probe_duration_seconds 0.001",
                "# HELP probe_module_info Selected probe module",
                "# TYPE probe_module_info gauge",
                f'probe_module_info{{module="{prometheus_label_escape(module)}"}} 1',
            ]
            if target:
                lines.extend(
                    [
                        "# HELP probe_target_info Target passed to /probe",
                        "# TYPE probe_target_info gauge",
                        f'probe_target_info{{target="{prometheus_label_escape(target)}"}} 1',
                    ]
                )
            return "\n".join(lines) + "\n"

        def _exporter_metrics(self, parsed_path: Any) -> str:
            labels = self._extract_exporter_params(parsed_path)
            sample_labels = self._metrics_labels(
                {
                    "target": labels["target"],
                    "job": labels["job"],
                    "instance": labels["instance"],
                    "exporter": labels["exporter"],
                }
            )
            lines = [
                "# HELP exporter_redposture_up Synthetic exporter endpoint health.",
                "# TYPE exporter_redposture_up gauge",
                f"exporter_redposture_up{sample_labels} 1",
                "# HELP exporter_redposture_requests_total Synthetic request counter.",
                "# TYPE exporter_redposture_requests_total counter",
                f"exporter_redposture_requests_total{sample_labels} 1",
                "# HELP blackbox_exporter_build_info Build information",
                "# TYPE blackbox_exporter_build_info gauge",
                'blackbox_exporter_build_info{version="0.0.0-redposture"} 1',
            ]
            return "\n".join(lines) + "\n"

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/probe":
                target, module = self._extract_probe_params(parsed)
                self._log_probe(parsed, target, module, method="GET")
                metrics = self._probe_metrics(target, module)
                self._text(HTTPStatus.OK, metrics, headers={"X-RedPosture": "1"})
                return

            if parsed.path == "/metrics":
                self._log_exporter_metrics(parsed, method="GET")
                metrics = self._exporter_metrics(parsed)
                self._text(HTTPStatus.OK, metrics, headers={"X-RedPosture": "1"})
                return

            self._log_non_probe(parsed, method="GET")
            self._text(HTTPStatus.OK, "blackbox_exporter\n", headers={"X-RedPosture": "1"})

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            body_len = int(self.headers.get("Content-Length", "0") or "0")
            # C5 fix: cap request bodies. See MAX_LISTENER_REQUEST_BODY_BYTES.
            if body_len > MAX_LISTENER_REQUEST_BODY_BYTES:
                self.send_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
                return
            _ = _read_bounded_body(self.rfile, body_len)

            if parsed.path == "/probe":
                target, module = self._extract_probe_params(parsed)
                self._log_probe(parsed, target, module, method="POST", body_len=body_len)
                metrics = self._probe_metrics(target, module)
                self._text(HTTPStatus.OK, metrics, headers={"X-RedPosture": "1"})
                return

            if parsed.path == "/metrics":
                self._log_exporter_metrics(parsed, method="POST", body_len=body_len)
                metrics = self._exporter_metrics(parsed)
                self._text(HTTPStatus.OK, metrics, headers={"X-RedPosture": "1"})
                return

            self._log_non_probe(parsed, method="POST", body_len=body_len)
            self._text(HTTPStatus.OK, "blackbox_exporter\n", headers={"X-RedPosture": "1"})

    return BlackboxListenerHandler


def make_http_server(
    bind: str,
    port: int,
    handler: type[BaseHTTPRequestHandler],
    ssl_context: ssl.SSLContext | None = None,
) -> ThreadingHTTPReuseServer:
    server = ThreadingHTTPReuseServer((bind, port), handler)
    if ssl_context is not None:
        server.socket = ssl_context.wrap_socket(server.socket, server_side=True)
    return server


def build_ssl_context(cert_path: str, key_path: str) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return context


def _generate_self_signed_cert(cert_path: str, key_path: str) -> None:
    command = [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-sha256",
        "-days",
        "365",
        "-subj",
        "/CN=redposture-local",
        "-keyout",
        key_path,
        "-out",
        cert_path,
    ]
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        raise ValueError(f"failed to run openssl for self-signed cert generation: {exc}") from exc

    if completed.returncode != 0:
        details = (completed.stderr or completed.stdout or "").strip()
        if details:
            raise ValueError(f"openssl failed to generate self-signed cert: {details}")
        raise ValueError("openssl failed to generate self-signed cert")


def write_self_signed_cert_files(cert_path: str, key_path: str, *, force: bool = False) -> tuple[str, str]:
    cert_abs = os.path.abspath(cert_path)
    key_abs = os.path.abspath(key_path)

    if not cert_abs or not key_abs:
        raise ValueError("both cert path and key path must be set")
    if cert_abs == key_abs:
        raise ValueError("cert path and key path must be different files")

    for path, kind in ((cert_abs, "cert"), (key_abs, "key")):
        if os.path.isdir(path):
            raise ValueError(f"{kind} path points to a directory: {path}")
        parent = os.path.dirname(path) or "."
        os.makedirs(parent, exist_ok=True)
        if os.path.exists(path) and not force:
            raise ValueError(f"{kind} file already exists: {path} (use --force to overwrite)")

    _generate_self_signed_cert(cert_abs, key_abs)
    return cert_abs, key_abs


def prepare_cert_files(
    cert_path: str | None,
    key_path: str | None,
    generate_local_selfcert: bool = False,
) -> tuple[str, str, str | None]:
    if bool(cert_path) != bool(key_path):
        raise ValueError("both --cert-file and --key-file must be set together")

    if cert_path and key_path:
        return cert_path, key_path, None

    tmp_dir = tempfile.mkdtemp(prefix="redposture-certs-")
    cert = os.path.join(tmp_dir, "cert.pem")
    key = os.path.join(tmp_dir, "key.pem")

    # Default to a freshly generated ephemeral self-signed certificate so the
    # listener never relies on the publicly-known bundled private key. Fall back
    # to the bundled PEM only when local generation is unavailable (e.g. openssl
    # is missing) and a caller has not asked to force generation.
    try:
        _generate_self_signed_cert(cert, key)
        return cert, key, tmp_dir
    except (ValueError, OSError):
        if generate_local_selfcert:
            raise

    with open(cert, "w", encoding="utf-8") as cert_fh:
        cert_fh.write(DEFAULT_CERT_PEM)
    with open(key, "w", encoding="utf-8") as key_fh:
        key_fh.write(DEFAULT_KEY_PEM)
    return cert, key, tmp_dir


@dataclass
class RunningServer:
    name: str
    bind: str
    port: int
    server: Any
    thread: threading.Thread
    tls: bool


def start_server(name: str, bind: str, port: int, server: Any, tls: bool = False) -> RunningServer:
    thread = threading.Thread(target=server.serve_forever, daemon=True, name=f"{name}-server")
    thread.start()
    return RunningServer(name=name, bind=bind, port=port, server=server, thread=thread, tls=tls)
