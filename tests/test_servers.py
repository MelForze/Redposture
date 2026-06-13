from __future__ import annotations

import base64
import io
import json
import socket
import ssl
import threading
from types import SimpleNamespace

import pytest

from redposture_core import servers
from redposture_core.logger import AttemptLogger


class _RecvSocket:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = list(chunks)

    def recv(self, _size: int) -> bytes:
        if not self._chunks:
            return b""
        return self._chunks.pop(0)


def test_build_http_ok_response_contains_headers_and_body() -> None:
    payload = servers.build_http_ok_response(b"pong\n")
    assert payload.startswith(b"HTTP/1.1 200 OK\r\n")
    assert b"Content-Length: 5\r\n" in payload
    assert payload.endswith(b"\r\n\r\npong\n")


def test_recv_exact_reads_multiple_chunks_and_rejects_eof() -> None:
    assert servers.recv_exact(_RecvSocket([b"ab", b"cd"]), 4) == b"abcd"

    with pytest.raises(ConnectionError, match="unexpected EOF"):
        servers.recv_exact(_RecvSocket([b"ab"]), 4)


def test_parse_postgres_startup_params_and_encode_error() -> None:
    payload = b"user\x00postgres\x00database\x00appdb\x00\x00"
    assert servers.parse_postgres_startup_params(payload) == {"user": "postgres", "database": "appdb"}

    encoded = servers.encode_pg_error("alice")
    assert encoded.startswith(b"E")
    assert b'password authentication failed for user "alice"' in encoded


def test_read_redis_cmd_supports_resp_and_inline_and_invalid() -> None:
    resp = io.BytesIO(b"*2\r\n$4\r\nAUTH\r\n$6\r\nsecret\r\n")
    assert servers.read_redis_cmd(resp) == ["AUTH", "secret"]

    inline = io.BytesIO(b"PING\r\n")
    assert servers.read_redis_cmd(inline) == ["PING"]

    invalid = io.BytesIO(b"*1\r\n$2\r\nA")
    assert servers.read_redis_cmd(invalid) == []

    assert servers.read_redis_cmd(io.BytesIO(b"")) is None
    assert servers.read_redis_cmd(io.BytesIO(b"PING")) == []
    assert servers.read_redis_cmd(io.BytesIO(b"\r\n")) == []
    assert servers.read_redis_cmd(io.BytesIO(b"*x\r\n")) == []
    assert servers.read_redis_cmd(io.BytesIO(b"*0\r\n")) == []
    assert servers.read_redis_cmd(io.BytesIO(b"*129\r\n")) == []
    assert servers.read_redis_cmd(io.BytesIO(b"*1\r\n+PING\r\n")) == []
    assert servers.read_redis_cmd(io.BytesIO(b"*1\r\n$bad\r\n")) == []
    assert servers.read_redis_cmd(io.BytesIO(b"*1\r\n$-1\r\n")) == []
    assert servers.read_redis_cmd(io.BytesIO(b"*1\r\n$1048577\r\n")) == []
    assert servers.read_redis_cmd(io.BytesIO(b"*1\r\n$4\r\nPINGxx")) == []


def test_parse_redis_auth_variants() -> None:
    assert servers.parse_redis_auth(["AUTH", "secret"]) == ("default", "secret")
    assert servers.parse_redis_auth(["AUTH", "alice", "secret"]) == ("alice", "secret")
    assert servers.parse_redis_auth(["HELLO", "3", "AUTH", "bob", "pass"]) == ("bob", "pass")
    assert servers.parse_redis_auth(["PING"]) == (None, None)
    assert servers.parse_redis_auth([]) == (None, None)
    assert servers.parse_redis_auth(["HELLO", "3", "AUTH", "missing-password"]) == (None, None)


def test_write_self_signed_cert_files_and_prepare_cert_files(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    generated: list[tuple[str, str]] = []
    monkeypatch.setattr(
        servers,
        "_generate_self_signed_cert",
        lambda cert, key: generated.append((cert, key)) or None,
    )

    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_abs, key_abs = servers.write_self_signed_cert_files(str(cert_path), str(key_path))
    assert cert_abs == str(cert_path.resolve())
    assert key_abs == str(key_path.resolve())
    assert generated == [(str(cert_path.resolve()), str(key_path.resolve()))]
    cert_path.write_text("existing-cert", encoding="utf-8")
    key_path.write_text("existing-key", encoding="utf-8")

    with pytest.raises(ValueError, match="already exists"):
        servers.write_self_signed_cert_files(str(cert_path), str(key_path))

    returned_cert, returned_key, temp_dir = servers.prepare_cert_files(cert_abs, key_abs)
    assert (returned_cert, returned_key, temp_dir) == (cert_abs, key_abs, None)


def test_prepare_cert_files_bundled_and_generated_modes(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    temp_dir = tmp_path / "bundle"
    temp_dir.mkdir()
    monkeypatch.setattr(servers.tempfile, "mkdtemp", lambda prefix="": str(temp_dir))
    generated: list[tuple[str, str]] = []
    monkeypatch.setattr(
        servers,
        "_generate_self_signed_cert",
        lambda cert, key: generated.append((cert, key)) or None,
    )

    cert, key, created_dir = servers.prepare_cert_files(None, None, generate_local_selfcert=False)
    assert created_dir == str(temp_dir)
    assert "BEGIN CERTIFICATE" in open(cert, encoding="utf-8").read()
    assert "BEGIN PRIVATE KEY" in open(key, encoding="utf-8").read()

    cert2, key2, created_dir2 = servers.prepare_cert_files(None, None, generate_local_selfcert=True)
    assert created_dir2 == str(temp_dir)
    assert generated == [(cert2, key2)]

    with pytest.raises(ValueError, match="both --cert-file and --key-file"):
        servers.prepare_cert_files(str(tmp_path / "only-cert.pem"), None)


def test_start_server_starts_daemon_thread() -> None:
    started: list[bool] = []

    class _DummyServer:
        def serve_forever(self) -> None:
            started.append(True)

    running = servers.start_server("redis", "127.0.0.1", 6379, _DummyServer(), tls=False)
    running.thread.join(timeout=1.0)

    assert isinstance(running.thread, threading.Thread)
    assert running.thread.daemon is True
    assert started == [True]


def test_postgres_listener_handler_logs_http_probe(tmp_path) -> None:
    logger = AttemptLogger()
    log_path = tmp_path / "postgres-http.log"
    logger.set_text_output(str(log_path))
    server = SimpleNamespace(
        server_address=("127.0.0.1", 15432),
        attempt_logger=logger,
        postgres_tls=False,
    )
    left, right = socket.socketpair()
    try:
        right.sendall(b"GET / HT")
        servers.PostgresListenerHandler(left, ("127.0.0.1", 54321), server)
        response = right.recv(4096)
    finally:
        right.close()

    events = logger.get_trigger_callback_events()
    assert b"HTTP/1.1 200 OK" in response
    assert events == []
    attempts = log_path.read_text(encoding="utf-8")
    assert "[INFO] [Postgres]" in attempts
    assert "protocol=http" in attempts


def test_postgres_listener_handler_logs_cleartext_password(tmp_path) -> None:
    logger = AttemptLogger()
    log_path = tmp_path / "postgres-auth.log"
    logger.set_text_output(str(log_path))
    server = SimpleNamespace(
        server_address=("127.0.0.1", 15432),
        attempt_logger=logger,
        postgres_tls=False,
    )
    left, right = socket.socketpair()
    params = b"user\x00postgres\x00database\x00appdb\x00\x00"
    startup = (8 + len(params)).to_bytes(4, "big") + (196608).to_bytes(4, "big") + params
    password_body = b"secret\x00"
    password_message = b"p" + (4 + len(password_body)).to_bytes(4, "big") + password_body
    try:
        right.sendall(startup + password_message)
        servers.PostgresListenerHandler(left, ("127.0.0.1", 54321), server)
        response = right.recv(4096)
    finally:
        right.close()

    attempts = log_path.read_text(encoding="utf-8")
    assert b'password authentication failed for user "postgres"' in response
    assert "user=postgres" in attempts
    assert "pass=secret" in attempts
    assert "'database': 'appdb'" in attempts


def test_redis_listener_handler_logs_auth_and_http_probe(tmp_path) -> None:
    logger = AttemptLogger()
    log_path = tmp_path / "redis.log"
    logger.set_text_output(str(log_path))
    server = SimpleNamespace(
        server_address=("127.0.0.1", 16379),
        attempt_logger=logger,
    )

    # AUTH flow
    left, right = socket.socketpair()
    try:
        right.sendall(b"*2\r\n$4\r\nAUTH\r\n$6\r\nsecret\r\n*1\r\n$4\r\nQUIT\r\n")
        servers.RedisListenerHandler(left, ("127.0.0.1", 54321), server)
        response = right.recv(4096)
    finally:
        right.close()

    attempts = log_path.read_text(encoding="utf-8")
    assert b"-WRONGPASS invalid username-password pair" in response
    assert "[CRED] [REDIS]" in attempts
    assert "pass=secret" in attempts

    # HTTP inline probe
    left, right = socket.socketpair()
    try:
        right.sendall(b"GET / HTTP/1.1\r\n")
        servers.RedisListenerHandler(left, ("127.0.0.1", 54322), server)
        http_response = right.recv(4096)
    finally:
        right.close()

    attempts = log_path.read_text(encoding="utf-8")
    assert b"HTTP/1.1 200 OK" in http_response
    assert "protocol=http" in attempts


def test_redis_listener_handler_protocol_ping_and_noauth_paths(tmp_path) -> None:
    logger = AttemptLogger()
    log_path = tmp_path / "redis-extra.log"
    logger.set_text_output(str(log_path))
    server = SimpleNamespace(server_address=("127.0.0.1", 16379), attempt_logger=logger)

    def roundtrip(payload: bytes) -> bytes:
        left, right = socket.socketpair()
        try:
            right.sendall(payload)
            right.shutdown(socket.SHUT_WR)
            servers.RedisListenerHandler(left, ("127.0.0.1", 54321), server)
            return right.recv(4096)
        finally:
            right.close()

    assert b"+PONG" in roundtrip(b"*1\r\n$4\r\nPING\r\n")
    assert b"-NOAUTH Authentication required." in roundtrip(b"*1\r\n$6\r\nDBSIZE\r\n")
    assert b"-ERR protocol error" in roundtrip(b"*x\r\n")

    logger.close()


def test_make_proxmox_handler_serves_login_and_logs_basic_and_token_auth(tmp_path) -> None:
    logger = AttemptLogger()
    log_path = tmp_path / "proxmox.log"
    logger.set_text_output(str(log_path))
    handler_cls = servers.make_proxmox_handler(logger)
    server = SimpleNamespace(server_address=("127.0.0.1", 18006))

    def roundtrip(raw_request: bytes) -> bytes:
        left, right = socket.socketpair()
        try:
            right.sendall(raw_request)
            handler_cls(left, ("127.0.0.1", 54321), server)
            response = right.recv(8192)
        finally:
            right.close()
        return response

    try:
        auth = base64.b64encode(b"root@pam:secret").decode("ascii")
        response = roundtrip(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        assert b"200 OK" in response
        assert b"Proxmox VE" in response

        response = roundtrip(
            (f"GET /api2/json/nodes HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {auth}\r\n\r\n").encode()
        )
        assert b"401 Unauthorized" in response
        payload = json.loads(response.split(b"\r\n\r\n", 1)[1].decode("utf-8"))
        assert payload["message"] == "authentication failure"

        response = roundtrip(
            b"GET /api2/json/nodes HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Authorization: PVEAPIToken=admin@pve!token=supersecret\r\n"
            b"\r\n"
        )
        assert b"401 Unauthorized" in response

        form_body = b"username=root@pam&password=secret"
        response = roundtrip(
            (
                "POST /api2/json/access/ticket HTTP/1.1\r\n"
                "Host: localhost\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(form_body)}\r\n"
                "\r\n"
            ).encode()
            + form_body
        )
        assert b"401 Unauthorized" in response
        payload = json.loads(response.split(b"\r\n\r\n", 1)[1].decode("utf-8"))
        assert payload["message"] == "authentication failure"

        json_body = b"{bad"
        response = roundtrip(
            (
                "POST /api2/json/access/ticket HTTP/1.1\r\n"
                "Host: localhost\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(json_body)}\r\n"
                "\r\n"
            ).encode()
            + json_body
        )
        assert b"401 Unauthorized" in response

        response = roundtrip(b"GET /missing HTTP/1.1\r\nHost: localhost\r\n\r\n")
        assert b"404 Not Found" in response
        payload = json.loads(response.split(b"\r\n\r\n", 1)[1].decode("utf-8"))
        assert payload["message"] == "not found"

        response = roundtrip(b"POST /api2/json/other HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
        assert b"404 Not Found" in response
    finally:
        logger.close()

    attempts = log_path.read_text(encoding="utf-8")
    assert "[PVE]" in attempts
    assert "user=root@pam" in attempts
    assert "pass=secret" in attempts
    assert "auth=pveapitoken" in attempts
    assert "user=admin@pve!token" in attempts


def test_make_blackbox_handler_logs_probe_metrics_and_parse_error(tmp_path) -> None:
    logger = AttemptLogger()
    log_path = tmp_path / "blackbox.log"
    logger.set_text_output(str(log_path))
    handler_cls = servers.make_blackbox_handler(logger)
    server = SimpleNamespace(server_address=("127.0.0.1", 19115))

    def roundtrip(raw_request: bytes) -> bytes:
        left, right = socket.socketpair()
        try:
            right.sendall(raw_request)
            handler_cls(left, ("127.0.0.1", 54321), server)
            response = right.recv(8192)
        finally:
            right.close()
        return response

    try:
        auth = base64.b64encode(b"alice:secret").decode("ascii")
        response = roundtrip(
            (
                "GET /probe?target=http://example.local&module=unsupported HTTP/1.1\r\n"
                "Host: localhost\r\n"
                f"Authorization: Basic {auth}\r\n"
                "User-Agent: pytest\r\n"
                "\r\n"
            ).encode()
        )
        body = response.split(b"\r\n\r\n", 1)[1].decode("utf-8", errors="replace")
        assert b"200 OK" in response
        assert 'probe_module_info{module="http_2xx"} 1' in body
        assert 'probe_target_info{target="http://example.local"} 1' in body

        metric_body = b"ping"
        response = roundtrip(
            (
                "POST /metrics?target=redis://127.0.0.1:6379&job=metrics&instance=node-1&exporter=redis HTTP/1.1\r\n"
                "Host: localhost\r\n"
                f"Content-Length: {len(metric_body)}\r\n"
                "\r\n"
            ).encode()
            + metric_body
        )
        body = response.split(b"\r\n\r\n", 1)[1].decode("utf-8", errors="replace")
        assert b"200 OK" in response
        assert (
            'exporter_redposture_up{target="redis://127.0.0.1:6379",job="metrics",instance="node-1",exporter="redis"} 1'
            in body
        )

        response = roundtrip(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        body = response.split(b"\r\n\r\n", 1)[1].decode("utf-8", errors="replace")
        assert b"200 OK" in response
        assert "blackbox_exporter" in body

        malformed_response = roundtrip(b"BOGUS / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        assert b"501 Unsupported method" in malformed_response

        post_probe_body = b"target=http://body"
        response = roundtrip(
            (
                "POST /probe?target=http://post.local&module=tcp_connect HTTP/1.1\r\n"
                "Host: localhost\r\n"
                f"Content-Length: {len(post_probe_body)}\r\n"
                "\r\n"
            ).encode()
            + post_probe_body
        )
        body = response.split(b"\r\n\r\n", 1)[1].decode("utf-8", errors="replace")
        assert b"200 OK" in response
        assert 'probe_module_info{module="tcp_connect"} 1' in body

        response = roundtrip(b"POST /custom HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\nabc")
        assert b"200 OK" in response
    finally:
        logger.close()

    attempts = log_path.read_text(encoding="utf-8")
    assert "[BLACKBOX]" in attempts
    assert "target=http://example.local" in attempts
    assert "endpoint_type=exporter_metrics" in attempts
    assert "method=PARSE_ERROR" in attempts


def test_make_http_server_wraps_socket_and_build_ssl_context_loads_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    sentinel_socket = object()

    class _DummyHTTPServer:
        def __init__(self, server_address: tuple[str, int], handler: object) -> None:
            self.server_address = server_address
            self.handler = handler
            self.socket = sentinel_socket

    class _DummySSLContext:
        def __init__(self) -> None:
            self.calls: list[tuple[object, bool]] = []

        def wrap_socket(self, sock: object, *, server_side: bool = False) -> object:
            self.calls.append((sock, server_side))
            return sock

    handler = servers.make_blackbox_handler(AttemptLogger())
    dummy = _DummySSLContext()
    monkeypatch.setattr(servers, "ThreadingHTTPReuseServer", _DummyHTTPServer)
    server = servers.make_http_server("127.0.0.1", 0, handler, ssl_context=dummy)
    assert server.server_address == ("127.0.0.1", 0)
    assert dummy.calls == [(sentinel_socket, True)]

    loaded: list[tuple[str, str]] = []

    def fake_load_cert_chain(self: ssl.SSLContext, certfile: str, keyfile: str) -> None:
        loaded.append((certfile, keyfile))

    monkeypatch.setattr(ssl.SSLContext, "load_cert_chain", fake_load_cert_chain, raising=False)
    context = servers.build_ssl_context("/tmp/test-cert.pem", "/tmp/test-key.pem")
    assert isinstance(context, ssl.SSLContext)
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert loaded == [("/tmp/test-cert.pem", "/tmp/test-key.pem")]


def test_generate_self_signed_cert_surfaces_openssl_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        servers.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=1, stderr="openssl boom", stdout=""),
    )
    with pytest.raises(ValueError, match="openssl boom"):
        servers._generate_self_signed_cert("/tmp/cert.pem", "/tmp/key.pem")

    def raise_oserror(*args, **kwargs):
        raise OSError("missing openssl")

    monkeypatch.setattr(servers.subprocess, "run", raise_oserror)
    with pytest.raises(ValueError, match="missing openssl"):
        servers._generate_self_signed_cert("/tmp/cert.pem", "/tmp/key.pem")


def test_write_self_signed_cert_files_rejects_bad_paths(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setattr(servers, "_generate_self_signed_cert", lambda *_args, **_kwargs: None)

    same = tmp_path / "same.pem"
    with pytest.raises(ValueError, match="different files"):
        servers.write_self_signed_cert_files(str(same), str(same))

    directory = tmp_path / "certdir"
    directory.mkdir()
    with pytest.raises(ValueError, match="points to a directory"):
        servers.write_self_signed_cert_files(str(directory), str(tmp_path / "key.pem"))
