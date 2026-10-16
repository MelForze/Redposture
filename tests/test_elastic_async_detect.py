from __future__ import annotations

import gzip
import ipaddress
import ssl
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import redposture_core.modules.elastic.actions as elastic_actions
from redposture_core.clients.http_api import http_target_context
from redposture_core.modules.elastic.async_detect import probe_direct_paths
from redposture_core.network_proxy import ProxySocketPatch
from redposture_core.stage_runtime import is_pre_detect_operational_failure


@contextmanager
def _slow_server(
    *,
    late_positive: bool,
    prefix: str = "",
    tls_context: ssl.SSLContext | None = None,
    delay: float = 0.08,
    hard_path: str | None = None,
) -> Iterator[int]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:
            time.sleep(delay)
            path = self.path
            if prefix:
                if not path.startswith(prefix + "/"):
                    self.send_error(404)
                    return
                path = path[len(prefix) :]
            status = 200
            if hard_path == "/_nodes" and path.startswith("/_nodes?"):
                body = b'{"nodes":{"node1":{"version":"8.17.3"}}}'
                content_type = "application/json"
            elif hard_path == "/_security/_authenticate" and path == hard_path:
                status = 401
                body = b'{"error":{"type":"security_exception","reason":"missing authentication credentials"}}'
                content_type = "application/json"
            elif hard_path == "/_plugins/_security/authinfo" and path == hard_path:
                body = b'{"user_name":"admin"}'
                content_type = "application/json"
            elif late_positive and path == "/_cluster/health":
                body = b'{"cluster_name":"elastic-cluster","status":"yellow"}'
                content_type = "application/json"
            elif late_positive and path == "/_cat/health":
                body = b"cluster status node.total node.data\nelastic-cluster yellow 1 1"
                content_type = "text/plain"
            elif path == "/gzip":
                body = gzip.compress(b'{"test":"ok"}')
                content_type = "application/json"
            elif path == "/chunked":
                self.send_response(200)
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                self.wfile.write(b"5\r\nhello\r\n0\r\n\r\n")
                return
            elif path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            elif path == "/large":
                body = b"x" * (65 * 1024)
                content_type = "application/octet-stream"
            else:
                body = b"{}"
                content_type = "application/json"
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            if path == "/gzip":
                self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    if tls_context is not None:
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize("late_positive", [False, True])
def test_slow_ambiguous_root_checks_last_elastic_path(monkeypatch: pytest.MonkeyPatch, late_positive: bool) -> None:
    monkeypatch.setattr(elastic_actions, "_DETECT_SLOW_PROBE_THRESHOLD", 0.02)
    with _slow_server(late_positive=late_positive) as port:
        record = elastic_actions._audit_elastic_host(
            "127.0.0.1",
            port,
            2.0,
            0,
            username=None,
            password=None,
            api_token=None,
            ca_file=None,
            show_endpoints=False,
            show_plugins=False,
            show_cluster=False,
            show_users=False,
            discover=False,
        )
    assert record["is_elastic"] is late_positive
    if late_positive:
        assert {"/_cluster/health", "/_cat/health"} <= {probe["path"] for probe in record["detect_probe_trace"]}
    else:
        assert record["status"] == "not_elastic"


@pytest.mark.parametrize(
    "hard_path",
    ["/_nodes", "/_security/_authenticate", "/_plugins/_security/authinfo"],
)
def test_slow_root_checks_each_hard_fingerprint(monkeypatch: pytest.MonkeyPatch, hard_path: str) -> None:
    monkeypatch.setattr(elastic_actions, "_DETECT_SLOW_PROBE_THRESHOLD", 0.02)
    with _slow_server(late_positive=False, hard_path=hard_path) as port:
        record = elastic_actions._audit_elastic_host(
            "127.0.0.1",
            port,
            2.0,
            0,
            None,
            None,
            None,
            None,
            False,
            False,
            False,
            False,
            False,
        )
    assert record["is_elastic"] is True


def test_async_probe_falls_back_on_redirect_and_decodes_framing() -> None:
    with _slow_server(late_positive=False) as port:
        probes = probe_direct_paths("127.0.0.1", port, ("/gzip", "/chunked", "/redirect"), "http", 2.0, None)
    assert probes is not None
    assert probes[0].payload == b'{"test":"ok"}'
    assert probes[1].payload == b"hello"
    assert probes[2].fallback is True


def test_oversized_fingerprint_replays_via_shared_client() -> None:
    with _slow_server(late_positive=False) as port:
        probes = probe_direct_paths("127.0.0.1", port, ("/large",), "http", 2.0, None)
    assert probes is not None
    assert probes[0].fallback is True


def test_slow_target_with_url_prefix_keeps_late_fingerprint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(elastic_actions, "_DETECT_SLOW_PROBE_THRESHOLD", 0.02)
    with _slow_server(late_positive=True, prefix="/elastic") as port:
        target = SimpleNamespace(scheme="http", path="/elastic")
        with http_target_context(target):
            record = elastic_actions._audit_elastic_host(
                "127.0.0.1",
                port,
                2.0,
                0,
                None,
                None,
                None,
                None,
                False,
                False,
                False,
                False,
                False,
                preferred_scheme="http",
            )
    assert record["is_elastic"] is True
    assert {"/_cluster/health", "/_cat/health"} <= {item["path"] for item in record["detect_probe_trace"]}


def test_active_proxy_disables_direct_async_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ProxySocketPatch, "_active_proxy", object())
    assert elastic_actions._can_probe_direct_async("127.0.0.1", 9200) is False


def test_hostname_uses_shared_client_without_per_worker_dns_pool() -> None:
    assert elastic_actions._can_probe_direct_async("localhost", 9200) is False


@pytest.mark.parametrize(
    ("error", "operational"),
    [
        ("[Errno 22] Invalid argument", True),
        ("\x00\x01\x02 not http ÿþ", False),
    ],
)
def test_pre_detect_failure_distinguishes_local_socket_error(
    monkeypatch: pytest.MonkeyPatch, error: str, operational: bool
) -> None:
    monkeypatch.setattr(
        elastic_actions,
        "_request_with_tls_fallback",
        lambda *_args, **_kwargs: (0, b"", {}, error, "http", False, False),
    )
    record = elastic_actions._audit_elastic_host(
        "127.0.0.1",
        9200,
        1.0,
        0,
        None,
        None,
        None,
        None,
        False,
        False,
        False,
        False,
        False,
    )
    assert record["operational_failure"] is operational
    assert is_pre_detect_operational_failure(record) is operational


def _self_signed_context(tmp_path: Path) -> ssl.SSLContext:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "server.crt"
    key_path = tmp_path / "server.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert_path), str(key_path))
    return context


def test_slow_self_signed_tls_target_keeps_late_fingerprint(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(elastic_actions, "_DETECT_SLOW_PROBE_THRESHOLD", 0.02)
    with _slow_server(late_positive=True, tls_context=_self_signed_context(tmp_path)) as port:
        record = elastic_actions._audit_elastic_host(
            "127.0.0.1",
            port,
            2.0,
            0,
            None,
            None,
            None,
            None,
            False,
            False,
            False,
            False,
            False,
            preferred_scheme="https",
        )
    assert record["is_elastic"] is True
    assert record["scheme"] == "https"
