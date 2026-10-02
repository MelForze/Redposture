"""Cross-product discovery through the actual clients and loopback sockets.

The server keeps serving its own product on unknown paths, as a wildcard
reverse proxy might. This deliberately avoids trivial all-404 negatives.
No detector, parser, is_detected predicate or transport is mocked.
"""

from __future__ import annotations

import importlib
import json
import socket
import socketserver
import struct
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from typing import Any
from urllib.parse import urlsplit

import pytest
from bson.errors import InvalidBSON
from h2.exceptions import ProtocolError as H2ProtocolError

from redposture_core.cli_args import parse_args
from redposture_core.module_registry import AUDIT_MODULE_NAMES
from redposture_core.stage_runtime import AuditCommandRunner

HTTP_PRODUCTS = (
    "airflow",
    "consul",
    "docker",
    "elastic",
    "etcd",
    "gitlab",
    "grafana",
    "kubeapi",
    "minio",
    "proxmox",
    "qdrant",
    "rabbitmq",
    "docker-registry",
    "harbor",
    "nexus",
)
HTTP_API_SUFFIXES = {
    "airflow": "/api/v1/version",
    "consul": "/v1/status/leader",
    "docker": "/version",
    "elastic": "/_cluster/health",
    "etcd": "/version",
    "gitlab": "/api/v4/version",
    "grafana": "/api/health",
    "kubeapi": "/version",
    "minio": "/minio/health/live",
    "proxmox": "/api2/json/version",
    "qdrant": "/collections",
    "rabbitmq": "/api/overview",
    "docker-registry": "/v2/_catalog",
    "harbor": "/api/v2.0/systeminfo",
    "nexus": "/service/rest/v1/status",
}
NATIVE_PRODUCTS = ("clickhouse", "grpc", "kafka", "keeper", "mongodb", "oracle", "postgres", "redis", "zookeeper")
PRODUCTS = HTTP_PRODUCTS + NATIVE_PRODUCTS


def _http_response(product: str, path: str, *, proxy_headers: bool = False) -> bytes:
    path = urlsplit(path).path
    if product == "grpc_web":
        trailer = b"grpc-status: 12\r\n"
        body = b"\x80" + len(trailer).to_bytes(4, "big") + trailer
        return (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/grpc-web+proto\r\n"
            + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
            + body
        )
    status = 200
    headers = {"Content-Type": "application/json", "Connection": "close"}
    payload: Any
    if product == "airflow":
        payload = {"version": "2.9.2", "git_version": "abc123"}
        if path == "/api/v2/version":
            status, payload = 404, {}
        elif path.startswith("/api/v1/dags"):
            payload = {"dags": [], "total_entries": 0}
    elif product == "consul":
        payload = {"Config": {"Version": "1.18.1", "Datacenter": "dc1", "NodeName": "lab"}, "Member": {"Name": "lab"}}
        if path.endswith("/leader"):
            payload = "127.0.0.1:8300"
        elif path.endswith("/peers"):
            payload = ["127.0.0.1:8300"]
    elif product == "docker":
        payload = {"Version": "27.5.1", "ApiVersion": "1.47", "GitCommit": "abc123", "Os": "linux"}
        if path == "/_ping":
            payload = "OK"
        elif path == "/info":
            payload = {"ServerVersion": "27.5.1", "OSType": "linux", "Containers": 0, "Images": 0}
    elif product == "elastic":
        payload = {
            "name": "node",
            "cluster_name": "lab",
            "version": {"number": "8.13.4", "build_flavor": "default"},
            "tagline": "You Know, for Search",
        }
        headers["X-Elastic-Product"] = "Elasticsearch"
    elif product == "etcd":
        payload = {"etcdserver": "3.5.14", "etcdcluster": "3.5.0"}
    elif product == "gitlab":
        payload = {"version": "17.3.1", "revision": "abc123"}
        if path.startswith("/users/sign_in"):
            payload = '<title>GitLab</title><form action="/users/sign_in">Sign in</form>'
            headers["Content-Type"] = "text/html"
    elif product == "grafana":
        payload = {"database": "ok", "version": "11.0.0", "commit": "abc123"}
        if path == "/login":
            payload = "<title>Grafana</title>"
            headers["Content-Type"] = "text/html"
    elif product == "kubeapi":
        payload = {"major": "1", "minor": "27", "gitVersion": "v1.27.5", "gitCommit": "abc123"}
        if path == "/api":
            payload = {"kind": "APIVersions", "apiVersion": "v1", "versions": ["v1"]}
    elif product == "minio":
        headers.update({"Server": "MinIO", "Content-Type": "application/xml"})
        payload = "<Error><Code>AccessDenied</Code><Message>Access Denied.</Message><Resource>/</Resource><RequestId>qa</RequestId><HostId>qa</HostId></Error>"
        status = 403
        if path == "/minio/health/live":
            status, payload = 200, ""
    elif product == "proxmox":
        headers["Server"] = "pve-api-daemon/3.0"
        payload = {"data": {"version": "8.2", "release": "1", "repoid": "abc123"}}
    elif product == "qdrant":
        payload = {"title": "qdrant - vector search engine", "version": "1.15.5"}
        if path == "/collections":
            payload = {"result": {"collections": []}, "status": "ok", "time": 0.001}
    elif product == "rabbitmq":
        payload = {
            "rabbitmq_version": "4.0.9",
            "management_version": "4.0.9",
            "cluster_name": "rabbit@lab",
            "node": "rabbit@lab",
        }
    elif product == "docker-registry":
        headers["Docker-Distribution-Api-Version"] = "registry/2.0"
        payload = {}
    elif product == "harbor":
        headers["Docker-Distribution-Api-Version"] = "registry/2.0"
        payload = {"harbor_version": "v2.11.1"} if path == "/api/v2.0/systeminfo" else {}
    elif product == "nexus":
        headers["Server"] = "Nexus/3.72.0-04 (OSS)"
        payload = {"productName": "Nexus Repository", "version": "3.72.0-04", "edition": "OSS"}
    else:
        raise AssertionError(product)
    if proxy_headers:
        headers.pop("X-Elastic-Product", None)
        headers["Server"] = "nginx"
    body = payload.encode() if isinstance(payload, str) else json.dumps(payload).encode()
    headers["Content-Length"] = str(len(body))
    reason = {200: "OK", 403: "Forbidden", 404: "Not Found"}[status]
    return (
        f"HTTP/1.1 {status} {reason}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n"
    ).encode() + body


def _read_exact(sock: socket.socket, size: int) -> bytes:
    if size < 0 or size > 65536:
        raise ValueError("out-of-corpus request length")
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise EOFError
        result.extend(chunk)
    return bytes(result)


def _frame(body: bytes) -> bytes:
    return struct.pack(">i", len(body)) + body


def _var_string(value: str) -> bytes:
    raw = value.encode()
    assert len(raw) < 128
    return bytes([len(raw)]) + raw


def _native_response(product: str, sock: socket.socket, initial: bytes) -> None:
    if product == "clickhouse":
        # Native ServerException packet, code AUTHENTICATION_FAILED.
        sock.sendall(
            b"\x02"
            + struct.pack("<i", 516)
            + _var_string("DB::Exception")
            + _var_string("Authentication failed: password is incorrect")
            + b"\x00\x00"
        )
    elif product == "postgres":
        if initial == struct.pack(">i", 8):
            _read_exact(sock, 4)
            sock.sendall(b"N")
            initial = _read_exact(sock, 4)
        _read_exact(sock, struct.unpack(">i", initial)[0] - 4)
        sock.sendall(b"R" + struct.pack(">ii", 12, 5) + b"salt")
    elif product == "redis":
        sock.sendall(b"+PONG\r\n")
        while sock.recv(4096):
            body = b"# Server\r\nredis_version:7.0.3\r\n"
            sock.sendall(f"${len(body)}\r\n".encode() + body + b"\r\n")
    elif product == "oracle":
        _read_exact(sock, struct.unpack(">H", initial[:2])[0] - 4)
        body = b"\x00\x00(DESCRIPTION=(ERR=0)(VERSION=TNSLSNR for Linux: Version 23.6.0.0.0)(SERVICE_NAME=FREEPDB1))"
        sock.sendall(struct.pack(">HHBBH", 8 + len(body), 0, 6, 0, 0) + body)
    elif product == "kafka":
        while True:
            request = _read_exact(sock, struct.unpack(">i", initial)[0])
            api, _version, correlation = struct.unpack(">hhi", request[:8])
            if api == 18:
                body = struct.pack(">ihi", correlation, 0, 3) + b"".join(
                    struct.pack(">hhh", key, 0, maximum) for key, maximum in [(18, 0), (3, 0), (1, 0)]
                )
            elif api == 3:
                body = struct.pack(">iiii", correlation, 0, 0, 0)
            else:
                return
            sock.sendall(_frame(body))
            initial = _read_exact(sock, 4)
    elif product in {"keeper", "zookeeper"}:
        if initial in {b"srvr", b"stat", b"mntr", b"isro"}:
            version = (
                "ClickHouse Keeper version: 24.8.14.39"
                if product == "keeper"
                else "Zookeeper version: 3.9.5-abc123, built on 2025-01-01"
            )
            sock.sendall((version + "\nMode: standalone\n").encode())
            return
        _read_exact(sock, struct.unpack(">i", initial)[0])
        sock.sendall(_frame(struct.pack(">iiqi", 0, 30000, 1, 16) + b"passwordpassword" + b"\x00"))
        while True:
            request = _read_exact(sock, struct.unpack(">i", _read_exact(sock, 4))[0])
            xid, opcode = struct.unpack(">ii", request[:8])
            if opcode == -11:
                return
            # Real ReplyHeader and NoAuth error. The implementation is separately
            # established by its four-letter version response above.
            sock.sendall(_frame(struct.pack(">iqi", xid, 1, -102)))
    elif product == "mongodb":
        from bson import BSON

        while True:
            length = struct.unpack("<i", initial)[0]
            request_id, _response_to, opcode = struct.unpack("<iii", _read_exact(sock, 12))
            request = _read_exact(sock, length - 16)
            if opcode == 2004:
                start = request.index(b"\x00", 4) + 9
                command = BSON(request[start:]).decode()
            elif opcode == 2013:
                command = BSON(request[5:]).decode()
            else:
                return
            document: dict[str, Any]
            name = next(iter(command)).lower()
            if name in {"hello", "ismaster"}:
                document = {
                    "ok": 1.0,
                    "ismaster": True,
                    "isWritablePrimary": True,
                    "minWireVersion": 0,
                    "maxWireVersion": 21,
                    "maxBsonObjectSize": 16777216,
                    "maxMessageSizeBytes": 48000000,
                    "maxWriteBatchSize": 100000,
                }
            elif name == "buildinfo":
                document = {"ok": 1.0, "version": "7.0.14", "versionArray": [7, 0, 14, 0]}
            elif name == "listdatabases":
                document = {"ok": 1.0, "databases": [], "totalSize": 0}
            else:
                document = {"ok": 0.0, "code": 13, "errmsg": "not authorized"}
            bson = BSON.encode(document)
            body = struct.pack("<iqii", 0, 0, 0, 1) + bson if opcode == 2004 else struct.pack("<iB", 0, 0) + bson
            response_opcode = 1 if opcode == 2004 else 2013
            sock.sendall(struct.pack("<iiii", 16 + len(body), 1, request_id, response_opcode) + body)
            initial = _read_exact(sock, 4)
    elif product == "grpc":
        from h2.config import H2Configuration
        from h2.connection import H2Connection
        from h2.events import DataReceived, StreamEnded

        connection = H2Connection(config=H2Configuration(client_side=False))
        connection.initiate_connection()
        sock.sendall(connection.data_to_send())
        data = initial
        while data:
            for event in connection.receive_data(data):
                if isinstance(event, DataReceived):
                    connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                elif isinstance(event, StreamEnded):
                    connection.send_headers(event.stream_id, [(":status", "200"), ("content-type", "application/grpc")])
                    # UNIMPLEMENTED is a valid gRPC fingerprint, without claiming
                    # health/reflection support that this fixture lacks.
                    connection.send_headers(event.stream_id, [("grpc-status", "12")], end_stream=True)
            sock.sendall(connection.data_to_send())
            data = sock.recv(65536)
    else:
        raise AssertionError(product)


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = False
    block_on_close = True
    errors: list[str]

    def handle_error(self, request: Any, client_address: Any) -> None:
        self.errors.append(repr(sys.exc_info()[1]))


@contextmanager
def _product_server(
    product: str, *, proxy_headers: bool = False, prefix: str = ""
) -> Iterator[tuple[int, list[bytes]]]:
    requests: list[bytes] = []

    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            self.request.settimeout(0.4)
            try:
                initial = _read_exact(self.request, 4)
                if product in HTTP_PRODUCTS or product == "grpc_web":
                    path = "/"
                    if initial in {b"GET ", b"HEAD", b"POST"}:
                        data = initial
                        while b"\r\n\r\n" not in data and len(data) < 65536:
                            data += _read_exact(self.request, 1)
                        path = data.split(b" ")[1].decode("ascii", "replace")
                        requests.append(data)
                    else:
                        requests.append(initial)
                    if prefix and not (path == prefix or path.startswith(prefix + "/")):
                        self.request.sendall(
                            b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 9\r\n"
                            b"Connection: close\r\n\r\nnot found"
                        )
                    else:
                        self.request.sendall(
                            _http_response(product, path[len(prefix) :] or "/", proxy_headers=proxy_headers)
                        )
                else:
                    requests.append(initial)
                    _native_response(product, self.request, initial)
            except (OSError, EOFError, ValueError, struct.error, H2ProtocolError, InvalidBSON):
                # Foreign protocols, bounded timeouts and client disconnects.
                return

    server = _Server(("127.0.0.1", 0), Handler)
    server.errors = []
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield int(server.server_address[1]), requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()
        assert server.errors == [], server.errors


@contextmanager
def _redirect_server(
    destination_port: int, captured_requests: list[bytes] | None = None, destination_prefix: str = ""
) -> Iterator[tuple[int, list[str]]]:
    paths: list[str] = []

    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            self.request.settimeout(0.5)
            try:
                request = bytearray()
                while b"\r\n\r\n" not in request and len(request) < 65536:
                    request.extend(self.request.recv(4096))
                path = request.split(b" ", 2)[1].decode("ascii", "replace")
                paths.append(path)
                if captured_requests is not None:
                    captured_requests.append(bytes(request))
                location = f"http://127.0.0.1:{destination_port}{destination_prefix}{path}"
                self.request.sendall(
                    f"HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode()
                )
            except (OSError, IndexError):
                return

    server = _Server(("127.0.0.1", 0), Handler)
    server.errors = []
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield int(server.server_address[1]), paths
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()
        assert server.errors == [], server.errors


@contextmanager
def _fixed_http_server(status: int, body: bytes, content_type: str) -> Iterator[int]:
    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            self.request.settimeout(0.5)
            try:
                request = bytearray()
                while b"\r\n\r\n" not in request and len(request) < 65536:
                    request.extend(self.request.recv(4096))
                self.request.sendall(
                    f"HTTP/1.1 {status} QA\r\nServer: nginx\r\nContent-Type: {content_type}\r\n"
                    f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                    + body
                )
            except OSError:
                return

    server = _Server(("127.0.0.1", 0), Handler)
    server.errors = []
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield int(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()
        assert server.errors == [], server.errors


def _detect(
    module: str,
    port: int,
    *,
    verify_foreign: bool = False,
    target_path: str = "",
    with_credentials: bool = False,
    with_cve: bool = False,
) -> tuple[bool, dict[str, Any]]:
    extra = ["--protocol", "native"] if module == "clickhouse" else ["--plaintext"] if module == "grpc" else []
    if module == "oracle":
        extra += ["--service", "FREEPDB1", "--protocol", "tcp"]
    if verify_foreign or with_cve:
        extra += ["--enum-cve"]
    if verify_foreign or with_credentials:
        if module == "gitlab":
            extra += ["--token", "qa-token"]
        elif module == "qdrant":
            extra += ["--api-key", "qa-token"]
        elif module != "docker":
            extra += ["-u", "qa-user", "-p", "qa-password"]
    args = parse_args(
        [
            module,
            "-t",
            f"http://127.0.0.1:{port}{target_path}",
            "--port",
            str(port),
            "--timeout",
            "0.5",
            "--retries",
            "0",
            "--format",
            "json",
            *extra,
        ]
    )
    package = module.replace("-", "_")
    stage = importlib.import_module(f"redposture_core.modules.{package}.stage")
    spec = getattr(stage, f"build_{package}_spec")(args)
    # Preserve production detection/auth/state/cleanup. On lifecycle modules,
    # replace inventory hooks with no-ops rather than setting them to None:
    # None would accidentally fall back to the legacy monolithic host_stage.
    if spec.detect is not None:
        spec = replace(spec, data=lambda _ctx, record: record, capabilities=lambda _ctx, record: record)
    lines: list[str] = []
    result = AuditCommandRunner(args=args, spec=spec, emit_line=lines.append).run_plan(
        getattr(stage, f"build_{package}_plan")(args)
    )
    records = [json.loads(line) for line in lines if json.loads(line).get("type") != "summary"]
    assert len(records) == 1, (module, lines)
    return result.detected_count == 1, records[0]


def test_wire_corpus_covers_exactly_all_audit_modules() -> None:
    assert len(PRODUCTS) == len(set(PRODUCTS)) == 24
    assert set(PRODUCTS) == set(AUDIT_MODULE_NAMES)


@pytest.mark.parametrize("product", PRODUCTS)
def test_each_wire_fixture_has_a_real_positive_control(product: str) -> None:
    with _product_server(product) as (port, requests):
        detected, record = _detect(product, port)
    assert requests
    assert detected, record


@pytest.mark.parametrize("product", HTTP_PRODUCTS)
def test_http_product_survives_nginx_header_rewrite_on_ephemeral_port(product: str) -> None:
    with _product_server(product, proxy_headers=True) as (port, requests):
        detected, record = _detect(product, port)
    assert requests
    assert detected, record


@pytest.mark.parametrize("product", HTTP_PRODUCTS)
def test_http_product_detects_explicit_reverse_proxy_prefix(product: str) -> None:
    with _product_server(product, proxy_headers=True, prefix="/edge/app") as (port, requests):
        detected, record = _detect(product, port, target_path="/edge/app")
    assert requests
    assert detected, record


@pytest.mark.parametrize("product", HTTP_PRODUCTS)
def test_auth_and_cve_probes_keep_confirmed_reverse_proxy_prefix(product: str) -> None:
    with _product_server(product, proxy_headers=True, prefix="/edge/app") as (port, requests):
        detected, record = _detect(product, port, verify_foreign=True, target_path="/edge/app")
    assert detected, record
    paths = [
        request.split(b" ", 2)[1].decode("ascii", "replace")
        for request in requests
        if request.startswith((b"GET ", b"HEAD ", b"POST "))
    ]
    assert paths, requests
    assert all(path.startswith("/edge/app") for path in paths), (product, paths)


@pytest.mark.parametrize("product", HTTP_PRODUCTS)
def test_auth_probes_keep_confirmed_reverse_proxy_prefix(product: str) -> None:
    with _product_server(product, proxy_headers=True, prefix="/edge/app") as (port, requests):
        detected, record = _detect(product, port, with_credentials=True, target_path="/edge/app")
    assert detected, record
    paths = [
        request.split(b" ", 2)[1].decode("ascii", "replace")
        for request in requests
        if request.startswith((b"GET ", b"HEAD ", b"POST "))
    ]
    assert paths and all(path.startswith("/edge/app") for path in paths), (product, paths)


@pytest.mark.parametrize("product", HTTP_PRODUCTS)
def test_known_api_suffix_is_removed_from_target_base_path(product: str) -> None:
    with _product_server(product, proxy_headers=True, prefix="/edge/app") as (port, requests):
        detected, record = _detect(product, port, target_path="/edge/app" + HTTP_API_SUFFIXES[product])
    assert requests
    assert detected, record


@pytest.mark.parametrize("product", HTTP_PRODUCTS)
def test_http_detection_json_has_comparable_product_evidence(product: str) -> None:
    with _product_server(product, proxy_headers=True) as (port, _requests):
        detected, record = _detect(product, port)
    assert detected, record
    assert record["detection_status"] == "confirmed"
    assert isinstance(record["detection_signals"], list)
    assert record["detection_signals"]


@pytest.mark.parametrize("product", HTTP_PRODUCTS)
def test_http_product_detects_read_only_redirect_to_confirmed_origin(product: str) -> None:
    with _product_server(product, proxy_headers=True) as (destination_port, destination_requests):
        with _redirect_server(destination_port) as (source_port, source_paths):
            detected, record = _detect(product, source_port)
    assert source_paths and destination_requests
    assert detected, record


@pytest.mark.parametrize("product", HTTP_PRODUCTS)
def test_http_product_detects_redirect_with_explicit_prefix(product: str) -> None:
    with _product_server(product, proxy_headers=True, prefix="/edge/app") as (destination_port, destination_requests):
        with _redirect_server(destination_port) as (source_port, source_paths):
            detected, record = _detect(product, source_port, target_path="/edge/app")
    assert source_paths and destination_requests
    assert detected, record


@pytest.mark.parametrize("product", HTTP_PRODUCTS)
def test_credentials_use_confirmed_redirect_origin_without_revisiting_source(product: str) -> None:
    source_requests: list[bytes] = []
    with _product_server(product, proxy_headers=True, prefix="/edge/app") as (destination_port, _requests):
        with _redirect_server(destination_port, source_requests) as (source_port, source_paths):
            detected, record = _detect(product, source_port, with_credentials=True, target_path="/edge/app")
    assert detected, record
    # A module may need several anonymous discovery probes, but credentials
    # must not cause another request to the initial redirecting listener.
    assert source_paths
    assert all(path.startswith("/edge/app") for path in source_paths)
    assert not any(
        marker in request.lower()
        for request in source_requests
        for marker in (b"authorization:", b"private-token:", b"x-api-key:", b"x-consul-token:")
    ), (product, source_requests)


@pytest.mark.parametrize("product", HTTP_PRODUCTS)
def test_redirect_to_new_mount_keeps_product_and_credentials(product: str) -> None:
    source_requests: list[bytes] = []
    with _product_server(product, proxy_headers=True, prefix="/edge/app") as (destination_port, destination_requests):
        with _redirect_server(destination_port, source_requests, destination_prefix="/edge/app") as (
            source_port,
            _paths,
        ):
            detected, record = _detect(product, source_port, with_credentials=True)
    assert detected, record
    assert all(
        request.split(b" ", 2)[1].startswith(b"/edge/app/")
        for request in destination_requests
        if request.startswith((b"GET ", b"HEAD ", b"POST "))
    ), (product, destination_requests)
    assert not any(
        marker in request.lower()
        for request in source_requests
        for marker in (b"authorization:", b"private-token:", b"x-api-key:", b"x-consul-token:")
    ), (product, source_requests)


def test_grpc_web_real_detector_requires_valid_trailer_frame() -> None:
    with _product_server("grpc_web", proxy_headers=True) as (port, requests):
        detected, record = _detect("grpc", port)
    assert requests
    assert detected, record
    assert record["detection_status"] == "confirmed"
    assert record["protocol_flavor"] == "grpc-web"


def test_grpc_web_content_type_only_does_not_start_auth_or_cve() -> None:
    with _fixed_http_server(200, b"<html>SSO login</html>", "application/grpc-web+proto") as port:
        detected, record = _detect("grpc", port, verify_foreign=True)
    assert not detected, record
    assert record["detection_status"] in {"not_service", "probable", "transport_failure"}
    assert not record.get("attempted_credentials")
    assert record["cve_enumeration"]["findings"] == []


@pytest.mark.parametrize("module", HTTP_PRODUCTS)
@pytest.mark.parametrize(
    "status, body, content_type",
    [
        (200, b'{"version":"2.11.2"}', "application/json"),
        (200, b'<html><form action="/auth/realms/qa">Sign in</form></html>', "text/html"),
        (401, b'{"error":"authentication required"}', "application/json"),
    ],
)
def test_generic_http_and_sso_are_not_product_evidence(
    module: str,
    status: int,
    body: bytes,
    content_type: str,
) -> None:
    with _fixed_http_server(status, body, content_type) as port:
        detected, record = _detect(module, port, verify_foreign=True)
    assert not detected, (module, record)
    assert record["detection_status"] in {"probable", "not_service", "transport_failure"}
    assert record["detection_signals"] == [f"{module}.probe"]
    assert not record.get("attempted_credentials")
    assert record["cve_enumeration"]["findings"] == []


@pytest.mark.parametrize("product", HTTP_PRODUCTS)
@pytest.mark.parametrize("module", HTTP_PRODUCTS)
def test_nginx_header_rewrite_does_not_cross_confirm_http_products(module: str, product: str) -> None:
    with _product_server(product, proxy_headers=True) as (port, _requests):
        detected, record = _detect(module, port, verify_foreign=module != product)
    assert detected is (module == product), (module, product, record)
    if module != product:
        assert record["detection_status"] in {"not_service", "probable", "transport_failure"}, record
        assert isinstance(record["detection_signals"], list), record
        assert not record.get("attempted_credentials"), record
        assert record["cve_enumeration"]["findings"] == [], record


@pytest.mark.parametrize("product", PRODUCTS)
@pytest.mark.parametrize("module", AUDIT_MODULE_NAMES)
def test_actual_detector_rejects_other_products_over_the_network(module: str, product: str) -> None:
    with _product_server(product) as (port, requests):
        detected, record = _detect(module, port, verify_foreign=module != product)
    assert requests
    if module != product:
        assert not record.get("attempted_credentials"), record
        assert record["cve_enumeration"]["findings"] == [], record
        assert record["cve_enumeration"]["reason"] == "service_not_confirmed", record
    assert detected is (module == product), (module, product, record)
