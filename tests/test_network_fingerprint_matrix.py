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
    "registry",
)
NATIVE_PRODUCTS = ("clickhouse", "grpc", "kafka", "keeper", "mongodb", "oracle", "postgres", "redis", "zookeeper")
PRODUCTS = HTTP_PRODUCTS + NATIVE_PRODUCTS


def _http_response(product: str, path: str) -> bytes:
    path = urlsplit(path).path
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
    elif product == "registry":
        headers["Server"] = "Nexus/3.72.0-04 (OSS)"
        payload = {"version": "3.72.0-04", "edition": "OSS"}
    else:
        raise AssertionError(product)
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
def _product_server(product: str) -> Iterator[tuple[int, list[bytes]]]:
    requests: list[bytes] = []

    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            self.request.settimeout(0.4)
            try:
                initial = _read_exact(self.request, 4)
                requests.append(initial)
                if product in HTTP_PRODUCTS:
                    path = "/"
                    if initial in {b"GET ", b"HEAD", b"POST"}:
                        data = initial
                        while b"\r\n\r\n" not in data and len(data) < 65536:
                            data += _read_exact(self.request, 1)
                        path = data.split(b" ")[1].decode("ascii", "replace")
                    self.request.sendall(_http_response(product, path))
                else:
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


def _detect(module: str, port: int, *, verify_foreign: bool = False) -> tuple[bool, dict[str, Any]]:
    extra = ["--protocol", "native"] if module == "clickhouse" else ["--plaintext"] if module == "grpc" else []
    if module == "registry":
        extra += ["--nexus"]
    if module == "oracle":
        extra += ["--service", "FREEPDB1", "--protocol", "tcp"]
    if verify_foreign:
        extra += ["--enum-cve"]
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
            f"http://127.0.0.1:{port}",
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
    stage = importlib.import_module(f"redposture_core.modules.{module}.stage")
    spec = getattr(stage, f"build_{module}_spec")(args)
    # Discovery is tested here; preserve production detection/state/cleanup,
    # bypass only the independent post-detection inventory on lifecycle modules.
    spec = replace(spec, data=None, capabilities=None)
    lines: list[str] = []
    result = AuditCommandRunner(args=args, spec=spec, emit_line=lines.append).run_plan(
        getattr(stage, f"build_{module}_plan")(args)
    )
    records = [json.loads(line) for line in lines if json.loads(line).get("type") != "summary"]
    assert len(records) == 1, (module, lines)
    return result.detected_count == 1, records[0]


def test_wire_corpus_covers_exactly_all_audit_modules() -> None:
    assert len(PRODUCTS) == len(set(PRODUCTS)) == 22
    assert set(PRODUCTS) == set(AUDIT_MODULE_NAMES)


@pytest.mark.parametrize("product", PRODUCTS)
def test_each_wire_fixture_has_a_real_positive_control(product: str) -> None:
    with _product_server(product) as (port, requests):
        detected, record = _detect(product, port)
    assert requests
    assert detected, record


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
