"""Loopback QA for CVE enumeration through real module protocol lifecycles."""

from __future__ import annotations

import importlib
import json
import socketserver
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.stage_runtime import AuditCommandRunner


@contextmanager
def _http_service(kind: str, version: str) -> Iterator[int]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
            status = 404
            headers: dict[str, str] = {"Content-Type": "application/json"}
            body = b"{}"
            if kind == "grafana":
                if self.path == "/api/health":
                    status = 200
                    body = json.dumps({"database": "ok", "version": version, "commit": "qa-commit"}).encode()
                elif self.path == "/login":
                    status = 200
                    headers = {"Content-Type": "text/html"}
                    body = b"<html><head><title>Grafana</title></head><body>login</body></html>"
                elif self.path == "/api/datasources":
                    status = 200
                    body = b"[]"
            elif kind == "nexus":
                if self.path == "/service/rest/v1/status":
                    status = 200
                    body = json.dumps({"version": version, "edition": "OSS"}).encode()
                elif self.path.startswith("/service/rest/v1/repositories"):
                    status = 200
                    body = b"[]"
            elif kind == "airflow":
                if self.path == "/api/v2/version":
                    status = 404
                elif self.path == "/api/v1/version":
                    status = 200
                    body = json.dumps({"version": version, "git_version": "qa"}).encode()
                elif self.path.startswith("/api/v1/"):
                    status = 200
                    key = "dags" if self.path.startswith("/api/v1/dags") else "items"
                    body = json.dumps({key: [], "total_entries": 0}).encode()
            elif kind == "docker":
                if self.path == "/_ping":
                    status = 200
                    headers = {"Content-Type": "text/plain"}
                    body = b"OK"
                elif self.path == "/version":
                    status = 200
                    body = json.dumps(
                        {"Version": version, "ApiVersion": "1.41", "GitCommit": "qa", "Os": "linux"}
                    ).encode()
                elif self.path == "/info":
                    status = 200
                    body = json.dumps(
                        {"ServerVersion": version, "OSType": "linux", "Containers": 0, "Images": 0}
                    ).encode()
            elif kind == "qdrant":
                if self.path == "/":
                    status = 200
                    body = json.dumps({"title": "qdrant - vector search engine", "version": version}).encode()
                elif self.path == "/collections":
                    status = 200
                    body = b'{"result":{"collections":[]},"status":"ok","time":0.0}'
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: object) -> None:
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()


class _RedisServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _read_resp_command(stream: Any) -> list[str] | None:
    first = stream.readline()
    if not first:
        return None
    if not first.startswith(b"*"):
        return []
    try:
        count = int(first[1:-2])
    except ValueError:
        return []
    result: list[str] = []
    for _ in range(count):
        size_line = stream.readline()
        if not size_line.startswith(b"$"):
            return []
        try:
            size = int(size_line[1:-2])
        except ValueError:
            return []
        value = stream.read(size)
        if len(value) != size or stream.read(2) != b"\r\n":
            return []
        result.append(value.decode("utf-8", errors="replace"))
    return result


@contextmanager
def _redis_service(version: str) -> Iterator[int]:
    class Handler(socketserver.StreamRequestHandler):
        def handle(self) -> None:
            while True:
                command = _read_resp_command(self.rfile)
                if command is None:
                    return
                name = command[0].upper() if command else ""
                if name == "PING":
                    response = b"+PONG\r\n"
                elif name == "INFO":
                    body = f"# Server\r\nredis_version:{version}\r\n".encode()
                    response = f"${len(body)}\r\n".encode() + body + b"\r\n"
                elif name == "DBSIZE":
                    response = b":0\r\n"
                else:
                    response = b"-ERR unsupported QA command\r\n"
                self.wfile.write(response)
                self.wfile.flush()

    server = _RedisServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()


def _audit_json(module: str, port: int, *extra: str) -> dict[str, Any]:
    target = (
        f"http://127.0.0.1:{port}" if module in {"airflow", "docker", "grafana", "qdrant", "registry"} else "127.0.0.1"
    )
    args = parse_args([module, "-t", target, "--port", str(port), "--enum-cve", "--format", "json", *extra])
    stage = importlib.import_module(f"redposture_core.modules.{module}.stage")
    lines: list[str] = []
    AuditCommandRunner(
        args=args,
        spec=getattr(stage, f"build_{module}_spec")(args),
        emit_line=lines.append,
    ).run_plan(getattr(stage, f"build_{module}_plan")(args))
    records = [json.loads(line) for line in lines if json.loads(line).get("type") != "summary"]
    assert len(records) == 1
    return records[0]


def _audit_text(module: str, port: int, *extra: str) -> list[str]:
    args = parse_args([module, "-t", "127.0.0.1", "--port", str(port), "--enum-cve", *extra])
    stage = importlib.import_module(f"redposture_core.modules.{module}.stage")
    lines: list[str] = []
    AuditCommandRunner(
        args=args,
        spec=getattr(stage, f"build_{module}_spec")(args),
        emit_line=lines.append,
    ).run_plan(getattr(stage, f"build_{module}_plan")(args))
    return lines


@pytest.mark.parametrize(("version", "affected"), [("11.0.0", True), ("11.0.5", False)])
def test_grafana_live_http_vulnerable_and_fixed_versions(version: str, affected: bool) -> None:
    with _http_service("grafana", version) as port:
        record = _audit_json("grafana", port)
        text_lines = _audit_text("grafana", port)

    findings = {item["id"]: item for item in record["cve_enumeration"]["findings"]}
    assert ("CVE-2024-9264" in findings) is affected
    assert any("CVE-2024-9264 potentially affected" in line for line in text_lines) is affected
    if affected:
        assert findings["CVE-2024-9264"]["access_basis"] == "anonymous_access"
        assert findings["CVE-2024-9264"]["privileges_required"] == "L"


@pytest.mark.parametrize(("version", "affected"), [("7.0.3", True), ("7.0.4", False)])
def test_redis_live_resp_version_controls_cve_boundary(version: str, affected: bool) -> None:
    with _redis_service(version) as port:
        record = _audit_json("redis", port)

    assert record["implementation"] == "redis"
    assert record["server_version"] == version
    findings = {item["id"]: item for item in record["cve_enumeration"]["findings"]}
    assert ("CVE-2022-31144" in findings) is affected


def test_registry_live_nexus_fingerprint_and_version_feed_cve_enumeration() -> None:
    with _http_service("nexus", "3.68.0") as port:
        record = _audit_json("registry", port)

    assert record["is_nexus"] is True
    assert record["nexus_info"]["version"] == "3.68.0"
    findings = {item["id"]: item for item in record["cve_enumeration"]["findings"]}
    assert findings["CVE-2024-4956"]["product"] == "nexus_repository"


@pytest.mark.parametrize(
    ("kind", "module", "version", "cve_id", "affected"),
    [
        ("airflow", "airflow", "2.9.2", "CVE-2024-39877", True),
        ("airflow", "airflow", "2.9.3", "CVE-2024-39877", False),
        ("docker", "docker", "17.05.0", "CVE-2018-12608", True),
        ("docker", "docker", "17.06.0", "CVE-2018-12608", False),
        ("qdrant", "qdrant", "1.15.5", "CVE-2026-25628", True),
        ("qdrant", "qdrant", "1.15.6", "CVE-2026-25628", False),
    ],
)
def test_live_service_version_matrix_covers_vulnerable_and_fixed_boundaries(
    kind: str,
    module: str,
    version: str,
    cve_id: str,
    affected: bool,
) -> None:
    with _http_service(kind, version) as port:
        record = _audit_json(module, port)

    findings = {item["id"] for item in record["cve_enumeration"]["findings"]}
    assert (cve_id in findings) is affected
