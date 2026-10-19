"""Loopback HTTP client checks for newly supported product fingerprints."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core import web_panels
from redposture_core.modules.kafka import ui


@contextmanager
def _server(routes: dict[str, tuple[int, str, str]]) -> Iterator[int]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            status, content_type, body = routes.get(self.path, (404, "text/plain", "missing"))
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            if self.path == "/" and content_type == "application/openapi+json":
                self.send_header("Server", "postgrest/12.0")
            self.end_headers()
            self.wfile.write(body.encode())

        def log_message(self, *_args: Any) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield int(server.server_port)
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


@pytest.mark.parametrize(
    ("routes", "product"),
    [
        (
            {
                "/": (200, "text/html", "<title>AKHQ</title>"),
                "/api/me": (200, "application/json", '{"logged":false,"roles":[{"actions":["READ"]}]}'),
            },
            "akhq",
        ),
        (
            {
                "/": (200, "text/html", "<title>Redpanda Console</title>"),
                "/admin/startup": (200, "application/json", "{}"),
                "/api/topics": (200, "application/json", '[{"name":"orders"}]'),
            },
            "redpanda_console",
        ),
        (
            {
                "/topics": (200, "application/vnd.kafka.v2+json", '["orders"]'),
                "/v3/clusters": (200, "application/json", '{"kind":"KafkaClusterList","data":[]}'),
            },
            "kafka_rest_proxy",
        ),
        (
            {
                "/": (200, "application/json", '{"version":"3.7.0","commit":"abc","kafka_cluster_id":"id"}'),
                "/connectors": (200, "application/json", '["db"]'),
            },
            "kafka_connect",
        ),
        (
            {
                "/info": (
                    200,
                    "application/json",
                    '{"KsqlServerInfo":{"version":"1.0","kafkaClusterId":"id","serverStatus":"RUNNING"}}',
                )
            },
            "ksqldb",
        ),
        ({"/subjects": (200, "application/vnd.schemaregistry.v1+json", '["orders-value"]')}, "schema_registry"),
    ],
)
def test_kafka_network_client_detects_each_http_surface(routes: dict[str, tuple[int, str, str]], product: str) -> None:
    with _server(routes) as port:
        ctx = SimpleNamespace(
            host="127.0.0.1",
            port=port,
            target=SimpleNamespace(scheme="http", path="", explicit_port=port),
            args=SimpleNamespace(timeout=0.5, port=None, _proxy_config=None),
        )
        state = SimpleNamespace(ui_http=None, ui_base=None, ui_vendor=None, ui_auth_type=None)
        try:
            result = ui.detect_ui(ctx, state)
            assert result["is_kafka"] is True and result["ui_vendor"] == product
        finally:
            if state.ui_http is not None:
                state.ui_http.close()


def test_postgrest_network_probe_proves_table_access() -> None:
    spec = json.dumps({"swagger": "2.0", "paths": {"/items": {"get": {}}}})
    routes = {
        "/": (200, "application/openapi+json", spec),
        "/items?limit=1": (200, "application/json", '[{"name":"alpha"}]'),
    }
    with _server(routes) as port:
        ctx = SimpleNamespace(
            host="127.0.0.1",
            port=port,
            target=SimpleNamespace(scheme="http", path="", explicit_port=port),
            args=SimpleNamespace(timeout=1, secure=False, _proxy_config=None),
        )
        result = web_panels.detect_panel("postgres", ctx)
        assert result is not None and result["ui_product"] == "postgrest"
        assert result["ui"]["anonymous_read"] is True


def test_foreign_web_app_never_confirms_new_panel() -> None:
    with _server({"/": (200, "text/html", "<title>Dashboard</title>")}) as port:
        ctx = SimpleNamespace(
            host="127.0.0.1",
            port=port,
            target=SimpleNamespace(scheme="http", path="", explicit_port=port),
            args=SimpleNamespace(timeout=0.5, secure=False, _proxy_config=None),
        )
        assert web_panels.detect_panel("kubeapi", ctx) is None
        assert web_panels.detect_panel("postgres", ctx) is None


@pytest.mark.parametrize(
    ("module", "routes", "expected"),
    [
        (
            "kafka",
            {
                "/topics": (200, "application/vnd.kafka.v2+json", '["orders"]'),
                "/v3/clusters": (200, "application/json", '{"kind":"KafkaClusterList","data":[]}'),
            },
            "Kafka REST Proxy",
        ),
        (
            "postgres",
            {
                "/": (200, "application/openapi+json", '{"swagger":"2.0","paths":{"/items":{"get":{}}}}'),
                "/items?limit=1": (200, "application/json", '[{"name":"alpha"}]'),
            },
            "PostgREST",
        ),
        (
            "kubeapi",
            {"/": (200, "text/html", "<title>Kubernetes Dashboard</title><kd-root></kd-root>")},
            "Kubernetes Dashboard",
        ),
    ],
)
def test_cli_lifecycle_detects_http_surface_without_backend(
    module: str, routes: dict[str, tuple[int, str, str]], expected: str, tmp_path: Path
) -> None:
    script = Path(__file__).resolve().parents[1] / "redposture.py"
    output = tmp_path / "report.txt"
    with _server(routes) as port:
        result = subprocess.run(
            [
                sys.executable,
                str(script),
                module,
                "-t",
                f"http://127.0.0.1:{port}",
                "--timeout",
                "0.2",
                "-r",
                "0",
                "--no-color",
                "-o",
                str(output),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    assert result.returncode == 0, result.stderr
    assert expected in result.stdout
    assert "\x1b[" not in result.stdout
    assert expected in output.read_text()
    assert "\x1b[" not in output.read_text()


def test_kafka_http_surface_saved_json_has_product_and_no_ansi(tmp_path: Path) -> None:
    script = Path(__file__).resolve().parents[1] / "redposture.py"
    output = tmp_path / "report.json"
    routes = {
        "/topics": (200, "application/vnd.kafka.v2+json", '["orders"]'),
        "/v3/clusters": (200, "application/json", '{"kind":"KafkaClusterList","data":[]}'),
    }
    with _server(routes) as port:
        result = subprocess.run(
            [
                sys.executable,
                str(script),
                "kafka",
                "-t",
                f"http://127.0.0.1:{port}",
                "--timeout",
                "0.2",
                "-r",
                "0",
                "-f",
                "json",
                "-o",
                str(output),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
    assert result.returncode == 0, result.stderr
    saved = output.read_text()
    assert "\x1b[" not in saved
    records = [json.loads(line) for line in saved.splitlines() if line.strip()]
    assert any(record.get("ui_vendor") == "kafka_rest_proxy" for record in records)
