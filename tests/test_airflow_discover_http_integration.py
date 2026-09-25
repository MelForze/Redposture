"""Wire-level QA for Airflow discovery across every read-only surface."""

from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import unquote, urlsplit

from redposture_core.clients.airflow_api import AirflowClient
from redposture_core.clients.http_session import HttpSessionPool
from redposture_core.modules.airflow.discover import DiscoverConfig, discover_task_logs, list_connections


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urlsplit(self.path)
        path = unquote(parsed.path)
        payloads: dict[str, dict[str, Any]] = {
            "/api/v2/variables": {
                "variables": [{"key": "warehouse_password", "value": "variableSecret123"}],
                "total_entries": 1,
            },
            "/api/v2/connections": {
                "connections": [{"connection_id": "warehouse", "password": "connectionSecret123"}],
                "total_entries": 1,
            },
            "/api/v2/dags": {"dags": [{"dag_id": "team/dag"}], "total_entries": 1},
            "/api/v2/dagSources/team/dag": {"content": 'password = "sourceSecret123"'},
            "/api/v2/dags/team/dag/dagRuns": {
                "dag_runs": [{"dag_run_id": "manual/run"}],
                "total_entries": 1,
            },
            "/api/v2/dags/team/dag/dagRuns/manual/run/taskInstances": {
                "task_instances": [{"task_id": "extract/task", "try_number": 1}],
                "total_entries": 1,
            },
            "/api/v2/dags/team/dag/dagRuns/manual/run/taskInstances/extract/task/logs/1": {
                "content": [{"event": "api_key=logSecret12345"}]
            },
        }
        payload = payloads.get(path)
        if payload is None:
            self.send_error(404)
            return
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


@contextmanager
def _serve():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_real_http_client_discovers_source_configuration_and_log_secrets() -> None:
    with _serve() as server:
        pool = HttpSessionPool(timeout=2.0, insecure=True)
        try:
            client = AirflowClient(pool, scheme="http", host="127.0.0.1", port=int(server.server_port))
            report = discover_task_logs(
                client,
                "v2",
                DiscoverConfig(include_dag_sources=True, include_variables=True, include_connections=True),
            )
        finally:
            pool.close()

    assert report["status"] == "complete"
    assert report["variable_keys"] == ["warehouse_password"]
    assert {finding["source_kind"] for finding in report["findings"]} == {
        "dag_source",
        "variable",
        "connection",
        "task_log",
    }
    assert report["bytes_scanned"] == sum(
        report[name]
        for name in (
            "dag_source_bytes_scanned",
            "variable_bytes_scanned",
            "connection_bytes_scanned",
            "log_bytes_scanned",
        )
    )


def test_real_http_client_lists_complete_connection_contents() -> None:
    with _serve() as server:
        pool = HttpSessionPool(timeout=2.0, insecure=True)
        try:
            client = AirflowClient(pool, scheme="http", host="127.0.0.1", port=int(server.server_port))
            result = list_connections(client, "v2")
        finally:
            pool.close()

    assert result["count"] == 1
    assert result["total"] == 1
    assert result["truncated"] is False
    assert result["connections"] == [{"connection_id": "warehouse", "password": "connectionSecret123"}]
