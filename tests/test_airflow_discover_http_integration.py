"""Wire-level QA for Airflow discovery across every read-only surface."""

from __future__ import annotations

import json
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from redposture_core.clients.airflow_api import AirflowClient
from redposture_core.clients.http_session import HttpSessionPool
from redposture_core.discovery_values import DiskBackedText
from redposture_core.modules.airflow.discover import (
    DiscoverConfig,
    _collection,
    _NetworkBudget,
    discover_task_logs,
    list_connections,
)


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
def _serve(handler: type[BaseHTTPRequestHandler] = _Handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
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


def test_real_http_client_retries_oversized_collection_at_same_offset() -> None:
    items = [{"key": f"item-{index:03d}", "value": "a" * 25_000} for index in range(100)]
    requests: list[tuple[int, int]] = []

    class Handler(_Handler):
        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            parsed = urlsplit(self.path)
            args = parse_qs(parsed.query)
            size = int(args["limit"][0])
            offset = int(args["offset"][0])
            requests.append((size, offset))
            body = json.dumps({"variables": items[offset : offset + size], "total_entries": len(items)}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except BrokenPipeError:
                pass

    with _serve(Handler) as server:
        pool = HttpSessionPool(timeout=5.0, insecure=True)
        try:
            client = AirflowClient(pool, scheme="http", host="127.0.0.1", port=int(server.server_port))
            result = _collection(
                client,
                "/api/v2/variables",
                "variables",
                None,
                time.monotonic() + 20,
                network_budget=_NetworkBudget(300_000_000),
            )
        finally:
            pool.close()

    assert result.complete is True
    assert [item["key"] for item in result.items] == [item["key"] for item in items]
    assert requests == [(100, 0), (50, 0), (50, 50)]


def test_real_http_client_streams_single_oversized_variable_without_truncating() -> None:
    token = "tok_" + "Ab0" * 800_000
    body = json.dumps({"variables": [{"key": "api_token", "value": token}], "total_entries": 1}).encode()
    assert len(body) > 2 * 1024 * 1024

    class Handler(_Handler):
        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            if urlsplit(self.path).path.endswith("/dags"):
                response = json.dumps({"dags": [], "total_entries": 0}).encode()
            else:
                response = body
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            try:
                self.wfile.write(response)
            except BrokenPipeError:
                pass

    with _serve(Handler) as server:
        pool = HttpSessionPool(timeout=5.0, insecure=True)
        try:
            client = AirflowClient(pool, scheme="http", host="127.0.0.1", port=int(server.server_port))
            report = discover_task_logs(client, "v1", DiscoverConfig(include_variables=True, max_seconds=30))
        finally:
            pool.close()

    assert report["status"] == "complete", report["partial_reasons"]
    assert len(report["findings"]) == 1
    value = report["findings"][0]["value"]
    assert isinstance(value, DiskBackedText)
    assert "".join(value.iter_text_chunks()) == token
    value.close()


def test_real_http_client_reads_a_log_page_larger_than_the_buffered_response() -> None:
    log_body = json.dumps(
        {"content": ("ordinary task output\n" * 120_000) + "api_key=glpat-abcdefghijklmnopqrst\n"}
    ).encode()
    assert len(log_body) > 2 * 1024 * 1024

    class Handler(_Handler):
        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            if urlsplit(self.path).path.endswith("/logs/1"):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(log_body)))
                self.end_headers()
                self.wfile.write(log_body)
                return
            super().do_GET()

    with _serve(Handler) as server:
        pool = HttpSessionPool(timeout=5.0, insecure=True)
        try:
            client = AirflowClient(pool, scheme="http", host="127.0.0.1", port=int(server.server_port))
            report = discover_task_logs(client, "v2", DiscoverConfig())
        finally:
            pool.close()

    assert report["status"] == "complete", report["partial_reasons"]
    assert any(finding["value"] == "glpat-abcdefghijklmnopqrst" for finding in report["findings"])


def test_real_http_client_streams_a_large_plain_text_log() -> None:
    body = (b"ordinary task output\n" * 120_000) + b"password=plainTextSecret123\n"
    assert len(body) > 2 * 1024 * 1024

    class Handler(_Handler):
        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            if urlsplit(self.path).path.endswith("/logs/1"):
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            super().do_GET()

    with _serve(Handler) as server:
        pool = HttpSessionPool(timeout=5.0, insecure=True)
        try:
            client = AirflowClient(pool, scheme="http", host="127.0.0.1", port=int(server.server_port))
            report = discover_task_logs(client, "v2", DiscoverConfig())
        finally:
            pool.close()

    assert report["status"] == "complete", report["partial_reasons"]
    assert any(finding["value"] == "plainTextSecret123" for finding in report["findings"])


def test_large_wrapped_airflow2_log_streams_only_log_content() -> None:
    wrapped = (
        '[("glpat-abcdefghijklmnopqrst", "*** Found local files:\\n'
        + "***   * /logs/"
        + ("x" * 180)
        + "/password=notASecret123\\n"
        + ("ordinary task output\\n" * 120_000)
        + 'password=wrappedSecret123")]'
    )
    body = json.dumps({"content": wrapped}).encode()
    assert len(body) > 2 * 1024 * 1024

    class Handler(_Handler):
        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            if urlsplit(self.path).path.endswith("/logs/1"):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            super().do_GET()

    with _serve(Handler) as server:
        pool = HttpSessionPool(timeout=5.0, insecure=True)
        try:
            client = AirflowClient(pool, scheme="http", host="127.0.0.1", port=int(server.server_port))
            report = discover_task_logs(client, "v2", DiscoverConfig())
        finally:
            pool.close()

    assert report["status"] == "complete", report["partial_reasons"]
    assert any(finding["value"] == "wrappedSecret123" for finding in report["findings"])
    assert not any(finding["value"] == "glpat-abcdefghijklmnopqrst" for finding in report["findings"])
    assert not any(finding["value"] == "notASecret123" for finding in report["findings"])


def test_streamed_log_retry_does_not_scan_a_later_denial_body() -> None:
    first_body = json.dumps({"content": "ordinary task output\n" * 120_000}).encode()
    denied_body = json.dumps({"content": "api_key=glpat-abcdefghijklmnopqrst"}).encode()
    requests = 0

    class Handler(_Handler):
        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            nonlocal requests
            if urlsplit(self.path).path.endswith("/logs/1"):
                requests += 1
                body, status = (first_body, 200) if requests == 1 else (denied_body, 403)
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            super().do_GET()

    with _serve(Handler) as server:
        pool = HttpSessionPool(timeout=5.0, insecure=True)
        try:
            client = AirflowClient(pool, scheme="http", host="127.0.0.1", port=int(server.server_port))
            report = discover_task_logs(client, "v2", DiscoverConfig())
        finally:
            pool.close()

    assert requests == 2
    assert report["status"] == "partial"
    assert not any(finding["value"] == "glpat-abcdefghijklmnopqrst" for finding in report["findings"])


def test_streamed_log_page_continues_to_the_next_token_page() -> None:
    first_body = json.dumps(
        {
            "content": [{"event": "ordinary task output\n" * 120_000}, {"event": "api_key=glpat-abcdefghijklmnopqrst"}],
            "continuation_token": "next-page",
        }
    ).encode()
    second_body = json.dumps({"content": [{"event": "password=secondPageSecret123"}]}).encode()
    requested_paths: list[str] = []

    class Handler(_Handler):
        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            if urlsplit(self.path).path.endswith("/logs/1"):
                requested_paths.append(self.path)
                body = second_body if "token=next-page" in self.path else first_body
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            super().do_GET()

    with _serve(Handler) as server:
        pool = HttpSessionPool(timeout=5.0, insecure=True)
        try:
            client = AirflowClient(pool, scheme="http", host="127.0.0.1", port=int(server.server_port))
            report = discover_task_logs(client, "v2", DiscoverConfig())
        finally:
            pool.close()

    assert report["status"] == "complete", report["partial_reasons"]
    assert {finding["value"] for finding in report["findings"]} >= {
        "glpat-abcdefghijklmnopqrst",
        "secondPageSecret123",
    }
    assert any("token=next-page" in path for path in requested_paths)


def test_streamed_log_keeps_early_finding_but_marks_corrupt_json_partial() -> None:
    body = (
        b'{"content":"api_key=glpat-abcdefghijklmnopqrst\\n'
        + (b"ordinary task output\\n" * 120_000)
        + b'","continuation_token":"next"'  # no closing brace
    )
    assert len(body) > 2 * 1024 * 1024

    class Handler(_Handler):
        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            if urlsplit(self.path).path.endswith("/logs/1"):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            super().do_GET()

    with _serve(Handler) as server:
        pool = HttpSessionPool(timeout=5.0, insecure=True)
        try:
            client = AirflowClient(pool, scheme="http", host="127.0.0.1", port=int(server.server_port))
            report = discover_task_logs(client, "v2", DiscoverConfig())
        finally:
            pool.close()

    assert report["status"] == "partial"
    assert any(finding["value"] == "glpat-abcdefghijklmnopqrst" for finding in report["findings"])


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


def test_real_http_client_streams_large_v1_dag_source_with_url_prefix() -> None:
    source = (b"ordinary DAG source line\n" * 200) + b"api_token=glpat-abcdefghijklmnopqrst\n" + b"tail\n"

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - HTTP handler interface
            route = urlsplit(self.path).path
            if route == "/airflow/api/v1/dags":
                body = json.dumps(
                    {"dags": [{"dag_id": "example", "file_token": "source-token"}], "total_entries": 1}
                ).encode()
                media = "application/json"
            elif route == "/airflow/api/v1/dagSources/source-token":
                body = source
                media = "text/plain"
            elif route == "/airflow/api/v1/dags/example/dagRuns":
                body = b'{"dag_runs": [], "total_entries": 0}'
                media = "application/json"
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", media)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    with _serve(Handler) as server:
        pool = HttpSessionPool(timeout=2.0)
        try:
            client = AirflowClient(
                pool, scheme="http", host="127.0.0.1", port=int(server.server_port), base_path="/airflow"
            )
            report = discover_task_logs(
                client, "v1", DiscoverConfig(max_dags=1, max_bytes=128, include_dag_sources=True)
            )
        finally:
            pool.close()
    assert report["status"] == "complete", report
    assert report["dag_source_bytes_scanned"] == len(source)
    assert len(report["findings"]) == 1


def test_real_http_client_streams_large_v2_json_dag_source() -> None:
    source = ("ordinary DAG source line\n" * 200) + "api_token=glpat-abcdefghijklmnopqrst\n" + "tail\n"
    body = json.dumps({"content": source}).encode()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - HTTP handler interface
            route = urlsplit(self.path).path
            if route == "/api/v2/dags":
                payload = json.dumps({"dags": [{"dag_id": "example"}], "total_entries": 1}).encode()
            elif route == "/api/v2/dagSources/example":
                payload = body
            elif route == "/api/v2/dags/example/dagRuns":
                payload = b'{"dag_runs": [], "total_entries": 0}'
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    with _serve(Handler) as server:
        pool = HttpSessionPool(timeout=2.0)
        try:
            client = AirflowClient(pool, scheme="http", host="127.0.0.1", port=int(server.server_port))
            report = discover_task_logs(
                client, "v2", DiscoverConfig(max_dags=1, max_bytes=128, include_dag_sources=True)
            )
        finally:
            pool.close()
    assert report["status"] == "complete", report
    assert report["dag_source_bytes_scanned"] == len(body)
    assert len(report["findings"]) == 1
