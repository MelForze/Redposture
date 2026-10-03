"""Branch-guided contracts for large audit action modules."""

from __future__ import annotations

import json
from contextlib import contextmanager
from typing import Any

import pytest

from redposture_core.modules.consul import actions as consul_actions
from redposture_core.modules.elastic import actions as elastic_actions
from redposture_core.modules.elastic.discover import DiscoverRequest
from redposture_core.modules.postgres import actions as postgres_actions


def test_consul_health_instances_keep_only_related_checks_and_nested_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = [
        "not an instance",
        {
            "Node": {"Node": "node-b", "Address": "10.0.0.2", "Datacenter": "dc1"},
            "Service": {"ID": "api-1", "Address": "10.0.0.3", "Port": "bad", "Meta": {"owner": "qa"}},
            "Checks": [
                {"CheckID": "unrelated", "ServiceID": "other", "Status": "critical"},
                {
                    "CheckID": "service:api-1",
                    "Name": "API health",
                    "Status": "passing",
                    "Definition": {
                        "Args": ["curl", " ", "https://api.example.test/health"],
                        "EnterpriseMeta": {"Namespace": "prod", "Partition": "tenant-a"},
                        "HTTP": "https://api.example.test/health",
                    },
                },
            ],
        },
    ]
    monkeypatch.setattr(
        consul_actions,
        "_consul_get_json_any",
        lambda *_args, **_kwargs: (200, payload, None, False, False),
    )
    instances, error = consul_actions._consul_health_service_instances(
        "127.0.0.1", 8500, "api/web", 1, scheme="http", insecure=False
    )

    assert error is None and instances is not None and len(instances) == 1
    assert instances[0]["service_port"] is None
    assert instances[0]["meta"] == {"owner": "qa"}
    assert len(instances[0]["checks"]) == 1
    check = instances[0]["checks"][0]
    assert check["check_id"] == "service:api-1"
    assert check["args"] == ["curl", "https://api.example.test/health"]
    assert check["namespace"] == "prod" and check["partition"] == "tenant-a"
    assert json.loads(check["definition_raw"])["HTTP"] == "https://api.example.test/health"


@pytest.mark.parametrize(
    ("status", "expected"),
    [(401, "Unauthorized"), (403, "Forbidden"), (503, "status=503")],
)
def test_consul_health_instances_preserve_auth_and_upstream_errors(
    monkeypatch: pytest.MonkeyPatch, status: int, expected: str
) -> None:
    monkeypatch.setattr(
        consul_actions,
        "_consul_get_json_any",
        lambda *_args, **_kwargs: (status, {}, None, False, False),
    )
    assert consul_actions._consul_health_service_instances(
        "127.0.0.1", 8500, "api", 1, scheme="http", insecure=False
    ) == (None, expected)


def test_postgres_remote_inventory_retries_transport_and_closes_each_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    opened: list[int] = []
    closed: list[int] = []

    class Socket:
        def __init__(self, number: int) -> None:
            self.number = number

        def close(self) -> None:
            closed.append(self.number)

    @contextmanager
    def open_socket(*_args: Any, **_kwargs: Any):
        number = len(opened) + 1
        opened.append(number)
        yield Socket(number)

    def authenticate(sock: Socket, **_kwargs: Any) -> None:
        if sock.number == 1:
            raise OSError("connection reset during startup")

    expected = (["public.events"], [], [], [], 1, None)
    monkeypatch.setattr(postgres_actions, "_pg_open_socket", open_socket)
    monkeypatch.setattr(postgres_actions, "_pg_startup_and_auth", authenticate)
    monkeypatch.setattr(postgres_actions, "_pg_collect_database_artifacts", lambda *_args, **_kwargs: expected)
    monkeypatch.setattr(postgres_actions, "_pg_send_terminate", lambda _sock: None)
    monkeypatch.setattr(postgres_actions.time, "sleep", lambda _seconds: None)

    actual = postgres_actions._pg_collect_database_artifacts_remote(
        "127.0.0.1",
        5432,
        1,
        1,
        "observer",
        "secret",
        "app",
        include_database_prefix=False,
        show_tables=True,
        show_row_counts=False,
        show_columns=False,
        table_targets=[],
        table_columns=[],
        dump_table_rows=False,
        dump_row_limit=None,
    )
    assert actual == expected
    assert opened == [1, 2] and closed == [1, 2]


def test_elastic_inventory_parsers_deduplicate_and_skip_malformed_entries() -> None:
    plugins = elastic_actions._extract_cat_plugins(
        b'[{"name":"node-a","component":"analysis-icu","version":"8.15.0"},'
        b'{"name":"node-b","component":"analysis-kuromoji","version":"8.15.0"},null]'
    )
    assert [(item["node"], item["component"]) for item in plugins] == [
        ("node-a", "analysis-icu"),
        ("node-b", "analysis-kuromoji"),
    ]
    assert elastic_actions._parse_visible_indices(
        b'{"indices":[{"name":"logs"},{"name":"logs"},{"name":"metrics"},{"name":0},null]}', cat=False
    ) == ["logs", "metrics"]
    assert elastic_actions._parse_visible_indices(
        b'[{"index":"logs"},{"index":"logs"},{"index":"metrics"},null]', cat=True
    ) == ["logs", "metrics"]
    assert elastic_actions._parse_visible_indices(b"not-json", cat=True) is None


def test_elastic_plugin_inventory_falls_back_to_plaintext_and_keeps_error_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payloads = [
        (200, b"node-a analysis-icu 8.15.0 ICU analysis\ninvalid\nnode-b analysis-kuromoji 8.15.0", {}, None),
        (403, b"denied", {}, None),
        (503, b"unavailable", {}, None),
        (0, b"", {}, "connection reset"),
    ]
    monkeypatch.setattr(elastic_actions, "_elastic_request", lambda *_args, **_kwargs: payloads.pop(0))
    kwargs = dict(scheme="https", insecure=True, ca_file=None, auth_headers={"Authorization": "Bearer token"})
    plugins, error = elastic_actions._fetch_cat_plugins("127.0.0.1", 9200, 1.0, **kwargs)
    assert error is None and plugins is not None
    assert [(item["node"], item["component"], item["description"]) for item in plugins] == [
        ("node-a", "analysis-icu", "ICU analysis"),
        ("node-b", "analysis-kuromoji", "-"),
    ]
    assert elastic_actions._fetch_cat_plugins("127.0.0.1", 9200, 1.0, **kwargs) == (None, "Access Denied")
    assert elastic_actions._fetch_cat_plugins("127.0.0.1", 9200, 1.0, **kwargs) == (None, "status=503")
    assert elastic_actions._fetch_cat_plugins("127.0.0.1", 9200, 1.0, **kwargs) == (None, "connection reset")


def test_consul_ssrf_normalization_handles_ipv6_ports_paths_and_duplicates() -> None:
    assert consul_actions._normalize_ssrf_urls(
        "https://[::1]/first?old=1,https://[::1]/first?old=1",
        "8500,8501",
        "/health?probe=1",
    ) == [
        "https://[::1]:8500/health?probe=1",
        "https://[::1]:8501/health?probe=1",
    ]
    with pytest.raises(ValueError, match="invalid port"):
        consul_actions._normalize_ssrf_urls("127.0.0.1", "bad-port", "/")
    assert consul_actions._normalize_ssrf_urls("127.0.0.1", "8500", "http://[::1") == []


def test_consul_check_dump_renders_structured_fields_without_multiline_injection() -> None:
    record = {
        "is_consul": True,
        "host": "127.0.0.1",
        "port": 8500,
        "dump_requested": True,
        "checks_list_requested": True,
        "checks_list_source": "agent",
        "check_dump_id": "service:api",
        "checks_list": [
            None,
            {"name": "missing id"},
            {
                "check_id": "service:api",
                "name": "API\nhealth",
                "status": "passing",
                "service_id": "api",
                "script": "/bin/check",
                "type": "script",
                "namespace": "prod",
                "partition": "tenant-a",
                "http": "https://api.example.test/health",
                "args": ["--check", "api"],
                "interval": "10s",
                "timeout": "1s",
                "notes": "line one\nline two",
                "definition_raw": '{"HTTP":"https://api.example.test/health"}',
                "output": "healthy\nnow",
            },
        ],
    }
    lines = consul_actions._detail_lines(record, "txt", debug=True)
    assert any("Agent Checks (id:service:api) (source:agent) (count:3)" in line for line in lines)
    assert any("Check (id:service:api) (status:passing)" in line for line in lines)
    assert any("arg[0]=--check" in line for line in lines)
    assert any("namespace=prod" in line for line in lines)
    assert any("notes=line one line two" in line for line in lines)
    assert any("output=healthy now" in line for line in lines)
    assert consul_actions._detail_lines(record, "json", debug=True) == []


def test_postgres_file_read_invalid_large_object_oid_keeps_directory_diagnostic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queries: list[str] = []

    def query(_sock: object, sql: str):
        queries.append(sql)
        if "pg_read_file" in sql:
            return [], "permission denied"
        if "pg_ls_dir" in sql:
            return [], "permission denied"
        if "lo_import" in sql:
            return [["not-an-oid"]], None
        pytest.fail(f"unexpected query: {sql}")

    monkeypatch.setattr(postgres_actions, "_pg_query_rows", query)
    rows, error, method, attempts = postgres_actions._pg_try_read_server_file(object(), r"C:\secrets\token.txt")
    assert rows is None and method is None
    assert error is not None and "invalid oid" in error
    assert attempts[0]["method"] == "pg_read_file" and attempts[-1]["method"] == "lo_import"
    assert r"pg_ls_dir('C:\secrets'" in queries[1]
    assert not any("pg_switch_wal" in sql for sql in queries)


def test_postgres_table_column_output_renders_limits_and_errors() -> None:
    record = {
        "host": "127.0.0.1",
        "port": 5432,
        "database": "app",
        "show_columns": True,
        "show_columns_limit": 1,
        "table_columns_info": [
            None,
            {"table": "public.accounts", "columns": ["id", "secret"], "error": None},
            {"table": "public.blocked", "columns": [], "error": "permission denied"},
        ],
    }
    json_lines = postgres_actions._format_table_columns_detail_records(record, "json")
    assert len(json_lines) == 2
    first, second = (json.loads(line) for line in json_lines)
    assert first["columns"] == ["id"] and first["columns_truncated"] is True
    assert first["table"] == "public.accounts" and second["error"] == "permission denied"
    txt_lines = postgres_actions._format_table_columns_detail_records(record, "txt")
    assert any("showing:1 of 2" in line for line in txt_lines)
    assert any("<error:permission denied>" in line for line in txt_lines)
    assert not any("secret" in line for line in txt_lines)


def test_elastic_discovery_http_pool_preserves_auth_path_and_truncation(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[tuple[str, str, dict[str, str], bytes | None]] = []

    class Response:
        status = 206
        body = b"partial"
        headers = {"X-Test": "present"}
        error = None
        truncated = True

    class Pool:
        def request(self, method: str, url: str, *, headers: dict[str, str], body: bytes | None, **_kwargs: Any):
            requests.append((method, url, headers, body))
            return Response()

    captured: list[Any] = []

    def run(requester, **_kwargs: Any):
        captured.append(
            requester(DiscoverRequest(method="POST", path="/index/_search", body=b"{}", headers={"X-Probe": "1"}))
        )
        return "ok"

    monkeypatch.setattr(elastic_actions, "run_discovery", run)
    assert (
        elastic_actions._collect_discover_report(
            "search.example.test",
            9200,
            1.0,
            scheme="https",
            insecure=True,
            ca_file=None,
            auth_headers={"Authorization": "Basic dGVzdA=="},
            http_pool=Pool(),
        )
        == "ok"
    )
    assert requests[0][0] == "POST" and requests[0][3] == b"{}"
    assert requests[0][1] == "https://search.example.test:9200/index/_search"
    assert requests[0][2]["Authorization"] == "Basic dGVzdA=="
    assert requests[0][2]["X-Probe"] == "1"
    assert captured[0].truncated is True and captured[0].headers == {"X-Test": "present"}
