"""Airflow DAG-log discovery contracts for API v1 and v2."""

from __future__ import annotations

import json
import time
from types import SimpleNamespace
from urllib.parse import quote

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.clients.airflow_api import AirflowClient, AirflowResponse
from redposture_core.modules.airflow import actions, policy, render
from redposture_core.modules.airflow.discover import DiscoverConfig, _collection, _read_log, discover_task_logs
from redposture_core.modules.airflow.stage import build_airflow_plan, build_airflow_spec
from redposture_core.stage_runtime import AuditCommandRunner


def _response(payload: object, status: int = 200, *, truncated: bool = False) -> AirflowResponse:
    return AirflowResponse(
        http_status=status,
        headers={"Content-Type": "application/json"},
        body=json.dumps(payload).encode(),
        truncated=truncated,
    )


class _FakeClient:
    def __init__(self, responses: dict[str, AirflowResponse]) -> None:
        self.base_url = "http://127.0.0.1:8080"
        self.responses = responses
        self.calls: list[tuple[str, dict[str, object]]] = []

    def get(self, path: str, **kwargs: object) -> AirflowResponse:
        self.calls.append((path, kwargs))
        return self.responses.get(path, _response({"detail": "missing"}, 404))


def _paths(prefix: str, dag: str = "example", run: str = "manual__2026-09-13") -> tuple[str, str, str]:
    dag_path = f"{prefix}/dags"
    run_path = f"{dag_path}/{quote(dag, safe='')}/dagRuns"
    task_path = f"{run_path}/{quote(run, safe='')}/taskInstances"
    return dag_path, run_path, task_path


def test_default_discovery_walks_more_than_one_hundred_dags_without_count_limit() -> None:
    class ManyDagsClient:
        def get(self, path: str, **_kwargs: object) -> AirflowResponse:
            if path == "/api/v1/dags?limit=100&offset=0":
                return _response({"dags": [{"dag_id": f"dag-{i}"} for i in range(100)], "total_entries": 101})
            if path == "/api/v1/dags?limit=100&offset=100":
                return _response({"dags": [{"dag_id": "dag-100"}], "total_entries": 101})
            if "/dagRuns?" in path:
                return _response({"dag_runs": [], "total_entries": 0})
            raise AssertionError(path)

    report = discover_task_logs(ManyDagsClient(), "v1", DiscoverConfig())
    assert report["status"] == "complete"
    assert report["dags_scanned"] == 101
    assert report["partial_reasons"] == []


def test_v1_discover_reads_continuation_and_finds_secrets() -> None:
    dag_path, run_path, task_path = _paths("/api/v1")
    log_path = f"{task_path}/extract/logs/1"
    client = _FakeClient(
        {
            f"{dag_path}?limit=2&offset=0": _response({"dags": [{"dag_id": "example"}], "total_entries": 1}),
            f"{run_path}?limit=2&offset=0&order_by=-execution_date": _response(
                {"dag_runs": [{"dag_run_id": "manual__2026-09-13"}], "total_entries": 1}
            ),
            f"{task_path}?limit=3&offset=0": _response(
                {"task_instances": [{"task_id": "extract", "try_number": 1}], "total_entries": 1}
            ),
            f"{log_path}?full_content=false": _response(
                {"content": "api_key=firstsecret123\n", "continuation_token": "next/+?"}
            ),
            f"{log_path}?full_content=false&token=next%2F%2B%3F": _response(
                {"content": "password=secondsecret", "continuation_token": None}
            ),
        }
    )

    streamed: list[dict[str, object]] = []
    report = discover_task_logs(
        client,
        "v1",
        DiscoverConfig(max_dags=2, max_runs=2, max_tasks=3, max_logs=3),
        on_finding=streamed.append,
    )

    assert report["status"] == "complete"
    assert (report["dags_scanned"], report["runs_scanned"], report["logs_scanned"]) == (1, 1, 1)
    assert {(finding["type"], finding["value"]) for finding in report["findings"]} == {
        ("api_key", "firstsecret123"),
        ("password", "secondsecret"),
    }
    assert [(finding["type"], finding["value"]) for finding in streamed] == [
        (finding["type"], finding["value"]) for finding in report["findings"]
    ]
    assert all(
        streamed_item is not report_item
        for streamed_item, report_item in zip(streamed, report["findings"], strict=True)
    )
    assert all(finding["task_id"] == "extract" and finding["try_number"] == 1 for finding in report["findings"])
    log_calls = [(path, kwargs) for path, kwargs in client.calls if "/logs/" in path]
    assert len(log_calls) == 2
    assert all(kwargs["extra_headers"] == {"Accept": "application/json"} for _path, kwargs in log_calls)


def test_discover_scans_dag_sources_variables_connections_and_logs() -> None:
    dag_path, run_path, task_path = _paths("/api/v1")
    client = _FakeClient(
        {
            "/api/v1/variables?limit=100&offset=0": _response(
                {
                    "variables": [{"key": "warehouse_password", "value": "variableSecret123"}],
                    "total_entries": 1,
                }
            ),
            "/api/v1/connections?limit=100&offset=0": _response(
                {
                    "connections": [{"connection_id": "warehouse", "password": "connectionSecret123"}],
                    "total_entries": 1,
                }
            ),
            f"{dag_path}?limit=100&offset=0": _response(
                {"dags": [{"dag_id": "example", "file_token": "token/one"}], "total_entries": 1}
            ),
            "/api/v1/dagSources/token%2Fone": _response({"content": 'password = "sourceSecret123"'}),
            f"{run_path}?limit=100&offset=0&order_by=-execution_date": _response(
                {"dag_runs": [{"dag_run_id": "manual__2026-09-13"}], "total_entries": 1}
            ),
            f"{task_path}?limit=100&offset=0": _response(
                {"task_instances": [{"task_id": "extract", "try_number": 1}], "total_entries": 1}
            ),
            f"{task_path}/extract/logs/1?full_content=false": _response({"content": "api_key=logSecret12345"}),
        }
    )

    report = discover_task_logs(
        client,
        "v1",
        DiscoverConfig(include_dag_sources=True, include_variables=True, include_connections=True),
    )

    assert report["status"] == "complete"
    assert report["variable_keys"] == ["warehouse_password"]
    assert (report["dag_sources_scanned"], report["variables_scanned"], report["connections_scanned"]) == (1, 1, 1)
    assert report["logs_scanned"] == 1
    assert {finding["source_kind"] for finding in report["findings"]} == {
        "dag_source",
        "variable",
        "connection",
        "task_log",
    }
    assert any(finding["place"].startswith("dag_source:example") for finding in report["findings"])
    assert any(finding["place"].startswith("variable:warehouse_password") for finding in report["findings"])
    assert any(finding["place"].startswith("connection:warehouse") for finding in report["findings"])
    assert any(finding["place"].startswith("log:example/") for finding in report["findings"])
    source_calls = [(path, kwargs) for path, kwargs in client.calls if "/dagSources/" in path]
    assert source_calls == [
        (
            "/api/v1/dagSources/token%2Fone",
            {
                "extra_headers": {"Accept": "text/plain, application/json"},
                "response_size_cap": 2 * 1024 * 1024,
            },
        )
    ]


def test_discover_collapses_overlapping_detectors_for_one_secret_and_place() -> None:
    dag_path, run_path, _task_path = _paths("/api/v1")
    secret = "sk_live_RedpostureTaskLogD4w6kP8"
    client = _FakeClient(
        {
            f"{dag_path}?limit=100&offset=0": _response(
                {"dags": [{"dag_id": "example", "file_token": "source"}], "total_entries": 1}
            ),
            "/api/v1/dagSources/source": AirflowResponse(
                http_status=200,
                headers={"Content-Type": "text/plain"},
                body=f'api_key="{secret}"'.encode(),
            ),
            f"{run_path}?limit=100&offset=0&order_by=-execution_date": _response({"dag_runs": [], "total_entries": 0}),
        }
    )

    report = discover_task_logs(client, "v1", DiscoverConfig(include_dag_sources=True))

    same_value = [finding for finding in report["findings"] if finding["value"] == secret]
    assert len(same_value) == 1
    assert same_value[0]["type"] == "stripe_key"
    assert not any(finding["type"] == "high_entropy" for finding in report["findings"])


def test_show_variable_keys_never_returns_values() -> None:
    client = _FakeClient(
        {
            "/api/v2/variables?limit=2&offset=0": _response(
                {
                    "variables": [
                        {"key": "first", "value": "password=must-not-leak"},
                        {"key": "second", "value": "another-secret"},
                    ],
                    "total_entries": 3,
                }
            )
        }
    )

    result = actions.list_variable_keys(client, "v2", limit=2)

    assert result == {
        "keys": ["first", "second"],
        "count": 2,
        "total": 3,
        "truncated": True,
        "error": None,
    }
    assert "must-not-leak" not in json.dumps(result)


def test_show_connections_returns_complete_objects_and_honors_limit() -> None:
    client = _FakeClient(
        {
            "/api/v2/connections?limit=1&offset=0": _response(
                {
                    "connections": [
                        {
                            "connection_id": "warehouse",
                            "conn_type": "postgres",
                            "host": "db.internal",
                            "login": "reader",
                            "password": "connection-secret",
                            "extra": {"sslmode": "require"},
                        }
                    ],
                    "total_entries": 2,
                }
            )
        }
    )

    result = actions.list_connections(client, "v2", limit=1)

    assert result["count"] == 1
    assert result["total"] == 2
    assert result["truncated"] is True
    assert result["connections"][0]["password"] == "connection-secret"


def test_show_connections_flows_through_lifecycle_without_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = {
        "connection_id": "warehouse",
        "conn_type": "postgres",
        "host": "db.internal",
        "login": "reader",
        "password": "connection-secret",
    }
    client = _FakeClient(
        {
            "/api/v1/version": _response({"version": "2.10.5"}),
            "/api/v1/dags": _response({"dags": [], "total_entries": 0}),
            "/api/v1/connections?limit=1&offset=0": _response({"connections": [connection], "total_entries": 2}),
        }
    )
    monkeypatch.setattr(actions, "_client_for", lambda _ctx, **_kwargs: client)
    lines: list[str] = []
    args = parse_args(["airflow", "-t", "127.0.0.1:8080", "--show-connections", "1", "-f", "json"])

    AuditCommandRunner(args=args, spec=build_airflow_spec(args), emit_line=lines.append).run_plan(
        build_airflow_plan(args)
    )

    record = next(json.loads(line) for line in lines if line.startswith("{"))
    assert record["airflow_connections"] == [connection]
    assert record["airflow_connections_total"] == 2
    assert record["airflow_connections_truncated"] is True
    assert "discover_report" not in record


def test_show_keys_flows_through_airflow_lifecycle_without_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeClient(
        {
            "/api/v1/version": _response({"version": "2.10.5"}),
            "/api/v1/dags": _response({"dags": [], "total_entries": 0}),
            "/api/v1/pools": _response({"detail": "forbidden"}, 403),
            "/api/v1/eventLogs": _response({"detail": "forbidden"}, 403),
            "/api/v1/variables?limit=1&offset=0": _response(
                {
                    "variables": [{"key": "warehouse_password", "value": "must-not-enter-json"}],
                    "total_entries": 2,
                }
            ),
        }
    )
    monkeypatch.setattr(actions, "_client_for", lambda _ctx, **_kwargs: client)
    lines: list[str] = []
    args = parse_args(["airflow", "-t", "127.0.0.1:8080", "--show-keys", "1", "-f", "json"])

    AuditCommandRunner(args=args, spec=build_airflow_spec(args), emit_line=lines.append).run_plan(
        build_airflow_plan(args)
    )

    record = next(json.loads(line) for line in lines if line.startswith("{"))
    assert record["dags_allowed"] is True
    assert record["variable_keys"] == ["warehouse_password"]
    assert record["variable_keys_total"] == 2
    assert record["variable_keys_truncated"] is True
    assert "must-not-enter-json" not in json.dumps(record)
    assert "discover_report" not in record


def test_discovery_byte_budget_is_shared_across_configuration_and_logs() -> None:
    client = _FakeClient(
        {
            "/api/v1/variables?limit=100&offset=0": _response(
                {"variables": [{"key": "password", "value": "x" * 200}], "total_entries": 1}
            )
        }
    )

    report = discover_task_logs(
        client,
        "v1",
        DiscoverConfig(max_bytes=32, include_dag_sources=True, include_variables=True, include_connections=True),
    )

    assert report["status"] == "partial"
    assert report["bytes_scanned"] == 32
    assert report["variable_bytes_scanned"] == 32
    assert report["connections_scanned"] == report["dags_scanned"] == report["logs_scanned"] == 0
    assert "max_bytes" in report["partial_reasons"]
    assert [path for path, _kwargs in client.calls] == ["/api/v1/variables?limit=100&offset=0"]


def test_v2_dag_source_uses_dag_id_endpoint() -> None:
    dag_id = "team/source-dag"
    dag_path = "/api/v2/dags"
    runs_path = f"{dag_path}/{quote(dag_id, safe='')}/dagRuns"
    client = _FakeClient(
        {
            f"{dag_path}?limit=100&offset=0": _response(
                {"dags": [{"dag_id": dag_id, "file_token": "must-not-be-used"}], "total_entries": 1}
            ),
            f"/api/v2/dagSources/{quote(dag_id, safe='')}": _response({"content": 'api_key = "sourceKey123456"'}),
            f"{runs_path}?limit=100&offset=0&order_by=-start_date": _response({"dag_runs": [], "total_entries": 0}),
        }
    )

    report = discover_task_logs(client, "v2", DiscoverConfig(include_dag_sources=True))

    assert report["status"] == "complete"
    assert report["dag_sources_scanned"] == 1
    assert any(finding["source_kind"] == "dag_source" for finding in report["findings"])
    assert any(path == "/api/v2/dagSources/team%2Fsource-dag" for path, _kwargs in client.calls)
    assert all("must-not-be-used" not in path for path, _kwargs in client.calls)


def test_collection_falls_back_from_unsupported_order_and_handles_server_page_cap() -> None:
    path = "/api/v1/dags/example/dagRuns"
    client = _FakeClient(
        {
            f"{path}?limit=3&offset=0&order_by=-execution_date": _response({"detail": "bad order"}, 400),
            f"{path}?limit=3&offset=0": _response({"dag_runs": [{"dag_run_id": "one"}], "total_entries": 3}),
            f"{path}?limit=2&offset=1": _response({"dag_runs": [{"dag_run_id": "two"}], "total_entries": 3}),
            f"{path}?limit=1&offset=2": _response({"dag_runs": [{"dag_run_id": "three"}], "total_entries": 3}),
        }
    )

    result = _collection(client, path, "dag_runs", 3, time.monotonic() + 1, order_by="-execution_date")

    assert result.complete is True
    assert [item["dag_run_id"] for item in result.items] == ["one", "two", "three"]
    assert len(client.calls) == 4


@pytest.mark.parametrize(
    ("response", "expected_error"),
    [
        (_response({"detail": "denied"}, 401), "http_401"),
        (_response({"dags": "wrong"}), "invalid_collection"),
        (_response({"dags": []}, truncated=True), "response_truncated"),
        (AirflowResponse(http_status=0, headers={}, body=b"", transport_error="timeout"), "transport_error"),
    ],
)
def test_collection_errors_are_partial_not_empty_success(response: AirflowResponse, expected_error: str) -> None:
    client = _FakeClient({"/api/v1/dags?limit=2&offset=0": response})
    collection = _collection(client, "/api/v1/dags", "dags", 2, time.monotonic() + 1)
    assert collection.complete is False
    assert collection.error == expected_error


def test_collection_detects_repeated_page_when_offset_is_ignored() -> None:
    first = _response({"dags": [{"dag_id": "same"}], "total_entries": 3})
    client = _FakeClient({"/api/v1/dags?limit=3&offset=0": first, "/api/v1/dags?limit=2&offset=1": first})
    collection = _collection(client, "/api/v1/dags", "dags", 3, time.monotonic() + 1)
    assert collection.error == "pagination_stalled"
    assert [item["dag_id"] for item in collection.items] == ["same"]


def test_log_reader_detects_repeated_continuation_token() -> None:
    path = "/api/v1/dags/d/dagRuns/r/taskInstances/t/logs/1"
    client = _FakeClient(
        {
            f"{path}?full_content=false": _response({"content": "first", "continuation_token": "repeat"}),
            f"{path}?full_content=false&token=repeat": _response({"content": "second", "continuation_token": "repeat"}),
        }
    )
    text, used, error = _read_log(client, path, max_log_bytes=100, max_total_bytes=100, deadline=time.monotonic() + 1)
    assert (text, used, error) == ("firstsecond", 11, "continuation_loop")


def test_log_reader_unwraps_airflow2_host_payload_and_stops_at_end_token() -> None:
    path = "/api/v1/dags/d/dagRuns/r/taskInstances/t/logs/1"
    wrapped = '[("worker-1", "*** Found local files:\\n***   * /opt/airflow/logs/task.log\\npassword=taskSecret123") ]'
    end_token = "eyJlbmRfb2ZfbG9nIjp0cnVlLCJsb2dfcG9zIjo3NX0.signature"
    client = _FakeClient(
        {f"{path}?full_content=false": _response({"content": wrapped, "continuation_token": end_token})}
    )

    text, used, error = _read_log(client, path, max_log_bytes=100, max_total_bytes=100, deadline=time.monotonic() + 1)

    assert (text, used, error) == ("password=taskSecret123", 22, None)
    assert len(client.calls) == 1


def test_log_reader_accepts_plain_text_and_reports_truncation() -> None:
    path = "/api/v1/dags/d/dagRuns/r/taskInstances/t/logs/1"
    client = _FakeClient(
        {
            f"{path}?full_content=false": AirflowResponse(
                http_status=200,
                headers={"Content-Type": "text/plain"},
                body=b"password=from_plain_log",
                truncated=True,
            )
        }
    )
    text, used, error = _read_log(client, path, max_log_bytes=100, max_total_bytes=100, deadline=time.monotonic() + 1)
    assert (text, used, error) == ("password=from_plain_log", 23, "response_truncated")


def test_log_reader_respects_total_byte_budget() -> None:
    path = "/api/v1/dags/d/dagRuns/r/taskInstances/t/logs/1"
    client = _FakeClient({f"{path}?full_content=false": _response({"content": "password=longsecret"})})
    text, used, error = _read_log(client, path, max_log_bytes=100, max_total_bytes=10, deadline=time.monotonic() + 1)
    assert (text, used, error) == ("password=l", 10, "max_bytes")


def test_log_reader_skips_requests_after_deadline() -> None:
    client = _FakeClient({})
    assert _read_log(client, "/logs/1", max_log_bytes=100, max_total_bytes=100, deadline=time.monotonic() - 1) == (
        "",
        0,
        "discover_time",
    )
    assert client.calls == []


def test_v2_discover_encodes_ids_and_scans_mapped_task_attempts() -> None:
    dag_id, run_id, task_id = "team/dag", "manual/run?", "task/inner"
    dag_path, run_path, task_path = _paths("/api/v2", dag_id, run_id)
    log_base = f"{task_path}/{quote(task_id, safe='')}/logs"
    client = _FakeClient(
        {
            f"{dag_path}?limit=2&offset=0": _response({"dags": [{"dag_id": dag_id}], "total_entries": 1}),
            f"{run_path}?limit=2&offset=0&order_by=-start_date": _response(
                {"dag_runs": [{"dag_run_id": run_id}], "total_entries": 1}
            ),
            f"{task_path}?limit=3&offset=0": _response(
                {"task_instances": [{"task_id": task_id, "try_number": 2, "map_index": 3}], "total_entries": 1}
            ),
            f"{log_base}/1?map_index=3&full_content=false": _response({"content": [{"event": "nothing"}]}),
            f"{log_base}/2?map_index=3&full_content=false": _response(
                {"content": [{"event": "clientSecret=verysecretvalue"}]}
            ),
        }
    )

    report = discover_task_logs(client, "v2", DiscoverConfig(max_dags=2, max_runs=2, max_tasks=3, max_logs=3))

    assert report["status"] == "complete"
    assert report["logs_scanned"] == 2
    assert len(report["findings"]) == 1
    finding = report["findings"][0]
    assert (
        finding["dag_id"],
        finding["dag_run_id"],
        finding["task_id"],
        finding["try_number"],
        finding["map_index"],
    ) == (
        dag_id,
        run_id,
        task_id,
        2,
        3,
    )
    assert finding["value"] == "verysecretvalue"
    assert any("team%2Fdag" in path and "manual%2Frun%3F" in path for path, _kwargs in client.calls)


def test_discover_reports_denied_task_collection_without_claiming_complete() -> None:
    dag_path, run_path, task_path = _paths("/api/v1")
    client = _FakeClient(
        {
            f"{dag_path}?limit=2&offset=0": _response({"dags": [{"dag_id": "example"}], "total_entries": 1}),
            f"{run_path}?limit=2&offset=0&order_by=-execution_date": _response(
                {"dag_runs": [{"dag_run_id": "manual__2026-09-13"}], "total_entries": 1}
            ),
            f"{task_path}?limit=3&offset=0": _response({"detail": "forbidden"}, 403),
        }
    )

    report = discover_task_logs(client, "v1", DiscoverConfig(max_dags=2, max_runs=2, max_tasks=3))

    assert report["status"] == "partial"
    assert report["partial_reasons"] == ["task_instances:http_403"]
    assert report["logs_scanned"] == 0
    assert report["errors"] == [{"path": task_path, "reason": "task_instances:http_403"}]


def test_discover_enforces_per_log_byte_limit() -> None:
    dag_path, run_path, task_path = _paths("/api/v1")
    log_path = f"{task_path}/extract/logs/1"
    client = _FakeClient(
        {
            f"{dag_path}?limit=1&offset=0": _response({"dags": [{"dag_id": "example"}], "total_entries": 1}),
            f"{run_path}?limit=1&offset=0&order_by=-execution_date": _response(
                {"dag_runs": [{"dag_run_id": "manual__2026-09-13"}], "total_entries": 1}
            ),
            f"{task_path}?limit=1&offset=0": _response(
                {"task_instances": [{"task_id": "extract", "try_number": 1}], "total_entries": 1}
            ),
            f"{log_path}?full_content=false": _response({"content": "password=firstsecret\npassword=secondsecret"}),
        }
    )

    report = discover_task_logs(
        client,
        "v1",
        DiscoverConfig(max_dags=1, max_runs=1, max_tasks=1, max_logs=1, max_log_bytes=20, max_bytes=100),
    )

    assert report["status"] == "partial"
    assert "logs:max_log_bytes" in report["partial_reasons"]
    assert report["bytes_scanned"] == 20
    assert [finding["value"] for finding in report["findings"]] == ["firstsecret"]


def test_discover_uses_selected_v2_credential_token(monkeypatch: pytest.MonkeyPatch) -> None:
    state = actions.AirflowLifecycleState(SimpleNamespace(timeout=1.0, retries=0), "host", 8080)
    state.resolved_scheme = "http"
    state.bearer_token = "other-credential-token"
    state.bearer_tokens[("auditor", "secret")] = "selected-token"
    context = SimpleNamespace(
        host="host",
        port=8080,
        args=SimpleNamespace(discover=True),
        credential=SimpleNamespace(username="auditor", password="secret"),
        lifecycle_state=state,
    )
    captured: dict[str, object] = {}

    def fake_discover(client: AirflowClient, generation: str, config: DiscoverConfig) -> dict[str, object]:
        captured.update(token=client.bearer_token, generation=generation, max_logs=config.max_logs)
        return {"status": "complete", "findings": [], "finding_count": 0}

    monkeypatch.setattr(actions, "discover_task_logs", fake_discover)
    try:
        result = actions.discover_record(
            context,
            {"detection_status": "confirmed", "api_generation": "v2", "provided_credentials_ok": True},
        )
    finally:
        state.close()

    assert captured == {"token": "selected-token", "generation": "v2", "max_logs": None}
    assert result["discover_report"]["status"] == "complete"


def test_live_discovery_emits_header_before_progressive_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    emitted: list[str] = []
    context = SimpleNamespace(
        host="127.0.0.1",
        port=8080,
        args=SimpleNamespace(discover=True, show_keys=False, discover_max_bytes=1024, discover_time=None),
        credential=SimpleNamespace(username="airflow", password="airflow"),
        lifecycle_state=None,
        live_emit=lambda lines: emitted.extend(lines),
    )
    monkeypatch.setattr(actions, "_client_for", lambda _ctx, **_kwargs: _FakeClient({}))

    def fake_discover(_client, _generation, _config, on_finding=None):
        assert on_finding is not None
        on_finding(
            {
                "type": "password",
                "confidence": "high",
                "value": "sourceSecret123",
                "place": "dag_source:example$",
            }
        )
        return {
            "status": "complete",
            "finding_count": 1,
            "findings": [],
            "partial_reasons": [],
            "variable_keys": [],
        }

    monkeypatch.setattr(actions, "discover_task_logs", fake_discover)

    result = actions.discover_record(
        context,
        {"detection_status": "confirmed", "api_generation": "v1", "provided_credentials_ok": True},
    )

    assert emitted[0] == "AIRFLOW\t127.0.0.1\t8080\t [*] Discover Secrets"
    assert emitted[1].endswith('Pass Value="sourceSecret123" Place="dag_source:example$"')
    assert result["_discover_findings_streamed"] is True


def test_discover_flows_through_airflow_audit_lifecycle_and_json(monkeypatch: pytest.MonkeyPatch) -> None:
    dag_path, run_path, task_path = _paths("/api/v1")
    client = _FakeClient(
        {
            "/api/v1/version": _response({"version": "2.10.5"}),
            "/api/v1/dags": _response({"dags": [{"dag_id": "example"}], "total_entries": 1}),
            "/api/v1/pools": _response({"detail": "forbidden"}, 403),
            "/api/v1/eventLogs": _response({"detail": "forbidden"}, 403),
            "/api/v1/variables?limit=100&offset=0": _response({"variables": [], "total_entries": 0}),
            "/api/v1/connections?limit=100&offset=0": _response({"connections": [], "total_entries": 0}),
            f"{dag_path}?limit=100&offset=0": _response(
                {"dags": [{"dag_id": "example", "file_token": "source-token"}], "total_entries": 1}
            ),
            "/api/v1/dagSources/source-token": _response({"content": "print('safe')"}),
            f"{run_path}?limit=100&offset=0&order_by=-execution_date": _response(
                {"dag_runs": [{"dag_run_id": "manual__2026-09-13"}], "total_entries": 1}
            ),
            f"{task_path}?limit=100&offset=0": _response(
                {"task_instances": [{"task_id": "extract", "try_number": 1}], "total_entries": 1}
            ),
            f"{task_path}/extract/logs/1?full_content=false": _response({"content": "password=secret123"}),
        }
    )
    monkeypatch.setattr(actions, "_client_for", lambda _ctx, **_kwargs: client)
    lines: list[str] = []

    args = parse_args(
        [
            "airflow",
            "-t",
            "127.0.0.1:8080",
            "--discover",
            "-f",
            "json",
        ]
    )
    runner = AuditCommandRunner(args=args, spec=build_airflow_spec(args), emit_line=lines.append)
    runner.run_plan(build_airflow_plan(args))

    record = next(json.loads(line) for line in lines if line.startswith("{") and '"host"' in line)
    assert "discover_report" in record, record
    assert record["discover_report"]["status"] == "complete"
    assert record["discover_report"]["findings"][0]["value"] == "secret123"
    assert any("/logs/1" in path for path, _kwargs in client.calls)


def test_discover_cli_spec_policy_and_txt_render() -> None:
    args = parse_args(["airflow", "-t", "127.0.0.1", "--discover", "--discover-max-bytes", "7000"])
    assert args.discover is True and args.discover_max_bytes == 7000
    assert build_airflow_spec(args).data is not None
    record = {
        "host": "127.0.0.1",
        "port": 8080,
        "discover_requested": True,
        "discover_report": {
            "status": "partial",
            "logs_scanned": 1,
            "bytes_scanned": 22,
            "findings": [
                {
                    "type": "password",
                    "value": "secret123",
                    "dag_id": "example",
                    "dag_run_id": "manual",
                    "task_id": "extract",
                    "try_number": 1,
                    "map_index": -1,
                    "object_path": "$",
                }
            ],
            "partial_reasons": ["max_logs"],
        },
    }
    lines = render._format_discover_records(record, "txt")
    assert "Discover Secrets (status:partial) (findings:1)" in lines[0]
    assert "(logs:" not in lines[0]
    assert "(bytes:" not in lines[0]
    assert '[!] Pass Value="secret123" Place="example/manual/extract/try:1/map:-1$"' in lines[1]
    assert "Discover partial: max_logs" in lines[2]
    assert render._format_discover_records(record, "json") == []


@pytest.mark.parametrize(
    "flag",
    ["--discover-max-bytes"],
)
def test_discover_rejects_nonpositive_limits(flag: str) -> None:
    args = parse_args(["airflow", "-t", "127.0.0.1", "--discover", flag, "0"])
    errors: list[str] = []
    console = SimpleNamespace(error=errors.append)
    assert policy.validate_args(args, console) == 2
    assert flag in errors[0]


def test_discover_rejects_nonfinite_time() -> None:
    args = parse_args(["airflow", "-t", "127.0.0.1", "--discover", "--discover-time", "nan"])
    errors: list[str] = []
    assert policy.validate_args(args, SimpleNamespace(error=errors.append)) == 2
    assert "--discover-time" in errors[0]
