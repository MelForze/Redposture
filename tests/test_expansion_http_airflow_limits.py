"""Airflow DAG-log traversal reports precisely where bounded reads stop."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from redposture_core.clients.airflow_api import AirflowResponse
from redposture_core.modules.airflow.discover import DiscoverConfig, discover_task_logs


class Client:
    def __init__(self, source_failure: str | None = None) -> None:
        self.paths: list[str] = []
        self.source_failure = source_failure

    def get(self, path: str, **kwargs: Any) -> AirflowResponse:
        self.paths.append(path)
        clean = urlsplit(path).path
        if clean.endswith("/variables"):
            payload = {"variables": [{"key": "db_password", "value": "VariableSecret2026"}], "total_entries": 1}
        elif clean.endswith("/connections"):
            payload = {"connections": [{"connection_id": "db", "password": "ConnectionSecret2026"}], "total_entries": 1}
        elif clean.endswith("/dags"):
            payload = {"dags": [{"dag_id": "dag", "file_token": "source"}], "total_entries": 1}
        elif "/dagSources/" in clean:
            if self.source_failure == "transport":
                return AirflowResponse(0, {}, b"", transport_error="reset")
            if self.source_failure == "denied":
                return AirflowResponse(403, {}, b"{}")
            return AirflowResponse(
                200, {}, b'password="DagSourceSecret2026"', truncated=self.source_failure == "truncated"
            )
        elif clean.endswith("/dagRuns"):
            payload = {"dag_runs": [{"dag_run_id": "run"}], "total_entries": 1}
        elif clean.endswith("/taskInstances"):
            payload = {"task_instances": [{"task_id": "task", "try_number": 2, "map_index": 0}], "total_entries": 1}
        else:
            assert "/logs/" in clean
            payload = {"content": "password=TaskLogSecret2026"}
        return AirflowResponse(200, {"Content-Type": "application/json"}, json.dumps(payload).encode())


@pytest.mark.parametrize("reason", ["max_dags", "max_runs", "max_tasks", "max_logs", "max_findings", "max_bytes"])
def test_airflow_walk_stops_with_explicit_limit_reason(reason: str) -> None:
    client = Client()
    limits = {reason: 0 if reason in {"max_dags", "max_runs", "max_tasks", "max_logs"} else 1}
    result = discover_task_logs(client, "v2", DiscoverConfig(**limits))
    assert result["status"] == "partial" and reason in result["partial_reasons"]
    assert result["finding_count"] == len(result["findings"])
    if reason in {"max_dags", "max_runs", "max_tasks", "max_logs"}:
        assert result["logs_scanned"] == 0
        assert not any("/logs/" in path for path in client.paths)
    elif reason == "max_findings":
        assert result["finding_count"] == result["logs_scanned"] == 1
    else:
        assert result["bytes_scanned"] == 1


@pytest.mark.parametrize("generation", ["v1", "v2"])
@pytest.mark.parametrize("failure", ["denied", "transport", "truncated"])
def test_airflow_source_failure_retains_log_findings_and_exact_error(generation: str, failure: str) -> None:
    client = Client(failure)
    result = discover_task_logs(client, generation, DiscoverConfig(include_dag_sources=True))
    prefix = "/api/" + generation
    source_path = prefix + "/dagSources/" + ("source" if generation == "v1" else "dag")
    expected = {
        "denied": "dag_sources:http_403",
        "transport": "dag_sources:transport_error",
        "truncated": "dag_sources:response_truncated",
    }[failure]
    assert result["status"] == "partial" and expected in result["partial_reasons"]
    assert {"path": source_path, "reason": expected} in result["errors"]
    assert result["logs_scanned"] == 2 and any(f["value"] == "TaskLogSecret2026" for f in result["findings"])
    assert all(parse_qs(urlsplit(path).query)["map_index"] == ["0"] for path in client.paths if "/logs/" in path)


@pytest.mark.parametrize("surface", ["variables", "connections"])
def test_airflow_global_secret_finding_limit_prevents_later_task_walk(surface: str) -> None:
    client = Client()
    emitted = []
    config = DiscoverConfig(max_findings=1, **{"include_" + surface: True})
    result = discover_task_logs(client, "v2", config, emitted.append)
    assert result["status"] == "partial" and result["partial_reasons"] == ["max_findings"]
    assert result["dags_scanned"] == result["logs_scanned"] == 0
    assert result[surface + "_scanned"] == 1 and len(emitted) == result["finding_count"] == 1
    assert emitted == result["findings"] and emitted[0]["source_kind"] == surface.rstrip("s")
    assert client.paths == [f"/api/v2/{surface}?limit=100&offset=0"]
