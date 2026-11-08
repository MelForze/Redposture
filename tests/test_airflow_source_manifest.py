"""Airflow source access is independent of matches and catalog access."""

from __future__ import annotations

import pytest

from redposture_core.clients.airflow_api import AirflowResponse
from redposture_core.modules.airflow.discover import DiscoverConfig, discover_task_logs
from redposture_core.scheduler import NestedSchedulerCancelled
from tests.test_airflow_discover import _FakeClient, _response


def client(*, denied=False):
    return _FakeClient(
        {
            "/api/v1/variables?limit=100&offset=0": _response(
                {"variables": [{"key": "password", "value": "inactive-variable!42"}], "total_entries": 1}
            ),
            "/api/v1/connections?limit=100&offset=0": _response({}, 403)
            if denied
            else _response({"connections": [], "total_entries": 0}),
            "/api/v1/dags?limit=100&offset=0": _response({"dags": [], "total_entries": 0}),
        }
    )


@pytest.mark.parametrize("denied", [False, True])
def test_empty_collections_and_denied_contents_have_real_read_evidence(denied):
    report = discover_task_logs(
        client(denied=denied), "v1", DiscoverConfig(include_variables=True, include_connections=True)
    )
    rows = {r["id"]: r for r in report["sources"]}
    assert rows["airflow.variable_collection"]["read"] == 1 and rows["airflow.variable_collection"]["complete"]
    c = rows["airflow.connection_collection"]
    assert c["read"] == int(not denied) and c["denied"] == int(denied) and c["complete"] == (not denied)
    assert rows["airflow.task_logs"]["requested"] == 0
    assert [f["value"] for f in report["findings"]] == ["inactive-variable!42"]


def test_cancel_after_published_value_stops_next_source_and_repeat_is_fresh():
    c, emitted = client(), []
    with pytest.raises(NestedSchedulerCancelled):
        discover_task_logs(
            c,
            "v1",
            DiscoverConfig(include_variables=True, include_connections=True),
            on_finding=lambda f: emitted.append(f),
            cancelled=lambda: bool(emitted),
        )
    assert all("/connections?" not in path for path, _ in c.calls)
    for _ in range(2):
        report = discover_task_logs(client(), "v1", DiscoverConfig(include_variables=True, include_connections=True))
        assert report["status"] == "complete"
        assert len(report["findings"]) == 1


@pytest.mark.parametrize("status", [401, 403, 500])
def test_streamed_dag_error_body_never_becomes_a_finding(status):
    class Client(_FakeClient):
        def get_stream(self, path, *, on_chunk, on_response, **kwargs):
            on_response(status, {"Content-Type": "text/plain"})
            on_chunk(b'password="not-a-source!42"\n')
            return AirflowResponse(status, {}, b"")

    c = Client(
        {
            "/api/v1/dags?limit=100&offset=0": _response(
                {"dags": [{"dag_id": "qa", "file_token": "source"}], "total_entries": 1}
            ),
            "/api/v1/dags/qa/dagRuns?limit=100&offset=0&order_by=-execution_date": _response(
                {"dag_runs": [], "total_entries": 0}
            ),
        }
    )
    emitted = []
    report = discover_task_logs(
        c, "v1", DiscoverConfig(include_dag_sources=True), on_finding=lambda f: emitted.append(f)
    )
    assert not report["findings"] and not emitted
    row = next(r for r in report["sources"] if r["id"] == "airflow.dag_sources")
    assert row["read"] == 0 and row["denied"] == int(status in {401, 403}) and not row["complete"]
