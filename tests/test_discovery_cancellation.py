"""Cancellation stops discovery before it starts another network operation."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from redposture_core.clients.airflow_api import AirflowResponse
from redposture_core.modules.airflow.discover import DiscoverConfig as AirflowConfig
from redposture_core.modules.airflow.discover import _collection, _read_log, discover_task_logs
from redposture_core.modules.clickhouse.discover.engine import DiscoverConfig as ClickHouseConfig
from redposture_core.modules.clickhouse.discover.engine import run_discovery
from redposture_core.modules.elastic.discover import DiscoverEngine
from redposture_core.modules.minio.discover import Budget, DiscoverResult, _read_and_scan
from redposture_core.modules.minio.enumerate import ObjectInfo
from redposture_core.scheduler import NestedSchedulerCancelled


class _NoNetwork:
    def get(self, *_args: object, **_kwargs: object) -> None:
        raise AssertionError("cancelled discovery sent a request")

    def get_object_range(self, *_args: object, **_kwargs: object) -> None:
        raise AssertionError("cancelled discovery sent a ranged read")


def test_airflow_discovery_stops_before_next_page() -> None:
    with pytest.raises(NestedSchedulerCancelled):
        discover_task_logs(_NoNetwork(), "v1", AirflowConfig(), cancelled=lambda: True)


@pytest.mark.parametrize(
    ("body", "read_log"),
    [
        (b'{"dags":[{"dag_id":"one"}],"total_entries":2}', False),
        (b'{"content":"first page","continuation_token":"next"}', True),
    ],
)
def test_airflow_cancellation_between_pages_prevents_second_request(body: bytes, read_log: bool) -> None:
    class OnePageClient:
        calls = 0

        def get(self, _path: str, **_kwargs: object) -> AirflowResponse:
            self.calls += 1
            if self.calls > 1:
                raise AssertionError("cancellation failed to prevent a second request")
            return AirflowResponse(200, {"Content-Type": "application/json"}, body)

    client = OnePageClient()

    def cancelled() -> bool:
        return client.calls >= 1

    with pytest.raises(NestedSchedulerCancelled):
        if read_log:
            _read_log(
                client,
                "/api/v1/dags/one/dagRuns/run/taskInstances/task/logs/1",
                max_log_bytes=4096,
                max_total_bytes=4096,
                deadline=None,
                cancelled=cancelled,
            )
        else:
            _collection(client, "/api/v1/dags", "dags", None, None, cancelled=cancelled)
    assert client.calls == 1


def test_minio_discovery_stops_before_next_chunk() -> None:
    with pytest.raises(NestedSchedulerCancelled):
        _read_and_scan(
            _NoNetwork(),
            ObjectInfo(bucket="bucket", key="config.env", size=20),
            Budget(),
            DiscoverResult(),
            set(),
            None,
            cancelled=lambda: True,
        )


def test_elastic_discovery_stops_before_next_request() -> None:
    engine = DiscoverEngine(
        lambda _request: (_ for _ in ()).throw(AssertionError("cancelled discovery sent a request")),
        nested_scheduler=SimpleNamespace(cancelled=True),
    )
    with pytest.raises(NestedSchedulerCancelled):
        engine._request("GET", "/_mapping")


def test_clickhouse_discovery_stops_before_inventory_query() -> None:
    def no_query(_query: str) -> None:
        raise AssertionError("cancelled discovery sent a query")

    with pytest.raises(NestedSchedulerCancelled):
        run_discovery(
            None,
            host="127.0.0.1",
            port=9000,
            config=ClickHouseConfig(),
            query_rows=no_query,
            nested_scheduler=SimpleNamespace(cancelled=True),
        )
