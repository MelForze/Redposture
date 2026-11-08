"""Counters distinguish fresh catalog/chunk reads from checkpoint reuse."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from redposture_core.modules.clickhouse.discover import DiscoverConfig, run_discovery
from redposture_core.scheduler import NestedSchedulerCancelled
from tests.test_clickhouse_discover import _inventory_query, _session


@pytest.mark.parametrize("denied", [False, True])
def test_catalogs_and_data_chunks_have_separate_actual_read_evidence(denied):
    session = _session([('password="inactive-clickhouse!42"', {})])
    if denied:

        def fail(query):
            raise RuntimeError("not enough privileges")
            yield

        session.client.execute_iter = fail
    result = run_discovery(session, host="qa", port=9000, config=DiscoverConfig(), query_rows=_inventory_query)
    rows = {r["id"]: r for r in result["sources"]}
    assert rows["clickhouse.table_catalog"]["read"] == 1
    assert rows["clickhouse.column_catalog"]["read"] == 1
    assert rows["clickhouse.partition_catalog"]["read"] >= 1
    chunks = rows["clickhouse.table_chunks"]
    assert chunks["requested"] == 1 and chunks["read"] == int(not denied)
    assert chunks["denied"] == int(denied) and chunks["complete"] == (not denied)


def test_resumed_chunks_are_not_reported_as_fresh_server_reads(tmp_path):
    checkpoint = tmp_path / "resume"
    first = run_discovery(
        _session([('password="inactive-checkpoint!42"', {})]),
        host="qa",
        port=9000,
        config=DiscoverConfig(checkpoint=checkpoint),
        query_rows=_inventory_query,
    )
    session = _session([])
    second = run_discovery(
        session,
        host="qa",
        port=9000,
        config=DiscoverConfig(checkpoint=checkpoint, resume=True),
        query_rows=_inventory_query,
    )
    assert second["status"] == first["status"] == "complete"
    row = next(r for r in second["sources"] if r["id"] == "clickhouse.table_chunks")
    assert row["requested"] == row["read"] == 0 and not row["complete"]
    assert session.client.queries == []


def test_cancel_during_catalog_stops_before_the_next_query():
    nested = SimpleNamespace(cancelled=False)
    calls = []

    def query(sql):
        calls.append(sql)
        nested.cancelled = True
        return _inventory_query(sql)

    with pytest.raises(NestedSchedulerCancelled):
        run_discovery(
            _session([]), host="qa", port=9000, config=DiscoverConfig(), query_rows=query, nested_scheduler=nested
        )
    assert len(calls) == 1
