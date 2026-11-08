"""Elastic configuration and document sources retain independent ACL evidence."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from redposture_core.modules.elastic.discover import DiscoverEngine, DiscoverResponse
from redposture_core.scheduler import NestedSchedulerCancelled


def response(value, status=200):
    return DiscoverResponse(status, json.dumps(value).encode())


@pytest.mark.parametrize("status", [200, 403, 404])
def test_empty_configuration_read_denied_and_unavailable_sources(status):
    engine = DiscoverEngine(lambda req: response({}, status))
    engine._scan_remote_surface("cluster_settings", "/_cluster/settings")
    report = engine._finalize().to_dict()
    row = next(r for r in report["discover_coverage"]["sources"] if r["id"] == "elastic.cluster_settings")
    assert row["requested"] == 1 and row["read"] == int(status == 200)
    assert row["denied"] == int(status == 403) and row["complete"] == (status == 200)
    assert row["unsupported"] == (status == 404)
    assert not report["discover_findings"]


def test_transport_cancellation_is_not_wrapped_as_error_and_next_request():
    calls = []

    def request(req):
        calls.append(req.path)
        raise NestedSchedulerCancelled("stop transport")

    engine = DiscoverEngine(request)
    with pytest.raises(NestedSchedulerCancelled):
        engine.run()
    assert len(calls) == 1


def test_fresh_repeat_does_not_reuse_completed_source_counters():
    for _ in range(2):
        engine = DiscoverEngine(lambda req: response({"password": "inactive-config!42"}))
        engine._scan_remote_surface("cluster_settings", "/_cluster/settings")
        report = engine._finalize().to_dict()
        assert [f["value"] for f in report["discover_findings"]] == ["inactive-config!42"]
        row = next(r for r in report["discover_coverage"]["sources"] if r["id"] == "elastic.cluster_settings")
        assert row["requested"] == row["read"] == 1 and row["complete"]


def test_cancelled_walk_still_releases_existing_pit_and_scroll():
    calls = []
    engine = DiscoverEngine(
        lambda req: calls.append((req.method, req.path)) or response({}),
        nested_scheduler=SimpleNamespace(cancelled=True),
    )
    engine._close_pit("existing-pit")
    engine._clear_scroll("existing-scroll")
    assert calls == [("DELETE", "/_pit"), ("DELETE", "/_search/scroll")]
