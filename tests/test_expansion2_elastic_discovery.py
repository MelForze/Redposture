"""Discovery contracts across inventory, configuration and partial document reads."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest

from redposture_core.modules.elastic import actions
from redposture_core.modules.elastic.discover import (
    DiscoverEngine,
    DiscoverOptions,
    DiscoverRequest,
    DiscoverResponse,
)


def reply(value: Any, status: int = 200, *, truncated: bool = False) -> DiscoverResponse:
    return DiscoverResponse(status, json.dumps(value).encode(), truncated=truncated)


def page(hits: list[dict[str, Any]], **extras: Any) -> DiscoverResponse:
    return reply({"hits": {"total": {"value": len(hits), "relation": "eq"}, "hits": hits}, **extras})


class DiscoveryAPI:
    """A read-only API transcript; unconfigured searches finish with an empty page."""

    def __init__(self) -> None:
        self.inventory: Any = {"indices": [{"name": "logs", "attributes": ["open"]}]}
        self.mappings: Any = {"logs": {"mappings": {"properties": {}}}}
        self.settings: Any = {"logs": {"settings": {}}}
        self.remote: dict[str, Any] = {}
        self.requests: list[DiscoverRequest] = []
        self.search: Callable[[DiscoverRequest], DiscoverResponse] = lambda request: page([])

    def __call__(self, request: DiscoverRequest) -> DiscoverResponse:
        self.requests.append(request)
        if request.method == "DELETE":
            return reply({"succeeded": True, "num_freed": 1})
        if request.path.startswith("/_resolve/"):
            return reply(self.inventory)
        if "/_mapping" in request.path:
            return reply(self.mappings)
        if "/_settings" in request.path and not request.path.startswith(("/_cluster", "/_nodes")):
            return reply(self.settings)
        if "/_pit?" in request.path:
            return reply({"id": "pit-1"})
        if request.path == "/_search" or "/_search?" in request.path or request.path == "/_search/scroll":
            return self.search(request)
        value = self.remote.get(request.path.split("?", 1)[0], {})
        return value if isinstance(value, DiscoverResponse) else reply(value)


def test_data_stream_inventory_scans_each_backing_index_once_and_excludes_closed_indices() -> None:
    api = DiscoveryAPI()
    api.inventory = {
        "indices": [
            {"name": ".ds-logs-000001", "attributes": ["hidden", "closed"], "aliases": ["archive"]},
            {"name": ".ds-logs-000002", "attributes": ["hidden", "open"]},
        ],
        "data_streams": [
            {"name": "logs", "backing_indices": [".ds-logs-000001", ".ds-logs-000002"]},
            {"name": "audit", "backing_indices": [{"name": ".ds-audit-000001"}]},
            {"name": "metrics"},
        ],
    }
    names = [".ds-audit-000001", ".ds-logs-000002", "metrics"]
    api.mappings = {name: {"mappings": {"properties": {}}} for name in names}
    api.settings = {name: {"settings": {}} for name in names}
    report = DiscoverEngine(api).run()
    assert report.coverage.indices_enumerated == 4
    assert report.coverage.indices_closed == 1
    assert report.coverage.indices_scanned == 3
    assert [item["index"] for item in report.legacy_results] == names
    opened = [request.path.split("/")[1] for request in api.requests if "/_pit?" in request.path]
    assert opened == names
    assert report.coverage.surfaces["mappings"].objects_scanned == 3


def test_nested_field_and_multifield_metadata_are_scanned_as_configuration_without_running_scripts() -> None:
    api = DiscoveryAPI()
    api.mappings = {
        "logs": {
            "mappings": {
                "properties": {
                    "event": {"properties": {"message": {"type": "text", "meta": {"password": "nested-value"}}}},
                    "label": {
                        "type": "text",
                        "fields": {"raw": {"type": "keyword", "meta": {"password": "multifield-value"}}},
                    },
                },
                "runtime": {
                    "computed": {
                        "type": "keyword",
                        "script": {"source": "emit(params.password)", "params": {"password": "runtime-value"}},
                    }
                },
            }
        }
    }
    report = DiscoverEngine(api).run()
    found = {finding.value: finding for finding in report.findings}
    assert {"nested-value", "multifield-value", "runtime-value"} <= found.keys()
    assert all(
        location.source_kind == "mapping_configuration" for item in found.values() for location in item.locations
    )
    assert all("script_fields" not in (request.body or b"").decode() for request in api.requests)
    paths = [location.path for finding in report.findings for location in finding.locations]
    assert any("/properties/event/properties/message/meta/password" in path for path in paths)
    assert any("/fields/raw/meta/password" in path for path in paths)


@pytest.mark.parametrize("surface", ["index_templates", "component_templates"])
def test_unnamed_template_entry_keeps_stable_configuration_origin(surface: str) -> None:
    api = DiscoveryAPI()
    api.inventory = {"indices": []}
    api.remote[f"/_{surface[:-1]}"] = {surface: [{"template": {"settings": {"password": "template-value"}}}]}
    report = DiscoverEngine(api).run()
    finding = next(item for item in report.findings if item.value == "template-value")
    assert finding.locations[0].source_kind == surface
    assert finding.locations[0].object == f"{surface}/0"
    assert report.coverage.surfaces[surface].objects_scanned == 1


@pytest.mark.parametrize("fault", ["timeout", "shards", "both", "truncated"])
def test_search_partial_responses_keep_confirmed_secrets_and_explain_incompleteness(fault: str) -> None:
    api = DiscoveryAPI()
    calls = 0

    def search(request: DiscoverRequest) -> DiscoverResponse:
        nonlocal calls
        calls += 1
        if calls > 1:
            return page([])
        extras: dict[str, Any] = {}
        if fault in {"timeout", "both"}:
            extras["timed_out"] = True
        if fault in {"shards", "both"}:
            extras["_shards"] = {"total": 2, "successful": 1, "failed": 1}
        response = page(
            [{"_index": "logs", "_id": "1", "_source": {"password": "partial-evidence"}, "sort": [1]}], **extras
        )
        return DiscoverResponse(response.status, response.payload, truncated=fault == "truncated")

    api.search = search
    report = DiscoverEngine(api).run()
    assert [finding.value for finding in report.findings] == ["partial-evidence"]
    coverage = report.coverage.to_dict()
    assert coverage["complete"] is False and coverage["documents_scanned"] == 1
    if fault in {"timeout", "both"}:
        assert report.coverage.timed_out and "search:logs:timed_out" in report.coverage.truncated_reasons
    if fault in {"shards", "both"}:
        assert report.coverage.shard_failures == [{"index": "logs", "failed": 1}]
    if fault == "truncated":
        assert "search:logs:response_size_cap" in report.coverage.truncated_reasons
    assert any(request.method == "DELETE" and request.path == "/_pit" for request in api.requests)


@pytest.mark.parametrize("sort_values", [[None], [[1], [1]]], ids=["missing-sort", "repeated-sort"])
def test_unstable_pagination_stops_without_replaying_or_discarding_findings(sort_values: list[Any]) -> None:
    api = DiscoveryAPI()
    calls = 0

    def search(request: DiscoverRequest) -> DiscoverResponse:
        nonlocal calls
        assert calls < len(sort_values), "unstable pagination must stop"
        sort = sort_values[calls]
        calls += 1
        hit = {"_id": str(calls), "_source": {"password": f"page-{calls}-value"}}
        if sort is not None:
            hit["sort"] = sort
        return page([hit])

    api.search = search
    report = DiscoverEngine(api).run()
    assert len(report.findings) == len(sort_values)
    assert "search:logs:unstable_search_after" in report.coverage.truncated_reasons
    assert calls == len(sort_values)
    assert api.requests[-1].method == "DELETE"


@pytest.mark.parametrize("payload", ["fields", "stored_fields"])
def test_source_unavailable_documents_still_scan_returned_field_values(payload: str) -> None:
    api = DiscoveryAPI()
    calls = 0

    def search(request: DiscoverRequest) -> DiscoverResponse:
        nonlocal calls
        calls += 1
        return (
            page([{"_id": "1", payload: {"password": ["field-only-value"]}, "sort": [1]}]) if calls == 1 else page([])
        )

    api.search = search
    report = DiscoverEngine(api).run()
    finding = next(item for item in report.findings if item.value == "field-only-value")
    assert finding.locations[0].path == f"/{payload}/password/0"
    assert report.coverage.documents_scanned == report.coverage.missing_source_documents == 1
    assert "document:logs:source_unavailable" in report.coverage.truncated_reasons


def test_projected_candidate_is_enriched_by_complete_sweep_without_double_counting_document() -> None:
    api = DiscoveryAPI()
    api.mappings = {"logs": {"mappings": {"properties": {"password": {"type": "keyword"}}}}}
    responses: dict[str, int] = {}

    def search(request: DiscoverRequest) -> DiscoverResponse:
        body = json.loads(request.body or b"{}")
        kind = "complete" if body.get("_source") is True else "projected"
        responses[kind] = responses.get(kind, 0) + 1
        if "search_after" in body:
            return page([])
        source: dict[str, Any] = {"password": "projected-value"}
        if kind == "complete":
            source["database"] = {"password": "sweep-extra-value"}
        return page([{"_id": "1", "_source": source, "sort": [1]}])

    api.search = search
    report = DiscoverEngine(api).run()
    assert {finding.value for finding in report.findings} == {"projected-value", "sweep-extra-value"}
    assert report.coverage.documents_scanned == 1
    assert report.coverage.query_candidates == 1
    assert report.coverage.duplicate_documents >= 1
    assert report.coverage.missing_source_documents == 0


@pytest.mark.parametrize("fault", ["exception", "denied", "invalid_hits"])
def test_failure_after_first_page_preserves_evidence_and_falls_back_to_scroll(fault: str) -> None:
    api = DiscoveryAPI()
    searches = 0

    def search(request: DiscoverRequest) -> DiscoverResponse:
        nonlocal searches
        if request.path != "/_search":
            return reply({"_scroll_id": "scroll-1", "hits": {"hits": [], "total": 0}})
        searches += 1
        if searches == 1:
            return page([{"_id": "1", "_source": {"password": "retained-value"}, "sort": [1]}])
        if fault == "exception":
            raise OSError("connection reset by peer")
        if fault == "denied":
            return reply({"error": {"type": "security_exception", "reason": "denied"}}, 403)
        return reply({"hits": "not-an-object"})

    api.search = search
    report = DiscoverEngine(api).run()
    assert [finding.value for finding in report.findings] == ["retained-value"]
    assert report.coverage.documents_scanned == 1
    result = report.legacy_results[0]
    if fault == "invalid_hits":
        assert result["error_detail"]["reason"] == "invalid search hits payload"
    else:
        assert result["error"] is None
        assert result["partial_error_details"]
        assert any(request.path.startswith("/logs/_search?scroll=") for request in api.requests)
    assert any(request.method == "DELETE" and request.path == "/_pit" for request in api.requests)


@pytest.mark.parametrize("remote_fault", ["denied", "timeout", "truncated"])
def test_independent_configuration_failure_does_not_suppress_other_surface_findings(remote_fault: str) -> None:
    api = DiscoveryAPI()
    api.inventory = {"indices": []}
    if remote_fault == "timeout":
        api.remote["/_cluster/settings"] = DiscoverResponse(0, b"", error="read timed out")
    else:
        api.remote["/_cluster/settings"] = reply(
            {}, 403 if remote_fault == "denied" else 200, truncated=remote_fault == "truncated"
        )
    api.remote["/_ingest/pipeline"] = {
        "pipeline-a": {"processors": [{"set": {"field": "password", "value": "pipeline-value"}}]}
    }
    report = DiscoverEngine(api).run()
    assert any(finding.value == "pipeline-value" for finding in report.findings)
    surface = report.coverage.surfaces["cluster_settings"]
    assert surface.status == {"denied": "denied", "timeout": "timeout", "truncated": "partial"}[remote_fault]
    assert report.coverage.surfaces["ingest_pipelines"].objects_scanned == 1
    assert report.error is None


@pytest.mark.parametrize("limit", ["findings", "locations", "scalar"])
def test_configuration_limits_are_visible_and_do_not_claim_complete_coverage(limit: str) -> None:
    api = DiscoveryAPI()
    api.inventory = {"indices": []}
    api.remote["/_cluster/settings"] = {"persistent": {"password": "first-configuration-value"}}
    api.remote["/_ingest/pipeline"] = {
        "a": {"password": "second-configuration-value"},
        "b": {"password": "second-configuration-value"},
    }
    supplied = {
        "findings": DiscoverOptions(max_findings=1),
        "locations": DiscoverOptions(max_locations=1),
        "scalar": DiscoverOptions(max_scalar_bytes=8),
    }[limit]
    report = DiscoverEngine(api, options=supplied).run()
    assert report.coverage.to_dict()["complete"] is False
    if limit == "findings":
        assert [finding.value for finding in report.findings] == ["first-configuration-value"]
        assert "max_findings" in report.coverage.truncated_reasons
        assert len(report.findings) == 1
    elif limit == "locations":
        assert report.coverage.locations_dropped == 1
        assert "max_locations" in report.coverage.truncated_reasons
    else:
        assert report.coverage.surfaces["cluster_settings"].status == "partial"
        assert "cluster_settings:max_scalar_bytes" in report.coverage.truncated_reasons


def test_debug_discovery_renders_bounded_candidates_and_recovery_details_from_real_report() -> None:
    api = DiscoveryAPI()
    api.mappings = {"logs": {"mappings": {"properties": {"password": {"type": "keyword"}}}}}

    def search(request: DiscoverRequest) -> DiscoverResponse:
        body = json.loads(request.body or b"{}")
        offset = body.get("search_after", [0])[0]
        if offset == 2:
            return page([])
        return page(
            [{"_id": str(offset + 1), "_source": {"password": f"candidate-{offset + 1}-value"}, "sort": [offset + 1]}]
        )

    api.search = search
    report = DiscoverEngine(api, options=DiscoverOptions(page_size=1)).run()
    record = {"host": "qa", "port": 9200, "status": "open_no_auth", "discover": True, **report.to_dict()}
    normal = "\n".join(actions._format_detail_records(record, "txt"))
    debug = "\n".join(actions._format_detail_records(record, "txt", debug=True))
    assert "[debug] candidate=" not in normal
    assert '[debug] candidate={"password": "candidate-1-value"}' in debug
    assert "showing first 1 of 2 candidates" in debug
    assert "candidate index=logs hits=2 shown=1" in debug
    assert "\x1b" not in normal + debug


@pytest.mark.parametrize("inventory", [{}, {"unexpected": "not a resolve-index response"}])
def test_invalid_resolve_inventory_cannot_claim_complete_empty_scan(inventory: dict[str, str]) -> None:
    """A successful HTTP envelope alone cannot prove an empty index inventory."""
    api = DiscoveryAPI()
    api.inventory = inventory
    api.remote["/_cat/indices"] = [{"index": "logs", "status": "open"}]
    report = DiscoverEngine(api).run()
    assert report.coverage.indices_enumerated == 1 or not report.coverage.to_dict()["complete"]


@pytest.mark.parametrize("inventory", [{"indices": None}, {"indices": {}}, {"indices": [], "data_streams": "bad"}])
def test_malformed_resolve_fields_use_independent_inventory(inventory) -> None:
    api = DiscoveryAPI()
    api.inventory = inventory
    api.remote["/_cat/indices"] = [{"index": "logs", "status": "open"}]
    report = DiscoverEngine(api).run()
    assert report.error is None
    assert report.coverage.indices_enumerated == report.coverage.indices_scanned == 1
    assert any(request.path.startswith("/_cat/indices") for request in api.requests)


@pytest.mark.parametrize("inventory", [{"indices": []}, {"indices": [], "aliases": [], "data_streams": []}])
def test_explicit_empty_resolve_inventory_completes_without_cat_fallback(inventory) -> None:
    api = DiscoveryAPI()
    api.inventory = inventory
    report = DiscoverEngine(api).run()
    assert report.error is None
    assert report.coverage.indices_enumerated == 0
    assert report.coverage.to_dict()["complete"] is True
    assert not any(request.path.startswith("/_cat/indices") for request in api.requests)


@pytest.mark.parametrize(
    "inventory",
    [
        {"indices": [None]},
        {"indices": [{}]},
        {"indices": [{"name": ""}]},
        {"indices": [{"name": "   "}]},
        {"indices": [{"name": 12}]},
        {"indices": [{"name": ["logs"]}]},
        {"indices": [{"name": "logs", "attributes": "open"}]},
        {"indices": [{"name": "logs", "attributes": [None]}]},
        {"indices": [{"name": "logs", "aliases": "logs-alias"}]},
        {"indices": [{"name": "logs", "aliases": [None]}]},
        {"indices": [{"name": "logs"}, None]},
        {"data_streams": [None]},
        {"data_streams": [{}]},
        {"data_streams": [{"name": 12}]},
        {"data_streams": [{"name": "logs", "backing_indices": "logs"}]},
        {"data_streams": [{"name": "logs", "backing_indices": None}]},
        {"data_streams": [{"name": "logs", "backing_indices": [None]}]},
        {"data_streams": [{"name": "logs", "backing_indices": [{}]}]},
        {"data_streams": [{"name": "logs", "backing_indices": [12]}]},
        {"data_streams": [{"name": "logs", "backing_indices": ["logs", None]}]},
        {"data_streams": [{"name": "logs", "backing_indices": [{"name": ""}]}]},
        {"aliases": [None]},
        {"aliases": [{}]},
        {"aliases": [{"name": 12, "indices": ["logs"]}]},
        {"aliases": [{"name": "logs-alias"}]},
        {"aliases": [{"name": "logs-alias", "indices": "logs"}]},
        {"aliases": [{"name": "logs-alias", "indices": ["logs", None]}]},
    ],
)
def test_malformed_resolve_members_use_independent_cat_inventory(inventory) -> None:
    api = DiscoveryAPI()
    api.inventory = inventory
    api.remote["/_cat/indices"] = [{"index": "logs", "status": "open"}]
    report = DiscoverEngine(api).run()
    assert report.error is None
    assert report.coverage.indices_enumerated == report.coverage.indices_scanned == 1
    assert [item["index"] for item in report.legacy_results] == ["logs"]
    assert any(request.path.startswith("/_cat/indices") for request in api.requests)


def test_resolve_alias_only_inventory_scans_concrete_index_without_cat() -> None:
    api = DiscoveryAPI()
    api.inventory = {"aliases": [{"name": "logs-alias", "indices": ["logs"]}]}
    report = DiscoverEngine(api).run()
    assert report.error is None
    assert report.coverage.indices_enumerated == report.coverage.indices_scanned == 1
    assert [item["index"] for item in report.legacy_results] == ["logs"]
    assert not any(request.path.startswith("/_cat/indices") for request in api.requests)


def test_resolve_aliases_merge_concrete_indices_once_and_preserve_closed_status() -> None:
    api = DiscoveryAPI()
    api.inventory = {
        "indices": [{"name": "archive", "attributes": ["closed"]}],
        "aliases": [{"name": "all-logs", "indices": ["archive", "logs", "logs"]}],
    }
    report = DiscoverEngine(api).run()
    assert report.error is None
    assert report.coverage.indices_enumerated == 2
    assert report.coverage.indices_closed == report.coverage.indices_scanned == 1
    assert [item["index"] for item in report.legacy_results] == ["logs"]
    assert not any(request.path.startswith("/_cat/indices") for request in api.requests)
