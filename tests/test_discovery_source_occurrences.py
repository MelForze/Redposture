"""Common adapters preserve every real object/row locator for equal secrets."""

from __future__ import annotations

import json

import pytest

from redposture_core.data_discovery import inspect_record
from redposture_core.discovery_values import iter_json_chunks
from redposture_core.secret_detection import SecretMatch

PASSWORD = "inactive-shared-location-secret"


def inspect(module, record):
    result = inspect_record(module, {"status": "open_no_auth", **record})
    return json.loads("".join(iter_json_chunks(result)))


@pytest.mark.parametrize("field", ["documents", "query_documents"])
def test_mongodb_distinct_real_ids_are_retained_and_replayed_document_is_unique(field):
    a = {"database": "qa", "collection": "accounts", "document": {"_id": 0, "password": PASSWORD}}
    b = {"database": "qa", "collection": "accounts", "document": {"_id": "second", "password": PASSWORD}}
    result = inspect("mongodb", {field: [a, b, a]})
    assert result["status"] == "complete"
    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert finding["value"] == PASSWORD and finding["occurrence_count"] == 2
    assert [location["id"] for location in finding["locations"]] == [0, "second"]
    assert all(
        location["database"] == "qa"
        and location["collection"] == "accounts"
        and location["locator_kind"] == "document_id"
        for location in finding["locations"]
    )


def test_mongodb_without_id_uses_explicit_read_order_and_does_not_invent_id():
    document = {"database": "qa", "collection": "accounts", "document": {"password": PASSWORD}}
    finding = inspect("mongodb", {"documents": [document, document]})["findings"][0]
    assert finding["occurrence_count"] == 2
    assert [place["row_ordinal"] for place in finding["locations"]] == [0, 1]
    assert all(place["locator_kind"] == "read_order" and "id" not in place for place in finding["locations"])


def test_postgres_retains_each_row_and_observed_id_column_is_not_assumed_primary_key():
    table = {
        "database": "qa",
        "table": "public.accounts",
        "rows": [{"id": 7, "password": PASSWORD}, {"id": 7, "password": PASSWORD}],
    }
    finding = inspect("postgres", {"table_dumps": [table]})["findings"][0]
    assert finding["occurrence_count"] == 2
    assert [place["row_ordinal"] for place in finding["locations"]] == [0, 1]
    assert all(place["locator_kind"] == "read_order" and "selector" not in place for place in finding["locations"])


def test_postgres_uses_primary_key_only_when_explicit_metadata_and_values_are_available():
    table = {
        "database": "qa",
        "table": "public.accounts",
        "primary_key_columns": ["account_key"],
        "rows": [{"account_key": 0, "password": PASSWORD}, {"account_key": 3, "password": PASSWORD}],
    }
    finding = inspect("postgres", {"table_dumps": [table]})["findings"][0]
    assert [place["selector"] for place in finding["locations"]] == [{"account_key": 0}, {"account_key": 3}]
    assert all(place["locator_kind"] == "primary_key" for place in finding["locations"])


@pytest.mark.parametrize(
    "module,field", [("redis", "key_value_entries"), ("etcd", "key_value_entries"), ("consul", "kv_dump_items")]
)
def test_same_value_in_distinct_keys_keeps_both_places(module, field):
    first = {"key": "app/a/password", "value": PASSWORD}
    second = {"key": "app/b/password", "value": PASSWORD}
    finding = inspect(module, {field: [first, second, first]})["findings"][0]
    assert finding["occurrence_count"] == 2
    assert len({place["object_path"] for place in finding["locations"]}) == 2


def test_findings_completed_before_source_timeout_survive_final_publication(monkeypatch):
    from redposture_core import data_discovery

    clock = [0.0]
    monkeypatch.setattr(data_discovery.time, "monotonic", lambda: clock[0])

    def completed_then_timeout(_value, path, *_args, **_kwargs):
        clock[0] = 11.0
        return [SecretMatch("password", "high", path + ".password", PASSWORD)], 100, False

    monkeypatch.setattr(data_discovery, "_scan_portioned_value", completed_then_timeout)
    result = inspect_record("redis", {"key_value_entries": [{"key": "app", "value": "body"}]}, max_seconds=10)
    assert result["status"] == "partial" and "time_budget" in result["partial_reasons"]
    assert [row["value"] for row in result["findings"]] == [PASSWORD]
    assert result["findings"][0]["occurrence_count"] == 1
