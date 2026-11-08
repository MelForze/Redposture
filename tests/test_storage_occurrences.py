"""Live storage collection and surface merging retain all unique locations."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from redposture_core.discovery_values import iter_json_chunks
from redposture_core.storage_discovery import DiscoveryCollector, merge_discovery_results

PASSWORD = "inactive-location-storage-password"


def collector(module="gitlab", emitted=None):
    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=900), host="qa", port=443)
    if emitted is not None:
        ctx.live_emit = emitted.extend
    return DiscoveryCollector(module, ctx, {"status": "open_no_auth"})


def plain(result):
    return json.loads("".join(iter_json_chunks(result)))


def test_live_value_emits_once_while_repeated_sources_keep_all_places():
    emitted = []
    target = collector(emitted=emitted)
    for path in ("project/a", "project/b", "project/a"):
        assert target.add(path, {"password": PASSWORD})
    result = plain(target.result())
    assert len(result["findings"]) == 1
    row = result["findings"][0]
    assert row["occurrence_count"] == 2
    assert {p["object"] for p in row["locations"]} == {"project/a", "project/b"}
    assert sum(PASSWORD in line for line in emitted) == 1
    assert result["emitted_fingerprints"] == [row["fingerprint"]]


def test_merging_surfaces_retains_locations_and_live_provenance():
    emitted = []
    left, right = collector(emitted=emitted), collector()
    left.add("ui/project/a", {"password": PASSWORD})
    right.add("backend/project/b", {"password": PASSWORD})
    result = plain(merge_discovery_results(left.result(), right.result()))
    assert result["status"] == "complete" and len(result["findings"]) == 1
    assert result["findings"][0]["occurrence_count"] == 2
    assert {p["object"] for p in result["findings"][0]["locations"]} == {"ui/project/a", "backend/project/b"}
    assert result["emitted_fingerprints"] == [result["findings"][0]["fingerprint"]]


def test_native_mongo_document_callback_keeps_real_ids_including_zero():
    target = collector("mongodb")
    for identifier in (0, "second", 0):
        target.add("qa.accounts", {"_id": identifier, "password": PASSWORD})
    row = plain(target.result())["findings"][0]
    assert row["occurrence_count"] == 2
    assert [p["id"] for p in row["locations"]] == [0, "second"]
    assert all(p["locator_kind"] == "document_id" for p in row["locations"])


def test_mongo_transport_keeps_object_id_distinct_from_same_hex_string():
    from bson import ObjectId

    from redposture_core.clients.mongodb import _discovery_document

    target = collector("mongodb")
    identifier = ObjectId("0123456789abcdef01234567")
    for key in (identifier, str(identifier)):
        target.add("qa.accounts", _discovery_document({"_id": key, "password": PASSWORD}, None))
    row = plain(target.result())["findings"][0]
    assert row["occurrence_count"] == 2
    assert [item["id"] for item in row["locations"]] == [{"$oid": str(identifier)}, str(identifier)]


def test_adapter_supplied_row_locators_are_not_collapsed_by_equal_field_paths():
    target = collector("postgres")
    for row_number in (0, 1):
        target.add(
            "table/qa/accounts",
            {"password": PASSWORD},
            location={
                "source_kind": "table_row",
                "object": "qa.accounts",
                "row_ordinal": row_number,
                "locator_kind": "read_order",
            },
        )
    row = plain(target.result())["findings"][0]
    assert row["occurrence_count"] == 2
    assert [p["row_ordinal"] for p in row["locations"]] == [0, 1]


def test_scoped_source_location_is_nested_owner_specific_and_reset_after_error():
    target, other = collector("postgres"), collector("gitlab")
    with target.source_location({"object": "outer", "row_ordinal": 0, "locator_kind": "read_order"}):
        target.add("table", {"password": PASSWORD})
        other.add("unrelated", {"password": PASSWORD})
        with pytest.raises(ValueError), target.source_location({"object": "inner", "row_ordinal": 1}):
            target.add("table", {"password": PASSWORD})
            raise ValueError("source failed")
        target.add("table", {"password": PASSWORD})
    target.add("after", {"password": PASSWORD})
    locations = plain(target.result())["findings"][0]["locations"]
    assert [item["object"] for item in locations] == ["outer", "inner", "after"]
    assert plain(other.result())["findings"][0]["locations"][0]["object"] == "unrelated"


@pytest.mark.parametrize("module", ["gitlab", "portainer", "harbor", "nexus", "docker-registry"])
def test_many_places_survive_surface_merge_without_the_old_location_cap(module):
    left, right = collector(module), collector(module)
    for index in range(150):
        left.add(f"object/{index}", {"password": PASSWORD})
        right.add(f"object/{index + 100}", {"password": PASSWORD})
    row = plain(merge_discovery_results(left.result(), right.result()))["findings"][0]
    assert row["occurrence_count"] == len(row["locations"]) == 250
    assert {p["object"] for p in row["locations"]} == {f"object/{i}" for i in range(250)}


def test_all_denied_surfaces_remain_unavailable_not_partial():
    denied = {
        "status": "unavailable",
        "source": "access_unverified",
        "findings": [],
        "partial_reasons": ["source: access_denied"],
    }
    merged = merge_discovery_results(denied, denied)
    assert merged["status"] == "unavailable"
    assert merged["findings"] == []
    assert merged["partial_reasons"] == ["source: access_denied"]


def test_surface_merge_keeps_source_access_evidence_and_accumulates_same_class():
    left, right = collector("gitlab"), collector("gitlab")
    with left.source_attempt("gitlab.files", scope="project_selection") as source:
        source.accept(2)
    with right.source_attempt("gitlab.files", scope="project_selection") as source:
        source.status = 403
        right.partial("files", "access_denied")
    merged = merge_discovery_results(left.result(), right.result())
    row = next(r for r in merged["sources"] if r["id"] == "gitlab.files")
    assert row["requested"] == 2 and row["read"] == 2 and row["denied"] == 1
    assert not row["complete"] and merged["status"] == "partial"


def test_equal_value_across_secret_field_types_has_one_finding_and_all_places():
    target = collector("gitlab")
    for name in ("password", "client_secret", "api_key"):
        assert target.add("project/settings", {name: PASSWORD})
    findings = plain(target.result())["findings"]
    assert len(findings) == 1
    assert findings[0]["occurrence_count"] == 3
    assert {p["object_path"] for p in findings[0]["locations"]} == {
        f"$.project/settings.{name}" for name in ("password", "client_secret", "api_key")
    }
