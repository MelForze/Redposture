"""Every source survives value deduplication, including disk-owned locators."""

from __future__ import annotations

import gc
import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from redposture_core.discovery_occurrences import OccurrenceRegistry
from redposture_core.discovery_spool import SpoolingRecords, contains_spooled
from redposture_core.discovery_values import DiskBackedText, iter_json_chunks
from redposture_core.secret_detection import fingerprint


def finding(value="inactive-occurrence-secret", kind="password", path="$.password"):
    return {"type": kind, "fingerprint": fingerprint(value), "value": value, "object_path": path, "source": "test"}


def materialize(value):
    return json.loads("".join(iter_json_chunks(value)))


def test_value_emits_once_but_keeps_every_distinct_location():
    store = OccurrenceRegistry()
    row = finding()
    assert store.add(row, location={"object": "project/a", "path": "/password"})
    assert not store.add(row, location={"object": "project/b", "path": "/password"})
    assert not store.add(row, location={"path": "/password", "object": "project/a"})
    result = materialize(store)
    assert len(result) == 1
    assert result[0]["occurrence_count"] == 2
    assert result[0]["locations"] == [
        {"object": "project/a", "path": "/password"},
        {"object": "project/b", "path": "/password"},
    ]
    assert result[0]["value"] == row["value"]


def test_location_snapshot_has_consistent_length_iteration_and_reverse_during_live_appends():
    store = OccurrenceRegistry()
    row = finding()
    store.add(row, location={"path": "/first"})
    first = store.lookup((row["type"], row["fingerprint"]))["locations"]
    store.add(row, location={"path": "/second"})
    assert len(first) == 1 and list(first) == [{"path": "/first"}]
    assert list(reversed(first)) == [{"path": "/first"}]
    current = store.lookup((row["type"], row["fingerprint"]))["locations"]
    assert len(current) == 2 and current[-1] == {"path": "/second"}


def test_locations_have_no_hundred_item_cap_and_replays_do_not_inflate_count():
    store = OccurrenceRegistry()
    for index in range(1200):
        store.add(finding(), location={"object": f"document/{index}", "path": "/password"})
    for index in range(1200):
        store.add(finding(), location={"object": f"document/{index}", "path": "/password"})
    row = store[0]
    assert row["occurrence_count"] == len(row["locations"]) == 1200
    assert [p["object"] for p in row["locations"]] == [f"document/{i}" for i in range(1200)]


def test_engine_can_deduplicate_value_across_detector_aliases():
    store = OccurrenceRegistry()
    row = finding()
    key = ("value", row["fingerprint"])
    assert store.add(row, location={"path": "/password"}, identity=key)
    assert not store.add(finding(kind="api_key"), location={"path": "/api_key"}, identity=key)
    assert len(store) == 1
    assert store[0]["occurrence_count"] == 2


def test_emission_projection_does_not_drop_locations():
    store = OccurrenceRegistry()
    row = finding()
    store.add(row, location={"path": "/a"})
    store.add(row, location={"path": "/b"}, emitted=True, merge_emission=True)
    assert list(store.iter_unemitted()) == []
    result, emitted = next(store.iter_with_emission())
    assert emitted and result["occurrence_count"] == 2


def test_locations_keep_owner_alive_and_can_be_spooled_without_expansion():
    store = OccurrenceRegistry()
    store.add(finding(), location={"object": "пример", "path": "/пароль"})
    path = store._path
    row = store[0]
    retained = SpoolingRecords()
    retained.append(row)
    del store, row
    gc.collect()
    assert path.exists()
    assert contains_spooled(retained)
    restored = materialize(retained)[0]
    assert restored["locations"] == [{"object": "пример", "path": "/пароль"}]
    del retained
    gc.collect()
    assert not path.exists()


def test_full_disk_value_and_path_survive_after_inputs_close():
    value, path = DiskBackedText(), DiskBackedText()
    value.append_text("inactive-long-value-" * 7000)
    value.finish()
    path.append_text("/" + "объект/" * 15000 + "password")
    path.finish()
    expected_value = "inactive-long-value-" * 7000
    expected_path = "/" + "объект/" * 15000 + "password"
    store = OccurrenceRegistry()
    store.add(finding(value=value, path=path), location={"path": path})
    value.close()
    path.close()
    result = materialize(store)[0]
    assert result["value"] == expected_value
    assert result["locations"] == [{"path": expected_path}]
    assert "\x1b[" not in result["value"] and "DiskBackedText" not in result["value"]


@pytest.mark.parametrize("failed_new_value", [False, True])
def test_disk_failure_keeps_completed_prefix_and_no_unlocated_finding(failed_new_value):
    store = OccurrenceRegistry()
    store.add(finding(), location={"path": "/completed"})
    assert store._db is not None
    store._db.execute(
        "CREATE TRIGGER reject_location BEFORE INSERT ON occurrences "
        "BEGIN SELECT RAISE(ABORT,'injected disk failure'); END"
    )
    with pytest.raises(OSError, match="storage failure"):
        store.add(
            finding(value="second-completed-secret") if failed_new_value else finding(), location={"path": "/rejected"}
        )
    rows = materialize(store)
    assert len(rows) == len(store) == 1
    assert rows[0]["occurrence_count"] == 1
    assert rows[0]["locations"] == [{"path": "/completed"}]


def test_list_access_and_equality_use_the_disk_rows():
    store = OccurrenceRegistry()
    for index in range(3):
        store.add(finding(value=f"complete-secret-{index}"), location={"path": f"/{index}"})
    assert store[-1]["locations"][0] == {"path": "/2"}
    assert store[:2][1]["locations"] == [{"path": "/1"}]
    assert list(reversed(store))[0]["locations"] == [{"path": "/2"}]
    with pytest.raises(IndexError):
        _ = store[3]


def test_missing_locator_or_identity_is_rejected():
    store = OccurrenceRegistry()
    with pytest.raises(ValueError, match="location"):
        store.add({"type": "password", "fingerprint": "f", "value": "complete-secret"})
    with pytest.raises(ValueError, match="identity"):
        store.add({"object_path": "/password"})


def test_inline_projection_is_bounded_for_both_values_and_location_counts():
    small = OccurrenceRegistry()
    small.add(finding(), location={"path": "/one"})
    result = small.bounded_inline_view()
    assert type(result) is list and result[0]["locations"] == [{"path": "/one"}]
    large = OccurrenceRegistry()
    large.add(finding(value="inactive-large-value-" * 10000), location={"path": "/one"})
    assert large.bounded_inline_view() is large
    locations = OccurrenceRegistry()
    for index in range(1000):
        locations.add(finding(), location={"path": "/" + str(index) + "p" * 80})
    assert locations.bounded_inline_view() is locations


def test_concurrent_publishers_keep_unique_locations_and_emit_once():
    store = OccurrenceRegistry()

    def publish(index):
        return store.add(finding(), location={"object": f"document/{index % 100}", "path": "/password"})

    with ThreadPoolExecutor(max_workers=8) as pool:
        created = list(pool.map(publish, range(1000)))
    assert sum(created) == 1
    row = store[0]
    assert row["occurrence_count"] == len(row["locations"]) == 100
    assert {location["object"] for location in row["locations"]} == {f"document/{i}" for i in range(100)}


def test_deadline_during_long_locator_hash_keeps_completed_prefix_and_detaches_for_output():
    checks = 0

    def check():
        nonlocal checks
        checks += 1
        if checks > 10:
            raise TimeoutError("discover_time")

    store = OccurrenceRegistry(check=check)
    store.add(finding(), location={"path": "/completed"})
    with pytest.raises(TimeoutError):
        store.add(finding(), location={"path": "/" + "long-locator" * 10000})
    rows = materialize(store)
    assert len(rows) == 1 and rows[0]["locations"] == [{"path": "/completed"}]
    assert store._check is None
