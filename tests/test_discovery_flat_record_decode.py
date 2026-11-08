"""Flat spool records must not recursively revisit every primitive field."""

from __future__ import annotations

import json

import pytest

from redposture_core import discovery_engine as data_discovery
from redposture_core import discovery_spool as module


def test_flat_records_decode_once_and_remain_independent(monkeypatch):
    values = module.SpoolingRecords()
    expected = [
        {"type": "gitlab_token", "value": f"fixture-{n}", "enabled": False, "count": 0, "empty": None}
        for n in range(100)
    ]
    for record in expected:
        values.append(record)
    calls = 0
    original = module._DiskValueReferences._decode_disk_refs

    def decode(self, value):
        nonlocal calls
        calls += 1
        return original(self, value)

    monkeypatch.setattr(module._DiskValueReferences, "_decode_disk_refs", decode)
    restored = list(values)
    assert restored == expected
    assert calls <= len(expected), calls
    restored[0]["value"] = "edited"
    assert values[0]["value"] == "fixture-0"


def test_small_mapping_pairs_do_not_measure_unused_child_size(monkeypatch):
    source = {f"secret_{n}": "glpat-" + format(n, "032x") for n in range(20)}
    child_measurements = 0
    original = data_discovery._bounded_json_size

    def measure(value, limit):
        nonlocal child_measurements
        if isinstance(value, str) and value.startswith("glpat-"):
            child_measurements += 1
        return original(value, limit)

    monkeypatch.setattr(data_discovery, "_bounded_json_size", measure)
    matches, size, complete = data_discovery._scan_portioned_value(source, "$.projects", 128)
    expected = {(kind, f"$.projects.{key}", value) for key, value in source.items() for kind in ("gitlab_token",)}
    assert complete and len(matches) == 20
    assert {(m.detector, m.object_path, m.value) for m in matches} == expected
    assert size == sum(len(json.dumps({k: v}, ensure_ascii=False).encode()) for k, v in source.items())
    assert child_measurements == 0, child_measurements


@pytest.mark.parametrize(
    "marker",
    [
        "\x00redposture_disk_value",
        "\x00redposture_spool_value",
        "\x00redposture_container_value",
        "\x00redposture_mapping_value",
        "\x00redposture_path_value",
        "\x00redposture_inline_value",
        "\x00redposture_arena_value",
    ],
)
def test_literal_reference_marker_keys_still_round_trip(marker):
    values = module.SpoolingRecords()
    literal = {marker: "ordinary-source-value"}
    values.append(literal)
    assert list(values) == [literal]


@pytest.mark.parametrize("value", ["", "é🍰", 'a\n\t"\\', {"clé": "é🍰"}, {"secret": 'a\n\t"\\'}])
def test_small_text_json_size_is_exact_without_iterative_encoder(value, monkeypatch):
    expected = len(json.dumps(value, ensure_ascii=False).encode("utf-8"))
    original = json.JSONEncoder.iterencode

    def no_iterencode(*args, **kwargs):
        assert kwargs.get("_one_shot"), "small text records should use the bounded C encoder"
        return original(*args, **kwargs)

    monkeypatch.setattr(json.JSONEncoder, "iterencode", no_iterencode)
    for limit in (expected - 1, expected, expected + 1):
        assert data_discovery._bounded_json_size(value, limit) == (expected if expected <= limit else None)


@pytest.mark.parametrize("value", ["x" * 100_000, {"secret": "x" * 100_000}])
def test_oversized_text_is_rejected_before_serialization(value, monkeypatch):
    def no_dump(*args, **kwargs):
        raise AssertionError("do not allocate a full encoded copy of an oversized value")

    monkeypatch.setattr(json, "dumps", no_dump)
    assert data_discovery._bounded_json_size(value, 65_536) is None


def test_ordinary_nested_json_needs_no_reference_restoration(monkeypatch):
    records = module.SpoolingRecords()
    expected = {"nested": [{"value": "ordinary", "flag": False, "count": 0}], "path": "é.🍰"}
    records.append(expected)

    def no_decode(*args):
        raise AssertionError("ordinary JSON must not revisit every scalar after json.loads")

    monkeypatch.setattr(module._DiskValueReferences, "_decode_disk_refs", no_decode)
    assert list(records) == [expected]
    first = records[0]
    first["nested"][0]["value"] = "edited"
    assert records[0] == expected
    assert list(reversed(records)) == [expected]
