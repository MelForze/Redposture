"""A literal dotted key must never collide with a nested JSON path."""

from __future__ import annotations

import json
from types import SimpleNamespace

from redposture_core.discovery_values import DiskBackedText, iter_json_chunks
from redposture_core.storage_discovery import DiscoveryCollector


def test_literal_key_and_nested_key_remain_two_distinct_occurrences():
    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=900), host="qa", port=443)
    collector = DiscoveryCollector("gitlab", ctx, {"status": "open_no_auth"})
    collector.add(
        "config", {"a.b": {"password": "inactive-path-password"}, "a": {"b": {"password": "inactive-path-password"}}}
    )
    finding = json.loads("".join(iter_json_chunks(collector.result())))["findings"][0]
    assert finding["occurrence_count"] == 2
    assert {row["object_path"] for row in finding["locations"]} == {'$.config["a.b"].password', "$.config.a.b.password"}


def test_large_json_and_scalar_paths_have_the_same_distinct_field_locations():
    from redposture_core.discovery_engine import _scan_portioned_value

    value = {"a.b": {"password": "inactive-path-password"}, "a": {"b": {"password": "inactive-path-password"}}}
    with DiskBackedText() as source:
        source.append_text(json.dumps(value))
        source.finish()
        found, _, complete = _scan_portioned_value(source, "$", 64)
        assert complete
        assert {row.object_path for row in found} == {'$["a.b"].password', "$.a.b.password"}


def test_long_value_under_literal_dotted_sensitive_key_is_not_lost():
    from redposture_core.discovery_engine import _scan_portioned_value

    value = "inactive" + "Ab0λ " * 20000
    found, _, complete = _scan_portioned_value({"db.password": value}, "$", 64)
    assert complete and len(found) == 1
    assert found[0].object_path == '$["db.password"]'
    assert "".join(found[0].value.iter_text_chunks()) == value
