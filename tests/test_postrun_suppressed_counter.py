"""Generated index IDs affect diagnostic suppression, never the finding contract."""

import copy
from typing import Never

import pytest

from scripts.verify_postrun import _normalize_for_golden


def record(count=40):
    return {
        "module": "elastic",
        "discover": True,
        "discover_coverage": {
            "suppressed_indicators": count,
            "status": "complete",
            "complete": True,
            "documents_scanned": 3,
            "indices_scanned": 1,
        },
        "discover_findings": [
            {
                "value": "inactive-password!42",
                "secret_type": "password",
                "confidence": "high",
                "locations": [{"source_kind": "document", "object": "corpus/one"}],
            }
        ],
    }


def normalize(value):
    return _normalize_for_golden(value, module="elastic")


def test_only_root_diagnostic_count_is_volatile_and_input_is_not_modified():
    first = record(38)
    second = record(40)
    saved = copy.deepcopy(first)
    assert normalize(first) == normalize(second)
    assert normalize([first]) == normalize([second])
    assert first == saved
    assert "suppressed_indicators" not in normalize(first)["discover_coverage"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("complete", False),
        ("status", "partial"),
        ("documents_scanned", 2),
        ("indices_scanned", 0),
    ],
)
def test_semantic_coverage_fields_stay_strict(field, value):
    first = record()
    second = record()
    second["discover_coverage"][field] = value
    assert normalize(first) != normalize(second)


@pytest.mark.parametrize(
    "field,value",
    [
        ("value", "different-password!42"),
        ("secret_type", "high_entropy"),
        ("confidence", "low"),
        ("locations", []),
    ],
)
def test_findings_stay_strict(field, value):
    first = record()
    second = record()
    second["discover_findings"][0][field] = value
    assert normalize(first) != normalize(second)


@pytest.mark.parametrize("value", [True, -1, "40", None])
def test_malformed_diagnostic_counts_are_not_hidden(value):
    second = record(value)
    assert normalize(record()) != normalize(second)


def test_nested_finding_values_keep_same_named_data():
    first = record()
    second = record()
    for item, count in ((first, 38), (second, 40)):
        item["discover_findings"][0]["value"] = {
            "module": "elastic",
            "discover_coverage": {"suppressed_indicators": count},
        }
    assert normalize(first) != normalize(second)


@pytest.mark.parametrize("module", ["postgres", "mongodb"])
def test_other_modules_keep_same_named_diagnostic_data(module):
    first, second = record(1), record(2)
    first["module"] = second["module"] = module
    assert _normalize_for_golden(first, module=module) != _normalize_for_golden(second, module=module)


def test_actual_generated_index_ids_can_change_count_without_any_finding():
    from redposture_core.modules.elastic.discover import DiscoverEngine

    def no_request(_request: object) -> Never:
        raise AssertionError("configuration-only reproduction sent a network request")

    counts = []
    for identifier in ("a" * 22, "q7XeN4rBm9Vk2Aa8Hs5DuZ"):
        engine = DiscoverEngine(no_request)
        engine._scan_configuration(
            "index_settings",
            {"settings": {"index": {"uuid": identifier}}},
            object_name="qa",
            source_kind="index_settings",
            index="qa",
        )
        assert len(engine.accumulator) == 0
        counts.append(engine.coverage.suppressed_indicators)
    assert counts == [0, 1]
