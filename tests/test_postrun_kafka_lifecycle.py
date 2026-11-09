import copy

import pytest

from scripts.verify_postrun import _normalize_for_golden


def record(nonce="a" * 32):
    probe = {
        "topic": "__redposture_probe_" + nonce,
        "create": True,
        "delete": True,
        "cleanup_complete": True,
        "errors": [],
    }
    return {
        "module": "kafka",
        "is_kafka": True,
        "topic_lifecycle": probe,
        "attempted_credentials": [{"username": "a", "topic_lifecycle": probe}],
    }


def test_only_generated_probe_id_changes_are_volatile_and_source_is_preserved():
    first = record()
    saved = copy.deepcopy(first)
    assert _normalize_for_golden(first) == _normalize_for_golden(record("b" * 32))
    assert first == saved


@pytest.mark.parametrize(
    "field,value", [("create", False), ("delete", None), ("cleanup_complete", False), ("errors", ["permission denied"])]
)
def test_lifecycle_failure_is_never_normalized_away(field, value):
    changed = copy.deepcopy(record())
    changed["topic_lifecycle"][field] = value
    assert _normalize_for_golden(changed) != _normalize_for_golden(record())


def test_user_topics_and_discovery_values_keep_their_identifiers():
    first = record()
    user = {"topic_lifecycle": first["topic_lifecycle"]}
    first.update(
        topics=[first["topic_lifecycle"]["topic"]],
        discover_findings=[{"value": first["topic_lifecycle"]["topic"], **user}],
    )
    normalized = _normalize_for_golden(first)
    assert normalized["topics"] == first["topics"]
    assert normalized["discover_findings"] == first["discover_findings"]


def test_per_pair_capability_probe_ids_are_normalized_without_hiding_results():
    first = record()
    second = record("b" * 32)
    for row in (first, second):
        row["credential_capabilities"] = {"topic_count": 4, "topic_lifecycle": row["topic_lifecycle"]}
        row["attempted_credentials"][0] = {"credential_capabilities": row["credential_capabilities"]}
    assert _normalize_for_golden(first) == _normalize_for_golden(second)
    second["credential_capabilities"]["topic_lifecycle"]["delete"] = False
    assert _normalize_for_golden(first) != _normalize_for_golden(second)
