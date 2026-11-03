"""Per-source intermediate match collections must not grow the Python heap."""

from __future__ import annotations

import tracemalloc
from types import SimpleNamespace

import pytest

from redposture_core.data_discovery import _scan_portioned_value
from redposture_core.discovery_matches import SpoolingSecretMatches, prefer_specific_matches
from redposture_core.discovery_values import DiskBackedText
from redposture_core.secret_detection import SecretMatch
from redposture_core.storage_discovery import DiscoveryCollector
from scripts.qa_memory_workload import run_memory_workload


def test_many_text_findings_are_retained_without_one_large_memory_list() -> None:
    count = 100_000
    text = "".join(f"password=secret-value-{number:08d}\n" for number in range(count))
    tracemalloc.start()
    try:
        matches, size, complete = _scan_portioned_value(text, "$.log", 65_536)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert complete and size == len(text)
    assert len(matches) == count
    assert matches[0].value == "secret-value-00000000"
    assert matches[-1].value == "secret-value-00099999"
    assert all(match.detector == "password" and match.object_path == "$.log" for match in matches)
    assert peak < 8_000_000, f"intermediate findings retained {peak} bytes"


def test_match_spool_also_bounds_memory_when_individual_values_are_medium_sized() -> None:
    tracemalloc.start()
    try:
        matches = SpoolingSecretMatches()
        for number in range(400):
            matches.append(SecretMatch("password", "high", "$", "Sa7/" * 15_000 + str(number)))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert len(matches) == 400
    assert matches[-1].value.endswith("399")
    assert peak < 8_000_000


def test_a_small_match_slice_does_not_load_all_values_from_disk() -> None:
    matches = SpoolingSecretMatches(inline_limit=0)
    for number in range(400):
        matches.append(SecretMatch("password", "high", "$", "Sa7/" * 15_000 + str(number)))
    tracemalloc.start()
    try:
        prefix = matches[:1]
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert len(prefix) == 1 and prefix[0].value.endswith("0")
    assert peak < 2_000_000


def test_match_spool_preserves_order_duplicates_slices_and_disk_values() -> None:
    value = DiskBackedText()
    value.append_text("full-secret-value")
    value.finish()
    first = SecretMatch("password", "high", "$.one", "small-secret")
    last = SecretMatch("api_key", "high", "$.last", value)
    matches = SpoolingSecretMatches([first, first, last], inline_limit=1)
    assert len(matches) == 3
    assert [match.detector for match in matches] == ["password", "password", "api_key"]
    assert [match.object_path for match in matches] == ["$.one", "$.one", "$.last"]
    assert [match.value for match in matches[:2]] == [first.value, first.value]
    assert [match.detector for match in matches[1:]] == ["password", "api_key"]
    assert [match.detector for match in reversed(matches)] == ["api_key", "password", "password"]
    restored = matches[-1].value
    assert isinstance(restored, DiskBackedText)
    assert restored.digest == value.digest and restored.byte_length == value.byte_length
    assert "".join(restored.iter_text_chunks()) == "full-secret-value"


def _check_specific_filter(count: int) -> dict[str, int]:
    source = {f"secret_{number}": "glpat-" + format(number, "032x") for number in range(count)}
    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=900), host="qa", port=80)
    collector = DiscoveryCollector("gitlab", ctx, {"status": "open_no_auth"})
    tracemalloc.start()
    try:
        assert collector.add("projects", source, prefer_specific=True)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    report = collector.result()
    assert report["status"] == "complete"
    assert len(report["findings"]) == count
    assert all(item["type"] == "gitlab_token" for item in report["findings"])
    assert peak < 12_000_000, f"specific detector filter retained {peak} bytes"
    return {"count": count, "peak": peak}


def test_specific_detector_filter_does_not_rebuild_large_lists_or_fingerprint_sets() -> None:
    # This parent input also exercises both disk-spill thresholds under branch
    # coverage; the isolated child still checks the full 100k cardinality.
    _check_specific_filter(8192)
    run_memory_workload(__file__, "_check_specific_filter", 100_000)


@pytest.mark.parametrize("inline_limit", [0, 2048])
@pytest.mark.parametrize("spooled", [False, True])
def test_specific_filter_preserves_unmatched_generic_occurrences_and_paths(inline_limit: int, spooled: bool) -> None:
    generic = SecretMatch("generic_secret", "high", "$.one", "ordinary-secret")
    generic_again = SecretMatch("generic_secret", "high", "$.two", "ordinary-secret")
    suppressed = SecretMatch("generic_secret", "high", "$.three", "glpat-abcdefghijklmnopqrst")
    specific = SecretMatch("gitlab_token", "high", "$.three", suppressed.value)
    values = [generic, suppressed, specific, generic_again]
    matches = SpoolingSecretMatches(values, inline_limit=0) if spooled else values
    assert list(prefer_specific_matches(matches, inline_limit=inline_limit)) == [generic, specific, generic_again]


@pytest.mark.parametrize("spooled", [False, True])
def test_specific_filter_does_not_emit_same_password_as_high_entropy(spooled: bool) -> None:
    value = "qa-history-secret-7d8f9b0c1d2e3f4a5b6c"
    specific = SecretMatch("password", "high", "$.password", value)
    heuristic = SecretMatch("high_entropy", "medium", "$.password", value)
    unrelated = SecretMatch("high_entropy", "medium", "$.other", "AbcD3fGhJ6kLmN9pQrS2tUvW5xYz")
    values = [specific, heuristic, unrelated]
    matches = SpoolingSecretMatches(values, inline_limit=0) if spooled else values
    assert list(prefer_specific_matches(matches)) == [specific, unrelated]
