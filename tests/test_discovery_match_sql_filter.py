"""Disk match filtering preserves exact ordered values without re-decoding all rows."""

from __future__ import annotations

import pytest

from redposture_core.discovery_matches import SpoolingSecretMatches, prefer_specific_matches
from redposture_core.discovery_spool import SpoolingRecords
from redposture_core.discovery_values import DiskBackedText
from redposture_core.secret_detection import SecretMatch


def test_specific_filter_keeps_input_and_streams_encoded_output(monkeypatch: pytest.MonkeyPatch) -> None:
    specific = SecretMatch("gitlab_token", "high", "$.token", "glpat-abcdefghijklmnopqrst")
    generic = SecretMatch("generic_secret", "high", "$.another", specific.value)
    unrelated = SecretMatch("generic_secret", "high", "$.other", "different-secret")
    matches = SpoolingSecretMatches([generic, specific, unrelated, unrelated], inline_limit=0)
    with monkeypatch.context() as patch:

        def no_iteration(_self):
            pytest.fail("do not reconstruct every match for SQL filtering")

        patch.setattr(SpoolingRecords, "__iter__", no_iteration)
        filtered = prefer_specific_matches(matches)
    assert list(filtered) == [specific, unrelated, unrelated]
    assert list(matches) == [generic, specific, unrelated, unrelated]


@pytest.mark.parametrize("value", ["plain", "кириллица-λ", "nul\x00tail", 'quote"\\end'])
def test_specific_filter_preserves_full_scalar_identity_and_paths(value: str) -> None:
    values = [
        SecretMatch("password", "high", "$.specific", value),
        SecretMatch("high_entropy", "low", "$.same", value),
        SecretMatch("generic_secret", "high", "$.different", value + "x"),
    ]
    assert list(prefer_specific_matches(SpoolingSecretMatches(values, inline_limit=0))) == [values[0], values[2]]


def test_specific_filter_retains_owned_disk_values_and_incomplete_reason() -> None:
    value = DiskBackedText()
    value.append_text("Sa7/" * 20_000)
    value.finish()
    specific = SecretMatch("password", "high", "$.password", value)
    generic = SecretMatch("high_entropy", "low", "$.other", value)
    matches = SpoolingSecretMatches([specific, generic], inline_limit=0)
    matches.incomplete_reason = "storage_failure"
    filtered = prefer_specific_matches(matches)
    assert len(filtered) == 1
    assert filtered.incomplete_reason == "storage_failure"
    assert next(iter(filtered)).value.digest == value.digest


def test_sql_filter_without_json_extension_uses_original_fingerprint_path(monkeypatch: pytest.MonkeyPatch) -> None:
    import sqlite3

    original_connect = sqlite3.connect

    class NoJSON(sqlite3.Connection):
        def execute(self, query, parameters=()):
            if query == "SELECT json_type('{}')":
                raise sqlite3.OperationalError("no such function: json_type")
            return super().execute(query, parameters)

    def connect(*args, **kwargs):
        return original_connect(*args, factory=NoJSON, **kwargs)

    specific = SecretMatch("password", "high", "$.first", "specific-value")
    values = [specific, SecretMatch("high_entropy", "low", "$.second", specific.value)]
    matches = SpoolingSecretMatches(values, inline_limit=0)
    monkeypatch.setattr(sqlite3, "connect", connect)
    assert list(prefer_specific_matches(matches)) == [specific]


def test_sql_filter_propagates_storage_failure_and_keeps_input(monkeypatch: pytest.MonkeyPatch) -> None:
    import sqlite3

    original_connect = sqlite3.connect

    class FailedTemp(sqlite3.Connection):
        def execute(self, query, parameters=()):
            if query.startswith("CREATE TEMP TABLE specific_values"):
                raise sqlite3.OperationalError("database or disk is full")
            return super().execute(query, parameters)

    def connect(*args, **kwargs):
        return original_connect(*args, factory=FailedTemp, **kwargs)

    specific = SecretMatch("password", "high", "$.first", "specific-value")
    values = [specific, SecretMatch("high_entropy", "low", "$.second", specific.value)]
    matches = SpoolingSecretMatches(values, inline_limit=0)
    monkeypatch.setattr(sqlite3, "connect", connect)
    with pytest.raises(OSError, match="filtering storage failure"):
        prefer_specific_matches(matches)
    assert list(matches) == values


@pytest.mark.parametrize("inline_limit", [0, 2048])
def test_specific_filter_retains_partial_reason_with_small_values(inline_limit: int) -> None:
    first = SecretMatch("password", "high", "$.one", "completed-value")
    matches = SpoolingSecretMatches(
        [first, SecretMatch("high_entropy", "low", "$.two", first.value)], inline_limit=inline_limit
    )
    matches.incomplete_reason = "discover_time"
    filtered = prefer_specific_matches(matches, inline_limit=inline_limit)
    assert list(filtered) == [first]
    assert filtered.incomplete_reason == "discover_time"


@pytest.mark.parametrize("with_nul", [False, True])
def test_disk_filter_matches_reference_on_unicode_duplicates_and_detector_mixes(with_nul: bool) -> None:
    import random

    from redposture_core.secret_detection import fingerprint

    random_source = random.Random(20261103)
    texts = ["one", "secret-token", "é", "e\u0301", '"quoted"', "λ🌍"]
    if with_nul:
        texts += ["NUL\x00tail", "\\u0000redposture_disk_value"]
    detectors = ["generic_secret", "high_entropy", "password", "gitlab_token", "api_key"]
    for _ in range(40):
        values = [
            SecretMatch(random_source.choice(detectors), "high", f"$.p{index}", random_source.choice(texts))
            for index in range(30)
        ]
        specifics = {
            fingerprint(item.value) for item in values if item.detector not in {"generic_secret", "high_entropy"}
        }
        expected = [
            item
            for item in values
            if item.detector not in {"generic_secret", "high_entropy"} or fingerprint(item.value) not in specifics
        ]
        assert list(prefer_specific_matches(SpoolingSecretMatches(values, inline_limit=0))) == expected
