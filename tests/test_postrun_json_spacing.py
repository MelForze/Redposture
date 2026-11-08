"""Rich fixture checks accept streaming JSON without weakening value checks."""

from __future__ import annotations

import json

import pytest

from scripts import verify_postrun as verifier


@pytest.mark.parametrize("formatting", [{}, {"separators": (",", ":")}, {"indent": 2}])
def test_rich_elastic_seed_check_is_independent_of_json_whitespace(tmp_path, formatting):
    payload = {"discover_schema_version": 2, "discover_findings": [{"value": "elastic-prod-api-key-2026"}]}
    artifact = tmp_path / "elastic.json"
    artifact.write_text(json.dumps(payload, **formatting))
    log = tmp_path / "elastic.log"
    log.write_text("")
    verifier._validate_rich_lab_outputs(
        [{"label": "elastic_open", "exit_code": "0", "json_path": str(artifact), "log_path": str(log)}]
    )


@pytest.mark.parametrize("wrong", [20, 2.5, "2", None])
def test_rich_seed_check_does_not_accept_a_json_value_prefix(tmp_path, wrong):
    artifact = tmp_path / "elastic.json"
    artifact.write_text(
        json.dumps({"discover_schema_version": wrong, "discover_findings": [], "hint": "elastic-prod-api-key-2026"})
    )
    log = tmp_path / "elastic.log"
    log.write_text("")
    with pytest.raises(SystemExit, match="discover_schema_version"):
        verifier._validate_rich_lab_outputs(
            [{"label": "elastic_open", "exit_code": "0", "json_path": str(artifact), "log_path": str(log)}]
        )


@pytest.mark.parametrize("actual,expected", [("two words", True), ("two  words", False), ("twowords", False)])
def test_rich_json_marker_preserves_whitespace_inside_strings(actual, expected):
    text = json.dumps({"label": actual}, separators=(",", ":"))
    assert verifier._rich_literal_present(text, '"label": "two words"') is expected


@pytest.mark.parametrize("formatting", [{}, {"separators": (",", ":")}, {"indent": 2}])
def test_empty_json_collection_is_not_hidden_by_compact_output(formatting):
    assert verifier._rich_literal_present(json.dumps({"items": []}, **formatting), '"items": []')
    assert not verifier._rich_literal_present(json.dumps({"items": [1]}, **formatting), '"items": []')
