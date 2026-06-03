from __future__ import annotations

from pathlib import Path

from scripts.matrix_flag_coverage import build_coverage_report, parse_matrix_cases
from scripts.verify_postrun import _expected_labels_for_profile


def test_matrix_flag_coverage_has_no_missing_parser_actions() -> None:
    report = build_coverage_report(Path("scripts/run_lab_matrix_sequential.sh"))

    assert report["missing_actions"] == {}
    assert report["summary"]["missing_actions"] == 0
    assert report["summary"]["total_parser_actions"] > 0


def test_matrix_case_parser_keeps_env_prefixed_proxy_cases() -> None:
    cases = parse_matrix_cases(Path("scripts/run_lab_matrix_sequential.sh").read_text(encoding="utf-8"))
    by_label = {case.label: case for case in cases}

    assert by_label["proxy_exporters_https"].command_key == "exporters scan"
    assert "--proxy" in by_label["proxy_exporters_https"].tokens
    assert by_label["proxy_redis_https"].command_key == "redis"


def test_extended_matrix_labels_are_present_in_script() -> None:
    cases = parse_matrix_cases(Path("scripts/run_lab_matrix_sequential.sh").read_text(encoding="utf-8"))
    labels = {case.label for case in cases}

    for label in {
        "exporters_collect_extended_controls",
        "registry_extended_tags_metadata",
        "mongodb_extended_document_index_cmd",
        "kafka_extended_dump_max_conflict",
        "proxy_redis_https",
    }:
        assert label in labels


def test_extended_verifier_labels_cover_script_labels() -> None:
    cases = parse_matrix_cases(Path("scripts/run_lab_matrix_sequential.sh").read_text(encoding="utf-8"))
    script_labels = {case.label for case in cases}
    verifier_labels = set(_expected_labels_for_profile("extended"))

    assert script_labels <= verifier_labels
