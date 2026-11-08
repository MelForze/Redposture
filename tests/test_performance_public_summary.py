"""Known host partitions must agree with the saved public JSON footer."""

from __future__ import annotations

import json

import pytest

from scripts.performance_contracts import public_summary_errors

ROLES = {0: "positive", 1: "foreign", 2: "closed"}


def summary():
    return {
        "type": "summary",
        "module": "kafka",
        "status": "partial",
        "reason": "partial_operational_failure",
        "requested_targets": 3,
        "processed_targets": 3,
        "record_count": 3,
        "detected_count": 1,
        "operational_failure_count": 1,
        "conclusive_negative_count": 1,
    }


def test_summary_is_checked_without_materializing_large_ordinary_records(tmp_path):
    path = tmp_path / "out.json"
    with path.open("w") as handle:
        handle.write('{"value":"')
        for _ in range(100):
            handle.write("x" * 65536)
        handle.write('"}\n' + json.dumps(summary()) + "\n")
    assert public_summary_errors(path, ROLES) == []


@pytest.mark.parametrize(
    "field",
    [
        "record_count",
        "requested_targets",
        "processed_targets",
        "detected_count",
        "operational_failure_count",
        "conclusive_negative_count",
        "status",
        "reason",
    ],
)
def test_wrong_counts_or_reason_are_not_a_passing_performance_sample(tmp_path, field):
    row = summary()
    row[field] = row[field] + 1 if isinstance(row[field], int) else "wrong"
    path = tmp_path / "out.json"
    path.write_text(json.dumps(row) + "\n")
    assert public_summary_errors(path, ROLES)


@pytest.mark.parametrize(
    "content",
    [
        "",
        '{"type":"summary",broken}\n',
        json.dumps(summary()) + "\n" + '{"host":"late"}\n',
        json.dumps(summary()) + "\n" + json.dumps(summary()) + "\n",
    ],
)
def test_missing_malformed_duplicate_or_nonterminal_summary_fails(tmp_path, content):
    path = tmp_path / "out.json"
    path.write_text(content)
    assert public_summary_errors(path, ROLES)


def test_positive_roots_are_not_conclusive_negatives_perf10_regression(tmp_path):
    row = summary()
    row["conclusive_negative_count"] = 2
    path = tmp_path / "out.json"
    path.write_text(json.dumps(row) + "\n")
    assert public_summary_errors(path, ROLES) == ["public summary counts differ from known target partitions"]


def test_expected_absence_of_footer_for_clean_runs_and_inconclusive_closed(tmp_path):
    path = tmp_path / "out.json"
    path.write_text('{"host":"valid"}\n')
    assert public_summary_errors(path, {0: "positive"}) == []
    row = summary()
    row.update(
        status="inconclusive",
        reason="operational_failures_before_detection",
        requested_targets=1,
        processed_targets=1,
        record_count=1,
        detected_count=0,
        conclusive_negative_count=0,
    )
    path.write_text(json.dumps(row) + "\n")
    assert public_summary_errors(path, {0: "closed"}) == []


def test_boolean_count_and_oversized_footer_fail(tmp_path):
    path = tmp_path / "out.json"
    row = summary()
    row["detected_count"] = True
    path.write_text(json.dumps(row) + "\n")
    assert public_summary_errors(path, ROLES)
    row = summary()
    row["extra"] = "x" * 65536
    path.write_text(json.dumps(row) + "\n")
    assert public_summary_errors(path, ROLES)
