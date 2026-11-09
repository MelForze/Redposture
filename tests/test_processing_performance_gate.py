"""Fast-gate failures cannot be turned into passing timing improvements."""

from copy import deepcopy

import pytest

from scripts.compare_module_performance import sample_order
from scripts.compare_processing_performance import IDENTITY, METRICS, summarize
from scripts.profile_processing_performance import expected_findings


def samples():
    return [
        {
            "repeat": repeat,
            "side": side,
            "exit": 0,
            "result": {
                **dict.fromkeys(IDENTITY, "fixed"),
                **dict.fromkeys(METRICS, 1),
                "case": "json-stream",
                "source_sha256": side,
                "quality": "PASS",
                "source_status": "complete",
                "no_ansi": True,
                "temporary_directory_removed": True,
                "fd_before": 4,
                "fd_after": 4,
                "threads_before": 1,
                "threads_after": 1,
                "findings": expected_findings("json-stream", "runtime/config.json"),
            },
        }
        for repeat, side in sample_order(3)
    ]


def test_matched_repeated_samples_pass_and_report_thresholds():
    result = summarize(samples(), 3)
    assert result["gate"] == "PASS" and result["warmups_excluded"]
    assert set(result["metrics"]) == set(METRICS)


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "duplicate",
        "warmup",
        "value",
        "place",
        "type",
        "ansi",
        "fd",
        "cleanup",
        "source",
        "instrument",
        "exit",
        "metric",
    ],
)
def test_quality_missing_evidence_or_leak_cannot_pass(change):
    rows = samples()
    candidate = rows[-1]["result"]
    if change == "missing":
        rows.pop()
    elif change == "duplicate":
        rows[-1] = deepcopy(rows[-2])
    elif change == "warmup":
        rows[1]["result"]["quality"] = "FAIL"
    elif change in {"value", "place", "type"}:
        candidate["findings"][0][change] = "wrong"
    elif change == "ansi":
        candidate["no_ansi"] = False
    elif change == "fd":
        candidate["fd_after"] = 5
    elif change == "cleanup":
        candidate["temporary_directory_removed"] = False
    elif change == "source":
        candidate["source_sha256"] = "changed"
    elif change == "instrument":
        candidate["profile_sha256"] = "changed"
    elif change == "exit":
        rows[-1]["exit"] = 1
    elif change == "metric":
        candidate.pop("first_finding_seconds")
    assert summarize(rows, 3)["gate"] == "FAIL"


@pytest.mark.parametrize("metric", METRICS)
def test_repeatable_latency_or_resource_regression_fails(metric):
    rows = samples()
    floor, _ = METRICS[metric]
    for row in rows:
        if row["side"] == "after":
            row["result"][metric] = 100 * (1 + floor)
    report = summarize(rows, 3)
    assert report["gate"] == "FAIL" and report["metrics"][metric]["status"] == "REGRESSION"


def test_same_wrong_findings_on_both_sides_cannot_pass():
    rows = samples()
    for row in rows:
        row["result"]["findings"] = []
    assert summarize(rows, 3)["gate"] == "FAIL"
