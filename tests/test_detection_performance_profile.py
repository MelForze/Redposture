"""The separate performance profile gates correctness even under timing noise."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.profile_detection_performance import compare_runs, expected_ids


def sample(seconds=1.0, **changes):
    return {
        "model": "mixed",
        "targets": 1000,
        "seed": 1,
        "detect_concurrency": 128,
        "deep_workers": 16,
        "timeout": 2,
        "retries": 0,
        "delay_ms": 2,
        "quality": "PASS",
        "wall_seconds": seconds,
        "http_requests": 2050,
        "cpu_seconds": 0.5,
        "peak_rss_bytes": 64000000,
        "first_finding_seconds": 0.1,
        "fd_peak": 300,
        "threads_peak": 24,
        **changes,
        "result_sha256": "expected-set",
    }


def test_seed_produces_fixed_exact_positive_set():
    assert expected_ids(1000, 42) == expected_ids(1000, 42)
    assert len(expected_ids(1000, 42)) == 50
    assert expected_ids(1000, 43) != expected_ids(1000, 42)


@pytest.mark.parametrize("quality", ["FAIL", "BLOCKED"])
def test_fast_but_incorrect_results_fail(quality):
    result = compare_runs([sample()] * 3, [sample(0.1, quality=quality)] * 3)
    assert result["status"] == result["quality"] == "FAIL"


def test_large_repeatable_slowdown_fails():
    assert compare_runs([sample()] * 3, [sample(2)] * 3)["timing_status"] == "REGRESSION"


def test_different_observed_set_fails_even_with_matching_counts():
    before = sample()
    after = {**sample(0.1), "result_sha256": "different-set"}
    assert compare_runs([before] * 3, [after] * 3)["quality"] == "FAIL"


def test_profile_failure_without_first_finding_is_still_reported():
    result = compare_runs([sample()] * 3, [sample(0.1, quality="FAIL", first_finding_seconds=None)] * 3)
    assert result["status"] == "FAIL"
    assert result["metrics"]["first_finding_seconds"]["after"] is None


def test_noisy_or_short_single_measurement_cannot_claim_regression():
    assert compare_runs([sample()], [sample(10)])["timing_status"] == "INSUFFICIENT_REPEATS"
    assert compare_runs([sample(1), sample(3), sample(2)], [sample(2), sample(4), sample(3)])["status"] == "PASS"
    assert compare_runs([sample(0.1)] * 3, [sample(0.2)] * 3)["status"] == "PASS"


def test_different_parameters_cannot_be_compared():
    with pytest.raises(ValueError, match="parameters differ"):
        compare_runs([sample()], [sample(targets=2000)])
    with pytest.raises(ValueError, match="equal nonempty"):
        compare_runs([], [])


@pytest.mark.parametrize("model", ["numeric", "hostname", "interim", "mixed"])
def test_actual_detector_profile_has_exact_results_and_cleans_up(tmp_path, model):
    root = Path(__file__).resolve().parents[1]
    output = tmp_path / "profile.json"
    run = subprocess.run(
        [
            sys.executable,
            str(root / "scripts/profile_detection_performance.py"),
            "--one-run",
            "--model",
            model,
            "--targets",
            "40",
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
        timeout=45,
    )
    assert run.returncode == 0, run.stdout + run.stderr
    row = json.loads(output.read_text())
    assert row["quality"] == row["cleanup"] == "PASS"
    assert row["records"] == 40 and row["missing"] == row["extra"] == [] and row["duplicates"] == 0
    assert row["http_requests"] > 40 and row["first_finding_seconds"] > 0


def test_qa_performance_section_is_explicit_and_sequential(tmp_path):
    root = Path(__file__).resolve().parents[1]
    command = ["bash", str(root / "scripts/run_full_local_qa.sh"), str(tmp_path), "--plan"]
    normal = subprocess.run(command, capture_output=True, text=True, check=True)
    assert "section: detect-performance" not in normal.stdout
    selected = subprocess.run(command + ["--section", "detect-performance"], capture_output=True, text=True, check=True)
    assert selected.stdout.count("section:") == 1 and "section: detect-performance" in selected.stdout
