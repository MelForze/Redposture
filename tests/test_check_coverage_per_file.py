from __future__ import annotations

import json
import re
from decimal import Decimal
from pathlib import Path

import pytest

from scripts.check_coverage_per_file import (
    CoverageDataError,
    below_minimum,
    load_coverage_json,
    main,
    measured_file_coverage,
)


def _write_report(path: Path, files: dict[str, object]) -> None:
    path.write_text(json.dumps({"files": files}), encoding="utf-8")


def _entry(percent_covered: object) -> dict[str, object]:
    return {
        "summary": {
            "covered_lines": 7,
            "num_statements": 10,
            "percent_covered": percent_covered,
            "percent_covered_display": "70",
        }
    }


def test_measured_file_coverage_filters_non_production_entries_and_normalizes_paths() -> None:
    report = {
        "files": {
            "tests/test_widget.py": _entry(1),
            "README.md": _entry(1),
            "redposture_core\\widget.py": _entry(72.5),
            "./redposture_core/alpha.py": _entry(70),
            "redposture_core/data.json": _entry(1),
        }
    }

    measured = measured_file_coverage(report)

    assert [(item.path, item.percent_covered) for item in measured] == [
        ("redposture_core/alpha.py", Decimal("70")),
        ("redposture_core/widget.py", Decimal("72.5")),
    ]


def test_below_minimum_uses_unrounded_percent_covered() -> None:
    report = {
        "files": {
            "redposture_core/almost.py": _entry(69.9999),
            "redposture_core/exactly.py": _entry(70),
        }
    }

    failures = below_minimum(report, Decimal("70"))

    assert [(item.path, item.percent_covered) for item in failures] == [
        ("redposture_core/almost.py", Decimal("69.9999"))
    ]


def test_main_reports_all_failures_in_deterministic_path_order(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report_path = tmp_path / "coverage.json"
    _write_report(
        report_path,
        {
            "redposture_core/zeta.py": _entry(10),
            "redposture_core/passing.py": _entry(70),
            "redposture_core/alpha.py": _entry(69.5),
            "tests/test_alpha.py": _entry(0),
        },
    )

    exit_code = main([str(report_path), "--min", "70"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err == (
        "per-file coverage failed: 2 of 3 measured redposture_core Python files are below 70%.\n"
        "  redposture_core/alpha.py: 69.5%\n"
        "  redposture_core/zeta.py: 10%\n"
    )


def test_main_passes_with_custom_minimum(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    report_path = tmp_path / "coverage.json"
    _write_report(report_path, {"redposture_core/widget.py": _entry(64.25)})

    exit_code = main(["--min", "64.25", str(report_path)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert captured.out == (
        "per-file coverage passed: all 1 measured redposture_core Python files are at or above 64.25%.\n"
    )


@pytest.mark.parametrize(
    ("report", "message"),
    [
        ([], "coverage report must be a JSON object"),
        ({}, "coverage report field 'files' must be a JSON object"),
        ({"files": []}, "coverage report field 'files' must be a JSON object"),
        (
            {"files": {"redposture_core/widget.py": []}},
            "redposture_core/widget.py: file coverage entry must be a JSON object",
        ),
        (
            {"files": {"redposture_core/widget.py": {}}},
            "redposture_core/widget.py: field 'summary' must be a JSON object",
        ),
        (
            {"files": {"redposture_core/widget.py": {"summary": {}}}},
            "redposture_core/widget.py: summary.percent_covered is missing",
        ),
        (
            {"files": {"redposture_core/widget.py": _entry("70")}},
            "redposture_core/widget.py: summary.percent_covered must be a number",
        ),
        (
            {"files": {"redposture_core/widget.py": _entry(True)}},
            "redposture_core/widget.py: summary.percent_covered must be a number",
        ),
        (
            {"files": {"redposture_core/widget.py": _entry(101)}},
            "redposture_core/widget.py: summary.percent_covered must be between 0 and 100",
        ),
        (
            {"files": {"tests/test_widget.py": _entry(100)}},
            "coverage report contains no measured Python files under redposture_core",
        ),
    ],
)
def test_measured_file_coverage_rejects_malformed_reports(report: object, message: str) -> None:
    with pytest.raises(CoverageDataError, match=f"^{re.escape(message)}$"):
        measured_file_coverage(report)


def test_load_and_main_report_invalid_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    report_path = tmp_path / "coverage.json"
    report_path.write_text('{"files":', encoding="utf-8")

    with pytest.raises(CoverageDataError, match="is not valid JSON"):
        load_coverage_json(report_path)

    exit_code = main([str(report_path)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert captured.err.startswith(f"per-file coverage error: {report_path} is not valid JSON:")
