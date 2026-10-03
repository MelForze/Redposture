"""The focused QA gate must not silently omit a requested production file."""

from __future__ import annotations

import json
from pathlib import Path

from scripts.check_quality_coverage import TARGETS, check_report, main


def _report(coverage: dict[str, float]) -> dict[str, object]:
    return {"files": {name: {"summary": {"percent_covered": percent}} for name, percent in coverage.items()}}


def test_target_gate_rejects_missing_files_and_uncovered_targets() -> None:
    complete = {name: 85.0 for name in TARGETS}
    assert check_report(_report(complete)) == []
    assert check_report(_report({name: value for name, value in complete.items() if name != TARGETS[0]})) == [
        f"{TARGETS[0]}: absent from coverage report"
    ]
    complete[TARGETS[-1]] = 84.999
    assert check_report(_report(complete)) == [f"{TARGETS[-1]}: 84.999% < 85%"]


def test_target_gate_cli_reports_failure(tmp_path: Path, capsys) -> None:
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps(_report({name: 85 for name in TARGETS[:-1]})), encoding="utf-8")
    assert main([str(path)]) == 1
    assert TARGETS[-1] in capsys.readouterr().err
