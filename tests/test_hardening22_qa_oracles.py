"""Positive and negative controls for the new opt-in QA runners."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from scripts.qa_owned_lab import OwnedLab
from scripts.run_fix22_mutations import CASES, verdict


@pytest.mark.parametrize(
    ("code", "node", "expected"),
    [
        (0, "<testcase/>", "PASS"),
        (1, '<testcase><failure message="assertion"/></testcase>', "KILLED"),
        (2, '<testcase><failure message="collection"/></testcase>', "ERROR"),
        (1, '<testcase><error message="import"/></testcase>', "ERROR"),
        (0, "<testcase><skipped/></testcase>", "ERROR"),
        (5, "", "ERROR"),
        (1, "<testcase/>", "ERROR"),
    ],
)
def test_mutation_verdict_never_counts_infrastructure_failures_as_kills(
    tmp_path: Path, code: int, node: str, expected: str
) -> None:
    report = tmp_path / "report.xml"
    report.write_text("<testsuites><testsuite>" + node + "</testsuite></testsuites>")
    assert verdict(code, report) == expected


def test_mutation_catalog_covers_every_fix_once() -> None:
    assert [row[0] for row in CASES] == list(range(1, 23))
    assert all(row[4].startswith("test_") and "::test_" in row[4] for row in CASES)


def test_owned_lab_command_timeout_reaps_its_process_group(tmp_path: Path) -> None:
    # No Docker is needed to verify command execution and timeout ownership.
    lab = OwnedLab.__new__(OwnedLab)
    lab.out = tmp_path
    lab.commands = []
    assert lab.run(sys.executable, "-c", "print('bounded')", timeout=2).strip() == "bounded"
    with pytest.raises(subprocess.TimeoutExpired):
        lab.run(sys.executable, "-c", "import time;time.sleep(30)", timeout=0.1)


@pytest.mark.parametrize("section", ["Clusters", "Brokers"])
def test_kafka_partial_inventory_lines_follow_airflow_palette_and_plain_text_contract(
    capsys: pytest.CaptureFixture[str], section: str
) -> None:
    from typing import TextIO

    from redposture_core.console import Console
    from redposture_core.modules.kafka import render

    class ColorConsole(Console):
        def _use_color(self, stream: TextIO) -> bool:
            return not self._no_color

    record = {"host": "127.0.0.1", "port": 8080, "is_kafka_ui": True, f"ui_{section.lower()}_partial": True}
    lines = render._format_ui_detail_records(record, "txt")
    line = next(line for line in lines if section + " coverage:partial" in line)
    assert "\x1b" not in line
    assert render._render_colored_kafka_line(ColorConsole(), line)
    color = capsys.readouterr().out
    assert "\x1b[1;97m" in color and "\x1b[1;38;5;208mcoverage:partial" in color
    assert render._render_colored_kafka_line(ColorConsole(no_color=True), line)
    assert "\x1b" not in capsys.readouterr().out
