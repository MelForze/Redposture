"""CVE display ordering and color regressions."""

from __future__ import annotations

import re

import pytest

from redposture_core.console import Console
from redposture_core.cve import render_finding_lines
from redposture_core.rendering import render_colored_marker_line


def _ids(lines: list[str]) -> list[str]:
    out: list[str] = []
    for line in lines:
        m = re.search(r"\b(CVE-\d{4}-\d+)\b", line)
        if m:
            out.append(m.group(1))
    return out


def _render(findings: list[dict]) -> list[str]:
    return render_finding_lines({"cve_enumeration": {"findings": findings}}, label="X", host="h", port=1)


def test_known_findings_sorted_by_severity_then_score() -> None:
    findings = [
        {"id": "CVE-0000-1", "severity": "HIGH", "score": 7.5, "title": "a", "version_assessment": "affected"},
        {"id": "CVE-0000-2", "severity": "CRITICAL", "score": 9.8, "title": "b", "version_assessment": "affected"},
        {"id": "CVE-0000-3", "severity": "HIGH", "score": 8.8, "title": "c", "version_assessment": "affected"},
        {"id": "CVE-0000-4", "severity": "MEDIUM", "score": 5.0, "title": "d", "version_assessment": "affected"},
        {"id": "CVE-0000-5", "severity": "LOW", "score": 3.1, "title": "e", "version_assessment": "affected"},
    ]
    assert _ids(_render(findings)) == ["CVE-0000-2", "CVE-0000-3", "CVE-0000-1", "CVE-0000-4", "CVE-0000-5"]


def test_version_unknown_findings_go_to_the_tail() -> None:
    findings = [
        {"id": "CVE-0000-6", "severity": "CRITICAL", "score": 10.0, "title": "poss", "version_assessment": "unknown"},
        {"id": "CVE-0000-7", "severity": "HIGH", "score": 7.0, "title": "known", "version_assessment": "affected"},
    ]
    # Known HIGH stands before a speculative CRITICAL — version-unknown always trails.
    assert _ids(_render(findings)) == ["CVE-0000-7", "CVE-0000-6"]


def test_possible_group_also_sorted_by_severity() -> None:
    findings = [
        {"id": "CVE-0000-8", "severity": "HIGH", "score": 7.0, "title": "p-high", "version_assessment": "unknown"},
        {"id": "CVE-0000-9", "severity": "CRITICAL", "score": 9.0, "title": "p-crit", "version_assessment": "unknown"},
    ]
    assert _ids(_render(findings)) == ["CVE-0000-9", "CVE-0000-8"]


def test_ordering_preserves_the_finding_set() -> None:
    findings = [
        {"id": "CVE-0000-1", "severity": "LOW", "score": 2.0, "title": "a", "version_assessment": "affected"},
        {"id": "CVE-0000-2", "severity": "CRITICAL", "score": 9.9, "title": "b", "version_assessment": "unknown"},
        {"id": "CVE-0000-3", "severity": "HIGH", "score": 8.0, "title": "c", "version_assessment": "affected"},
    ]
    assert set(_ids(_render(findings))) == {"CVE-0000-1", "CVE-0000-2", "CVE-0000-3"}


def test_sorted_cve_lines_keep_colors_and_no_color_output_is_plain(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    findings = [
        {"id": "CVE-0000-1", "severity": "LOW", "score": 3.0, "title": "known low", "version_assessment": "affected"},
        {
            "id": "CVE-0000-2",
            "severity": "CRITICAL",
            "score": 9.8,
            "title": "possible",
            "version_assessment": "unknown",
        },
        {"id": "CVE-0000-3", "severity": "HIGH", "score": 8.0, "title": "known high", "version_assessment": "affected"},
    ]
    lines = _render(findings)
    assert _ids(lines) == ["CVE-0000-3", "CVE-0000-1", "CVE-0000-2"]
    monkeypatch.setenv("FORCE_COLOR", "1")
    colored = Console(no_color=False)
    assert all(render_colored_marker_line(colored, line, tag="X") for line in lines)
    colored_output = capsys.readouterr().out
    uncolored = re.sub(r"\x1b\[[0-9;]*m", "", colored_output)
    assert _ids(uncolored.splitlines()) == _ids(lines)
    assert "\x1b[1;38;5;196m[!]" in colored_output
    assert "\x1b[1;93m[!]" in colored_output
    console = Console(no_color=True)
    assert all(render_colored_marker_line(console, line, tag="X") for line in lines)
    output = capsys.readouterr().out
    assert "\x1b[" not in output
    assert _ids(output.splitlines()) == _ids(lines)
