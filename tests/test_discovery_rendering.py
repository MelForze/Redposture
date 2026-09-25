from __future__ import annotations

import pytest

from redposture_core.discovery_rendering import (
    discovery_color_spans,
    format_discovery_finding_line,
    normalize_discovery_type,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("password", "Pass"), ("api_key", "ApiKey"), ("private_key", "Key"), ("custom secret", "CustomSecret")],
)
def test_normalize_discovery_type_is_one_word(raw: str, expected: str) -> None:
    assert normalize_discovery_type(raw) == expected


def test_common_discovery_line_escapes_value_and_place() -> None:
    line = format_discovery_finding_line(
        "AIRFLOW",
        "10.0.0.1",
        8080,
        severity="high",
        finding_type="password",
        value="line one\nline two",
        place="dag/task\tlog",
    )

    assert line == ('AIRFLOW\t10.0.0.1\t8080\t [!] Pass Value="line one\\nline two" Place="dag/task\\tlog"')


def test_common_discovery_colors_complete_finding_orange() -> None:
    payload = 'Pass Value="secret" Place="dag/task"'
    spans = discovery_color_spans("[!]", payload)

    assert spans == [(0, len(payload), "orange")]


@pytest.mark.parametrize(
    "payload",
    [
        "Discovered Secrets (status:complete)",
        "Discovered Credentials",
        "3 Secret Findings",
    ],
)
def test_discovery_summary_is_orange(payload: str) -> None:
    assert discovery_color_spans("[*]", payload) == [(0, len(payload), "orange")]


@pytest.mark.parametrize(
    ("payload", "status_color", "findings_color"),
    [
        ("Discover Secrets (status:complete) (findings:0)", "bright_green", "bright_green"),
        ("Discover Secrets (status:partial) (findings:2)", "orange", "true_red"),
        ("Discover Complete (status:complete) (findings:0)", "bright_green", "bright_green"),
        ("Discover Complete (status:partial) (findings:2)", "orange", "true_red"),
        ("Discover Complete (status:unavailable) (findings:0)", "true_red", "bright_green"),
    ],
)
def test_discovery_section_keeps_title_white_and_colors_status_and_findings(
    payload: str, status_color: str, findings_color: str
) -> None:
    spans = discovery_color_spans("[*]", payload)
    assert payload[spans[0][0] : spans[0][1]].startswith("(status:")
    assert spans[0][2] == status_color
    assert payload[spans[1][0] : spans[1][1]].startswith("(findings:")
    assert spans[1][2] == findings_color


def test_bare_discover_secrets_header_has_no_color_span() -> None:
    assert discovery_color_spans("[*]", "Discover Secrets") == []
