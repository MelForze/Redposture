from __future__ import annotations

from pathlib import Path
from typing import Any

from redposture_core.validate.artifacts import markdown_cell, write_vulnerable_targets_files


class _Validator:
    def vulnerable_targets_from_shown_hits(self) -> tuple[list[str], list[str]]:
        return ["10.0.0.1", "apikey-only.local"], [
            "http://10.0.0.1:9100/debug/vars",
            "http://apikey-only.local:9100/debug/vars",
        ]

    def vulnerable_login_rows_from_shown_hits(self) -> list[tuple[str, str, str]]:
        return [("10.0.0.1", "alice", "A1icePass!")]

    def vulnerable_credentials_from_shown_hits(self) -> tuple[list[str], list[str], list[str]]:
        return ["alice"], ["A1icePass!"], ["apikey-only.local:9100:ApiKeyValue"]

    def vulnerable_findings_from_shown_hits(self) -> list[dict[str, Any]]:
        return [
            {
                "host": "10.0.0.1",
                "port": "9100",
                "endpoint": "/debug/vars",
                "exporter": "node_exporter",
                "users": ["alice"],
                "passwords": ["A1icePass!"],
                "api_keys": [],
                "reason": "password field",
            },
            {
                "host": "apikey-only.local",
                "port": "9100",
                "endpoint": "/debug/vars",
                "exporter": "node_exporter",
                "users": [],
                "passwords": [],
                "api_keys": ["apikey-only.local:9100:ApiKeyValue"],
                "reason": "api key field",
            },
        ]


def _read_lines(path: Path) -> list[str]:
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_markdown_cell_escapes_tables_and_joins_lists() -> None:
    assert markdown_cell("a|b\nc") == "a\\|b<br>c"
    assert markdown_cell(["one", "two|three", ""]) == "one<br>two\\|three"
    assert markdown_cell("") == "-"


def test_write_vulnerable_targets_files_preserves_login_row_alignment(tmp_path: Path) -> None:
    debug_events: list[str] = []

    summary = write_vulnerable_targets_files(
        base_dir=str(tmp_path),
        validator=_Validator(),
        debug=debug_events.append,
    )

    assert _read_lines(tmp_path / "vulnerable_ips.txt") == ["10.0.0.1"]
    assert _read_lines(tmp_path / "vulnerable_users.txt") == ["alice"]
    assert _read_lines(tmp_path / "vulnerable_pass.txt") == ["A1icePass!"]
    assert _read_lines(tmp_path / "vulnerable_user_pass.txt") == ["alice:A1icePass!"]
    assert _read_lines(tmp_path / "vulnerable_apikeys.txt") == ["apikey-only.local:9100:ApiKeyValue"]
    assert _read_lines(tmp_path / "vulnerable_urls.txt") == [
        "http://10.0.0.1:9100/debug/vars",
        "http://apikey-only.local:9100/debug/vars",
    ]
    markdown = (tmp_path / "vulnerable_findings.md").read_text(encoding="utf-8")
    assert "# RedPosture Vulnerable Findings" in markdown
    assert "A1icePass!" in markdown
    assert "apikey-only.local:9100:ApiKeyValue" in markdown
    assert summary["login_rows"] == 1
    assert summary["api_keys"] == 1
    assert debug_events and "vulnerable targets written" in debug_events[0]
