from __future__ import annotations

from pathlib import Path

import pytest

from scripts.verify_postrun import (
    _EXPECTED_LABELS,
    _parse_status_file,
    _validate_expected_exits,
    _validate_expected_labels,
)


def _write_status(path: Path, header: str, rows: list[str]) -> None:
    body = "\n".join(rows)
    path.write_text(f"{header}\n{body}\n", encoding="utf-8")


def test_parse_status_file_supports_legacy_header(tmp_path: Path) -> None:
    status = tmp_path / "matrix-status.tsv"
    _write_status(
        status,
        "module\tlabel\texit_code\tjson_path\tlog_path",
        ["elastic\telastic_open\t0\t/tmp/elastic_open.json\t/tmp/elastic_open.log"],
    )

    rows = _parse_status_file(status)

    assert rows == [
        {
            "module": "elastic",
            "label": "elastic_open",
            "expected_exit": "0",
            "exit_code": "0",
            "json_path": "/tmp/elastic_open.json",
            "log_path": "/tmp/elastic_open.log",
        }
    ]


def test_parse_status_file_supports_new_header(tmp_path: Path) -> None:
    status = tmp_path / "matrix-status.tsv"
    _write_status(
        status,
        "module\tlabel\texpected_exit\texit_code\tjson_path\tlog_path",
        ["elastic\telastic_open\t2\t2\t-\t/tmp/elastic_open.log"],
    )

    rows = _parse_status_file(status)

    assert rows == [
        {
            "module": "elastic",
            "label": "elastic_open",
            "expected_exit": "2",
            "exit_code": "2",
            "json_path": "-",
            "log_path": "/tmp/elastic_open.log",
        }
    ]


def test_validate_expected_exits_fails_on_mismatch() -> None:
    rows = [
        {
            "module": "elastic",
            "label": "elastic_open",
            "expected_exit": "2",
            "exit_code": "0",
            "json_path": "-",
            "log_path": "/tmp/elastic_open.log",
        }
    ]
    with pytest.raises(SystemExit, match="exit mismatch"):
        _validate_expected_exits(rows)


def test_validate_expected_labels_fails_when_missing_label() -> None:
    rows = [{"module": "elastic", "label": _EXPECTED_LABELS[0]}]
    with pytest.raises(SystemExit, match="missing expected labels"):
        _validate_expected_labels(rows)


def test_validate_expected_labels_passes_with_full_label_set() -> None:
    rows = [{"module": "elastic", "label": label} for label in _EXPECTED_LABELS]
    _validate_expected_labels(rows)
