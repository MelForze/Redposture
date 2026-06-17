"""Static well-formedness check for golden snapshots (P4-A).

Catches accidental hand-edits or merge-conflict markers in `tests/fixtures/golden/*.json`
without needing to run the full lab matrix. Every golden must parse as a non-empty list
of dicts, each carrying the audit identity contract (`status` as a non-empty string).

Parametrised: each golden file produces its own test ID, so a regression points at the
specific file.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

_GOLDEN_DIR = Path(__file__).parent / "fixtures" / "golden"
_GOLDEN_FILES = sorted(_GOLDEN_DIR.glob("*.json"))


@pytest.mark.parametrize("golden_path", _GOLDEN_FILES, ids=lambda p: p.stem)
def test_golden_is_well_formed(golden_path: Path) -> None:
    text = golden_path.read_text(encoding="utf-8")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        pytest.fail(f"{golden_path.name}: not valid JSON: {exc}")

    assert isinstance(payload, list), f"{golden_path.name}: top-level must be a JSON list"
    assert payload, f"{golden_path.name}: top-level list is empty"

    for index, record in enumerate(payload):
        assert isinstance(record, dict), f"{golden_path.name}[{index}]: record must be an object"
        status = record.get("status")
        assert isinstance(status, str) and status, (
            f"{golden_path.name}[{index}]: missing or empty 'status' (audit contract violated)"
        )


def test_golden_directory_has_files() -> None:
    """Guard against accidentally deleting the entire golden fixtures directory."""
    assert _GOLDEN_FILES, (
        f"no golden snapshots found in {_GOLDEN_DIR}; either P4-A was disabled or the fixtures directory was wiped"
    )
