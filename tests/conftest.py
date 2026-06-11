from __future__ import annotations

import json
import os
from collections.abc import Callable, Iterable
from pathlib import Path

import pytest


@pytest.fixture
def write_json_payload(tmp_path: Path) -> Callable[[str, object], Path]:
    def _write(name: str, payload: object) -> Path:
        path = tmp_path / name
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        return path

    return _write


@pytest.fixture
def write_jsonl_payload(tmp_path: Path) -> Callable[[str, Iterable[object]], Path]:
    def _write(name: str, payloads: Iterable[object]) -> Path:
        path = tmp_path / name
        lines = [json.dumps(item, ensure_ascii=False) for item in payloads]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    return _write


@pytest.fixture
def lab_full_compose_path() -> Path:
    lab_dir = Path(os.environ.get("REDPOSTURE_LAB_DIR", "lab"))
    compose_path = lab_dir / "full" / "docker-compose.yml"
    if not compose_path.exists():
        pytest.skip(f"local lab compose not found: {compose_path}; set REDPOSTURE_LAB_DIR")
    return compose_path
