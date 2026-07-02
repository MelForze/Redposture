from __future__ import annotations

import json
import os
from collections.abc import Callable, Iterable
from pathlib import Path

import pytest


@pytest.fixture(autouse=True, scope="session")
def _force_color_in_tests() -> Iterable[None]:
    """Color output is now gated on ``isatty()``; pytest captures stdout to a
    non-tty, so force color on for the suite (mirrors a real terminal) and clear
    any inherited ``NO_COLOR`` so the color-assertion tests stay deterministic."""
    prev_force = os.environ.get("FORCE_COLOR")
    prev_no = os.environ.get("NO_COLOR")
    os.environ["FORCE_COLOR"] = "1"
    os.environ.pop("NO_COLOR", None)
    try:
        yield
    finally:
        if prev_force is None:
            os.environ.pop("FORCE_COLOR", None)
        else:
            os.environ["FORCE_COLOR"] = prev_force
        if prev_no is not None:
            os.environ["NO_COLOR"] = prev_no


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


@pytest.fixture
def lab_services_dir() -> Path:
    lab_dir = Path(os.environ.get("REDPOSTURE_LAB_DIR", "lab"))
    services_path = lab_dir / "services"
    if not services_path.exists():
        pytest.skip(f"lab services dir not found: {services_path}; set REDPOSTURE_LAB_DIR")
    return services_path
