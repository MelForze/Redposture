"""QA containers must not reuse names belonging to another fixture stack."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


def _build_override(config: object, project: str) -> dict[str, object]:
    path = Path(__file__).resolve().parents[1] / "scripts" / "qa_compose_override.py"
    spec = importlib.util.spec_from_file_location("qa_compose_override", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.build_override(config, project)


def test_fixed_fixture_names_are_isolated_but_service_dns_stays_the_same() -> None:
    config = {
        "services": {
            "redis": {"container_name": "redposture-lab-redis", "image": "redis:7.4"},
            "api": {"image": "api:latest", "depends_on": ["redis"]},
        }
    }
    assert _build_override(config, "qa-123") == {
        "services": {"redis": {"container_name": "qa-123-redposture-lab-redis"}}
    }
    assert config["services"]["api"]["depends_on"] == ["redis"]


@pytest.mark.parametrize("project", ["", "bad/name", "--bad", "has space"])
def test_invalid_project_name_is_rejected(project: str) -> None:
    with pytest.raises(ValueError, match="project name"):
        _build_override({"services": {}}, project)
