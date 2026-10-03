"""Version QA must reject obsolete module names before Docker startup."""

from __future__ import annotations

import pytest

from redposture_core.cli_args import build_parser
from scripts.run_service_version_matrix import validate_case_cli
from scripts.verify_valkey_lab import default_compose_project


def test_version_matrix_accepts_current_vendor_commands() -> None:
    parser = build_parser()
    for module in ("nexus", "harbor", "docker-registry"):
        validate_case_cli({"id": module, "module": module, "args": ["-t", "http://127.0.0.1:5000"]}, parser)


@pytest.mark.parametrize(
    ("module", "arguments"),
    [("registry", ["-t", "127.0.0.1"]), ("nexus", ["-t", "127.0.0.1", "--nexus"])],
)
def test_version_matrix_rejects_removed_registry_cli_before_stand(
    module: str, arguments: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(ValueError, match="invalid CLI arguments in version case stale"):
        validate_case_cli({"id": "stale", "module": module, "args": arguments}, build_parser())
    capsys.readouterr()


def test_valkey_verifier_follows_isolated_version_project(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDPOSTURE_QA_PROJECT_PREFIX", "redpostureqa123")
    assert default_compose_project() == "redpostureqa123-versions-valkey"
    monkeypatch.delenv("REDPOSTURE_QA_PROJECT_PREFIX")
    assert default_compose_project() == "redposture-versions-valkey"
