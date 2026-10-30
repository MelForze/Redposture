from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.wait_nomad_ready import ready_client, wait_ready


def test_ready_requires_raw_exec_and_scheduling_capacity() -> None:
    good = {"Status": "ready", "SchedulingEligibility": "eligible", "Drivers": {"raw_exec": {"Healthy": True}}}
    assert ready_client([good])
    for patch_value in (
        {"Status": "down"},
        {"SchedulingEligibility": "ineligible"},
        {"Drivers": {}},
        {"Drivers": {"raw_exec": {"Healthy": False}}},
    ):
        assert not ready_client([{**good, **patch_value}])
    assert not ready_client({"error": "not nodes"})
    assert not ready_client([])


def test_external_readiness_is_bounded_without_docker_exec() -> None:
    with patch("scripts.wait_nomad_ready.urllib.request.urlopen", side_effect=OSError("startup")):
        with pytest.raises(TimeoutError, match="startup"):
            wait_ready("http://127.0.0.1:1", 0.01)


def test_execution_override_uses_private_cgroups_and_no_exec_healthcheck() -> None:
    root = Path(__file__).resolve().parents[1] / "tests/fixtures/token_apis"
    service = (root / "nomad-execute-root.yml").read_text()
    assert "cgroup: private" in service and "init: false" in service
    assert "disable: true" in service
    assert "entrypoint: [/bin/sh, /etc/nomad/execute-entrypoint.sh]" in service
    text = (root / "nomad-execute-entrypoint.sh").read_text()
    assert text.index("echo $$ >") < text.index("exec /bin/nomad")
