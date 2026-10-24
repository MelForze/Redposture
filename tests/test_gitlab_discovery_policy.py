"""Discovery budget rejection must happen before GitLab target work."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.modules.gitlab import policy


@pytest.mark.parametrize("seconds,bytes_limit", [(0, 64), (float("nan"), 64), (1, 0), (1, -1)])
def test_invalid_budget_stops_before_basic_target_validation(monkeypatch, seconds, bytes_limit):
    errors = []
    monkeypatch.setattr(
        policy, "validate_basic_module_args", lambda *a, **k: pytest.fail("invalid budget reached targets")
    )
    args = SimpleNamespace(discover=True, discover_time=seconds, discover_max_bytes=bytes_limit)
    assert policy.validate_args(args, SimpleNamespace(error=errors.append)) == 2
    assert len(errors) == 1 and errors[0].startswith("--discover-")


def test_valid_discovery_budget_preserves_target_validation():
    args = parse_args(["gitlab", "-t", "127.0.0.1", "--discover", "--discover-time", "1", "--discover-max-bytes", "64"])
    errors = []
    assert policy.validate_args(args, SimpleNamespace(error=errors.append)) is None
    assert not errors
