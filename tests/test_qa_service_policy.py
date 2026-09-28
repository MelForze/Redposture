from __future__ import annotations

import pytest

from scripts.check_compose_readiness import fatal_readiness_issues
from scripts.qa_service_policy import startup_timeout


@pytest.mark.parametrize(
    "fixture,minimum",
    [
        ("gitlab", 2400),
        ("gitlab-real", 2400),
        ("registry-gitlab", 2400),
        ("oracle", 1800),
        ("oracle-licensed", 3600),
        ("registry-harbor", 1800),
        ("registry-harbor-real", 1800),
    ],
)
def test_real_heavy_product_has_its_own_startup_budget(
    fixture: str, minimum: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("REDPOSTURE_QA_STARTUP_TIMEOUT", raising=False)
    assert startup_timeout(fixture) >= minimum


def test_explicit_startup_budget_precedes_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDPOSTURE_QA_STARTUP_TIMEOUT", "4000")
    assert startup_timeout("gitlab", 2401) == 2401
    assert startup_timeout("gitlab") == 4000


@pytest.mark.parametrize("value", [0, -1])
def test_invalid_startup_budget_fails_instead_of_waiting_forever(value: int) -> None:
    with pytest.raises(ValueError, match="positive"):
        startup_timeout("oracle", value)


@pytest.mark.parametrize(
    "state,restarts",
    [
        ({"Status": "running", "OOMKilled": True}, 0),
        ({"Status": "dead"}, 0),
        ({"Status": "restarting"}, 3),
        ({"Status": "exited", "ExitCode": 1}, 3),
    ],
)
def test_fatal_product_startup_does_not_consume_long_budget(state, restarts) -> None:
    assert fatal_readiness_issues([{"Name": "/gitlab", "State": state, "RestartCount": restarts}])


def test_failed_seed_is_fatal_but_successful_seed_and_transient_health_are_not() -> None:
    failed = {"Name": "/vendor-seed", "State": {"Status": "exited", "ExitCode": 1}}
    assert fatal_readiness_issues([failed], allowed_completed=frozenset({"vendor-seed"}))
    failed["State"]["ExitCode"] = 0
    assert fatal_readiness_issues([failed], allowed_completed=frozenset({"vendor-seed"})) == []
    assert (
        fatal_readiness_issues([{"Name": "/gitlab", "State": {"Status": "running", "Health": {"Status": "starting"}}}])
        == []
    )
