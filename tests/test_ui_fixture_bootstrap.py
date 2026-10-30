from __future__ import annotations

from unittest.mock import patch

import pytest

from scripts.bootstrap_ui_lab import onboard_redisinsight, wait_api


def test_onboarding_accepts_only_eula_and_creates_connection_after_settings() -> None:
    with patch(
        "scripts.bootstrap_ui_lab.request",
        side_effect=[{"agreements": {"eula": {}, "analytics": {}}}, {}, [], {"id": "qa-connection"}],
    ) as request:
        assert onboard_redisinsight("http://qa") == "qa-connection"
    assert request.call_args_list[1].args[2] == {"agreements": {"eula": True, "analytics": False}}
    assert request.call_args_list[1].kwargs == {"method": "PATCH"}
    assert request.call_args_list[-1].args[1] == "/api/databases"


def test_onboarding_is_idempotent_and_does_not_replace_existing_connection() -> None:
    with patch(
        "scripts.bootstrap_ui_lab.request",
        side_effect=[{"agreements": {"eula": {}}}, {}, [{"host": "redis", "port": 6379, "db": 0, "id": "existing"}]],
    ) as request:
        assert onboard_redisinsight("http://qa") == "existing"
        assert request.call_count == 3


@pytest.mark.parametrize("value", [{}, {"agreements": []}, {"agreements": {"analytics": {}}}])
def test_changed_agreement_schema_does_not_silently_report_success(value: object) -> None:
    with patch("scripts.bootstrap_ui_lab.request", return_value=value):
        with pytest.raises(RuntimeError, match="schema"):
            onboard_redisinsight("http://qa")


def test_wait_api_does_not_accept_http_503_or_root_page_as_api_readiness() -> None:
    with patch("scripts.bootstrap_ui_lab.request", side_effect=OSError("HTTP 503")):
        with pytest.raises(TimeoutError, match="503"):
            wait_api("http://qa", "/api/status", seconds=0.01)
