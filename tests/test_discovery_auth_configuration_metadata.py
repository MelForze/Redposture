"""Real identity-provider policy fields are metadata, not stored credentials."""

import pytest

from scripts.discovery_accuracy import scan


@pytest.mark.parametrize("route", ["common", "disk-json", "stream-json", "elastic"])
def test_auth_configuration_is_not_plaintext_credentials(route):
    body = {
        "ssoSessionIdleTimeout": 1800,
        "ssoSessionMaxLifespanRememberMe": 36000,
        "clientSessionIdleTimeout": 0,
        "offlineSessionIdleTimeout": 2592000,
        "requiredCredentials": ["password"],
        "resetCredentialsFlow": "reset credentials",
    }
    rows, status = scan(route, body, portion=7)
    assert status == "complete" and rows == []


@pytest.mark.parametrize("route", ["common", "disk-json", "stream-json", "elastic"])
def test_numeric_passwords_and_real_session_values_are_preserved(route):
    rows, status = scan(
        route, {"password": "1800", "credential": "reset credentials", "session_id": "actual-session!42"}, portion=7
    )
    assert status == "complete"
    assert {r["value"] for r in rows} == {"1800", "reset credentials", "actual-session!42"}
