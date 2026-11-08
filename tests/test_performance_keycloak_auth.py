"""Observed Keycloak bearer identity and independent administrator ACLs."""

from __future__ import annotations

import json

import pytest

from scripts.performance_contracts import credential_verdict_errors, wire_token_record
from scripts.performance_http_fixtures import token_reply


def request(path, token=None, *, limited=False, method="GET"):
    headers = {b"authorization": b"Bearer " + token.encode()} if token else {}
    wire = token_reply(
        method, path, headers, b"", module="keycloak", valid_token="correct", limited=limited, origin="http://qa.local"
    )
    head, _, body = wire.partition(b"\r\n\r\n")
    return int(head.split()[1]), json.loads(body)


@pytest.mark.parametrize("token", [None, "wrong"])
def test_keycloak_invalid_token_is_denied_on_each_verifier(token):
    for path in ["/admin/serverinfo", "/admin/realms", "/realms/master/protocol/openid-connect/userinfo"]:
        assert request(path, token)[0] == 401


@pytest.mark.parametrize("limited", [False, True])
def test_limited_bearer_retains_subject_without_admin_access(limited):
    assert request("/realms/master/protocol/openid-connect/userinfo", "correct", limited=limited) == (
        200,
        {"sub": "profile-subject", "preferred_username": "profile-reader"},
    )
    for path in ["/admin/serverinfo", "/admin/realms"]:
        assert request(path, "correct", limited=limited)[0] == (403 if limited else 200)


def test_public_discovery_is_consistent_and_unknown_or_writing_routes_are_not_successes():
    assert request("/realms/master")[1]["realm"] == "master"
    discovery = request("/realms/master/.well-known/openid-configuration")[1]
    assert discovery["issuer"] == "http://qa.local/realms/master"
    assert discovery["jwks_uri"] == discovery["issuer"] + "/protocol/openid-connect/certs"
    assert request("/realms/master/protocol/openid-connect/certs")[1] == {"keys": []}
    assert request("/unknown", "correct")[0] == 404
    assert request("/admin/realms", "correct", method="POST")[0] == 403


@pytest.mark.parametrize("verified", [False, True])
def test_received_token_adapter_preserves_explicit_product_verdict(verified):
    record = {
        "status": "valid_credentials" if verified else "auth_required",
        "credential_state": "valid" if verified else "invalid",
        "provided_credentials_ok": verified,
        "token_access": "allowed" if verified else "denied",
    }
    observed = wire_token_record(record, received_token="received", source="provided", module="keycloak")
    assert observed is not record and "attempted_credentials" not in record
    expected = {(None, None, "received")} if verified else set()
    assert not credential_verdict_errors(observed, accepted_identities=expected)
    assert observed["attempted_credentials"][0]["token"] == "received"


@pytest.mark.parametrize(
    "changes",
    [
        {"credential_state": "unknown"},
        {"credential_state": "valid"},
        {"provided_credentials_ok": None},
        {"token_access": "unknown"},
        {"status": "open_no_auth"},
    ],
)
def test_unavailable_or_conflicting_product_proof_stays_unobserved(changes):
    record = {
        "status": "auth_required",
        "credential_state": "invalid",
        "provided_credentials_ok": False,
        "token_access": "denied",
        **changes,
    }
    observed = wire_token_record(record, received_token="received", source="provided", module="keycloak")
    assert observed is record and credential_verdict_errors(observed, accepted_identities=set())


def test_token_not_received_from_the_verifier_cannot_be_guessed_from_arguments():
    record = {
        "status": "auth_required",
        "credential_state": "invalid",
        "provided_credentials_ok": False,
        "token_access": "denied",
    }
    assert wire_token_record(record, received_token=None, source="provided", module="keycloak") is record


@pytest.mark.parametrize("peer", ["async", "threaded"])
def test_keycloak_wire_receipt_is_consumed_and_conflicting_headers_cannot_supply_identity(peer):
    import http.client
    import ipaddress
    import threading

    from scripts import profile_module_performance as profile

    before = threading.active_count()
    index = int(ipaddress.IPv4Address("127.0.0.1")) - profile.BASE_IP
    fixture = profile.Fixture(
        "keycloak",
        {index: "positive"},
        0,
        False,
        mode="credentials",
        auth_case="valid",
        bind_host="127.0.0.1",
        http_peer=peer,
    )
    try:
        for token in ["profile-valid-token", "another", "conflicting"]:
            client = http.client.HTTPConnection("127.0.0.1", fixture.port, timeout=1)
            try:
                client.request(
                    "GET",
                    "/realms/master/protocol/openid-connect/userinfo",
                    headers={"Authorization": "Bearer " + token},
                )
                response = client.getresponse()
                assert response.status == (200 if token == "profile-valid-token" else 401)
                response.read()
            finally:
                client.close()
            if token == "profile-valid-token":
                assert fixture.pop_token_identity(index) == token
                assert fixture.pop_token_identity(index) is None
        assert fixture.pop_token_identity(index) is None
        assert fixture.stats["http_requests"] == 3
    finally:
        fixture.close()
    assert not fixture.errors and threading.active_count() == before


@pytest.mark.parametrize(
    "module,token,prepared,expected",
    [
        ("keycloak", "<redacted>", "actual", "actual"),
        ("keycloak", "<redacted>", None, "<redacted>"),
        ("keycloak", "<redacted>", "", "<redacted>"),
        ("keycloak", "unchanged", "actual", "unchanged"),
        ("other", "<redacted>", "actual", "<redacted>"),
    ],
)
def test_expected_catalogue_uses_only_the_modules_own_prepared_secret(module, token, prepared, expected):
    from types import SimpleNamespace

    from scripts.profile_module_performance import expected_credential_identities

    plan = SimpleNamespace(credential_runs=(SimpleNamespace(username=None, password=None, token=token),))
    options = SimpleNamespace(_keycloak_token=prepared, token="cli-value-must-not-be-guessed")
    assert expected_credential_identities(module, options, plan) == [(None, None, expected)]
    assert plan.credential_runs[0].token == token


def test_redaction_adapter_cannot_collapse_or_rewrite_a_multi_credential_catalogue():
    from types import SimpleNamespace

    from scripts.profile_module_performance import expected_credential_identities

    row = SimpleNamespace(username=None, password=None, token="<redacted>")
    plan = SimpleNamespace(credential_runs=(row, row))
    assert expected_credential_identities("keycloak", SimpleNamespace(_keycloak_token="actual"), plan) == [
        (None, None, "<redacted>"),
        (None, None, "<redacted>"),
    ]
