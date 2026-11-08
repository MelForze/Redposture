"""Actual native error envelopes and mixed successful/default ledgers."""

from __future__ import annotations

import pytest

from scripts.performance_contracts import credential_summary, credential_verdict_errors


def record(error, *, status="auth_required", username="profile-user", accepted=False, protocol="native"):
    bad = {"username": username, "password": "wrong", "ok": False, "error": error}
    rows = [bad]
    if accepted:
        rows.append({"username": "admin", "password": "admin", "ok": True, "error": None})
    return {
        "service": "clickhouse",
        "is_clickhouse": True,
        "status": status,
        "protocol": protocol,
        "provided_credentials": status != "weak_default_creds",
        "provided_credentials_ok": accepted if status != "weak_default_creds" else None,
        "credential_attempts": rows,
    }


@pytest.mark.parametrize("status", ["auth_required", "valid_credentials", "weak_default_creds"])
@pytest.mark.parametrize("newline", ["\n", "\\n"])
@pytest.mark.parametrize("username", ["profile-user", "qa.reader+1"])
@pytest.mark.parametrize("protocol", ["native", "http"])
def test_real_native_516_is_classified_in_rejected_and_mixed_ledgers(status, newline, username, protocol):
    error = f"Code: 516.{newline}DB::Exception: {username}: Authentication failed: password is incorrect, or there is no user with such name.. Stack trace:"
    if protocol == "http":
        error = "Received ClickHouse exception, code: 516, server response: " + error
    accepted = status != "auth_required"
    result = record(error, status=status, username=username, accepted=accepted, protocol=protocol)
    summary = credential_summary(result)
    assert summary["invalid"] == 1 and summary["unverified"] == 0
    assert summary["attempts_observed"] == (2 if accepted else 1)
    assert (
        credential_verdict_errors(result, accepted_identities={("admin", "admin", None)} if accepted else set()) == []
    )
    assert "credential_state" not in result["credential_attempts"][0]


@pytest.mark.parametrize(
    "error",
    [
        "Code: 516.\nDB::Exception: another-user: Authentication failed: password is incorrect",
        "Code: 497.\nDB::Exception: profile-user: Authentication failed: permissions denied",
        "Code: 516.\nDB::Exception: profile-user: network unavailable",
        "proxy: Code: 516.\nDB::Exception: profile-user: Authentication failed: password is incorrect",
        "unexpected EOF",
    ],
)
def test_real_envelope_does_not_convert_other_identity_transport_or_acl_into_rejection(error):
    result = record(error)
    assert credential_summary(result)["unverified"] == 1
    assert credential_verdict_errors(result, accepted_identities=set())


@pytest.mark.parametrize("protocol", [None, "native", "auto"])
def test_http_envelope_needs_matching_record_transport(protocol):
    error = "Received ClickHouse exception, code: 516, server response: Code: 516. DB::Exception: profile-user: Authentication failed: password is incorrect"
    result = record(error, protocol=protocol)
    assert credential_summary(result)["unverified"] == 1


@pytest.mark.parametrize(
    "inner",
    [
        "Code: 497. DB::Exception: profile-user: Authentication failed:",
        "Code: 516. DB::Exception: another-user: Authentication failed:",
        "proxy: Code: 516. DB::Exception: profile-user: Authentication failed:",
    ],
)
def test_http_envelope_cannot_replace_inner_code_identity_or_server_prefix(inner):
    result = record("Received ClickHouse exception, code: 516, server response: " + inner, protocol="http")
    assert credential_summary(result)["unverified"] == 1
