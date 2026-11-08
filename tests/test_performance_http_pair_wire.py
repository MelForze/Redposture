"""Full request identities, bounded receipts and independent client verdicts."""

from __future__ import annotations

import base64
from copy import deepcopy
from urllib.parse import urlencode

import pytest

from scripts.performance_contracts import HttpPairWireLedger, HttpRouteStats, credential_summary, wire_http_pair_record


def form(user="u", password="bad", csrf="nonce"):
    return urlencode({"authenticity_token": csrf, "user[login]": user, "user[password]": password}).encode()


def test_pair_form_receipt_retains_actual_full_values_and_consumes_by_destination():
    ledger = HttpPairWireLedger()
    ledger.record(
        7, "gitlab", "POST", "/users/sign_in", {b"cookie": b"_gitlab_session=before"}, form("alice", "wrong"), 422
    )
    wire = ledger.pop(7)
    assert wire["complete"] and len(wire["calls"]) == 1
    call = wire["calls"][0]
    assert (call["username"], call["password"], call["csrf_token"], call["cookie"]) == (
        "alice",
        "wrong",
        "nonce",
        "_gitlab_session=before",
    )
    assert ledger.pop(7)["calls"] == [] and ledger.snapshot()["pending_calls"] == 0
    row = {"attempted_credentials": [{"username": "alice", "password": "wrong", "status": "invalid_credentials"}]}
    original = deepcopy(row)
    assert wire_http_pair_record(row, wire, module="gitlab") == (row, None) and row == original
    ledger.close()
    with pytest.raises(RuntimeError):
        ledger.pop(7)


def test_basic_auth_failed_needs_its_own_received_identity_and_client_state():
    ledger = HttpPairWireLedger()
    ledger.record(
        0,
        "kubeapi",
        "GET",
        "/api/v1/namespaces?limit=1",
        {b"authorization": b"Basic " + base64.b64encode(b"alice:bad")},
        b"",
        401,
    )
    row = {
        "auth_mode": "basic",
        "credential_verification_status": "available",
        "auth_verification_method": "namespace_list",
        "auth_valid": False,
        "attempted_credentials": [{"username": "alice", "password": "bad", "status": "auth_failed"}],
    }
    original = deepcopy(row)
    observed, error = wire_http_pair_record(row, ledger.pop(0), module="kubeapi")
    assert error is None and credential_summary(observed)["invalid"] == 1 and row == original


def test_single_web_result_uses_its_explicit_pair_and_received_form_without_a_ledger():
    ledger = HttpPairWireLedger()
    ledger.record(0, "gitlab", "POST", "/users/sign_in", {}, form("alice", "bad"), 422)
    row = {
        "service": "gitlab",
        "is_gitlab": True,
        "status": "invalid_credentials",
        "provided_username": "alice",
        "provided_password": "bad",
        "provided_credentials_ok": False,
        "credentials_source": "provided",
    }
    observed, error = wire_http_pair_record(row, ledger.pop(0), module="gitlab")
    assert error is None and credential_summary(observed)["invalid"] == 1 and "attempted_credentials" not in row


def test_single_basic_result_is_attributed_only_to_one_actual_received_pair():
    row = {
        "service": "kubeapi",
        "is_kubeapi": True,
        "status": "auth_failed",
        "auth_valid": False,
        "auth_mode": "basic",
        "auth_verification_method": "namespace_list",
        "credentials_source": "provided",
    }
    calls = [
        {
            "kind": "basic",
            "method": "GET",
            "path": "/api/v1/namespaces?limit=1",
            "username": "actual-user",
            "password": "actual-password",
            "status": 401,
        }
    ]
    observed, error = wire_http_pair_record(row, {"complete": True, "calls": calls}, module="kubeapi")
    assert error is None and observed["attempted_credentials"][0]["username"] == "actual-user"
    assert credential_summary(observed)["invalid"] == 1 and "attempted_credentials" not in row
    assert wire_http_pair_record(
        row, {"complete": True, "calls": calls + [{**calls[0], "password": "another"}]}, module="kubeapi"
    )[1]


@pytest.mark.parametrize("fault", ["missing", "wrong_password", "duplicate", "unavailable", "malformed"])
def test_incomplete_identity_or_receipt_never_turns_into_quality_success(fault):
    row = {"attempted_credentials": [{"username": "u", "password": "bad", "status": "invalid_credentials"}]}
    wire = {
        "complete": True,
        "calls": [
            {
                "username": "u",
                "password": "bad",
                "kind": "form",
                "method": "POST",
                "path": "/users/sign_in",
                "status": 422,
            }
        ],
    }
    if fault == "missing":
        wire["calls"] = []
    elif fault == "wrong_password":
        wire["calls"][0]["password"] = "other"
    elif fault == "duplicate":
        wire["calls"] *= 2
    elif fault == "unavailable":
        wire["complete"] = False
    else:
        wire["calls"] = ["not a receipt"]
    assert wire_http_pair_record(row, wire, module="gitlab")[1]


def test_overflow_cannot_be_hidden_by_consuming_a_later_target():
    ledger = HttpPairWireLedger(per_target_limit=1)
    for _ in range(2):
        ledger.record(0, "gitlab", "POST", "/users/sign_in", {}, form(), 422)
    assert not ledger.pop(0)["complete"] and ledger.snapshot()["overflow"] == 1
    assert not ledger.pop(1)["complete"]


def test_nonce_and_session_cookie_do_not_overflow_claimed_pair_route_grouping():
    stats = HttpRouteStats()
    for host in range(40):
        for i in range(19):
            stats.record(
                "POST",
                "/users/sign_in",
                {b"cookie": f"_gitlab_session=host-{host}".encode()},
                form("root", f"password-{i}", f"nonce-{host}"),
            )
    result = stats.snapshot()
    assert result["complete"] and result["overflow_requests"] == 0
    assert len(result["routes"]) == 19 and sum(r["requests"] for r in result["routes"]) == 760
    assert all(r["auth_mode"] == "form_claimed_identity" for r in result["routes"])


@pytest.mark.parametrize("state,width", [("anon", 24), ("auth", 64)])
def test_gitlab_web_cookie_get_statistics_are_bounded_without_counting_them_as_identity_proof(state, width):
    stats = HttpRouteStats(limit=4)
    for host in range(1000):
        stats.record(
            "GET",
            "/api/v4/user",
            {b"cookie": f"_gitlab_session=profile-{state}-{host:0{width}x}".encode()},
            b"",
            body_group="gitlab-web-session",
        )
    snapshot = stats.snapshot()
    assert snapshot["complete"] and snapshot["overflow_requests"] == 0
    assert len(snapshot["routes"]) == 1 and snapshot["routes"][0]["requests"] == 1000
    assert snapshot["routes"][0]["auth_mode"] == "gitlab_web_claimed_session_" + state


@pytest.mark.parametrize(
    "cookie",
    [
        b"_gitlab_session=unrecognized",
        b"_gitlab_session=profile-auth-nothex",
        b"_gitlab_session=profile-auth-" + b"a" * 63,
        b"_gitlab_session=profile-auth-" + b"a" * 64 + b"; another=1",
    ],
)
def test_gitlab_cookie_grouping_never_normalizes_unknown_or_multi_cookie_material(cookie):
    stats = HttpRouteStats()
    stats.record("GET", "/api/v4/user", {b"cookie": cookie}, b"", body_group="gitlab-web-session")
    row = stats.snapshot()["routes"][0]
    assert row["auth_mode"] == "header"


def test_gitlab_cookie_grouping_is_scoped_and_keeps_other_headers_routes_and_session_states_distinct():
    cookie = b"_gitlab_session=profile-auth-" + b"a" * 64
    stats = HttpRouteStats()
    for token in [b"token-one", b"token-two"]:
        for path in ["/api/v4/user", "/api/v4/projects?page=1"]:
            stats.record(
                "GET", path, {b"cookie": cookie, b"private-token": token}, b"", body_group="gitlab-web-session"
            )
    stats.record("GET", "/api/v4/user", {b"cookie": cookie}, b"")
    stats.record(
        "GET",
        "/api/v4/user",
        {b"cookie": b"_gitlab_session=profile-anon-" + b"b" * 24},
        b"",
        body_group="gitlab-web-session",
    )
    rows = stats.snapshot()["routes"]
    assert len(rows) == 6 and len({row["route_identity_sha256"] for row in rows}) == 6
    assert {row["auth_mode"] for row in rows} == {
        "header",
        "gitlab_web_claimed_session_auth",
        "gitlab_web_claimed_session_anon",
    }


@pytest.mark.parametrize("state", ["unknown", "unverified", "verification_unavailable"])
def test_received_401_does_not_override_an_explicit_unverified_client_state(state):
    row = {
        "auth_mode": "basic",
        "attempted_credentials": [
            {"username": "alice", "password": "bad", "status": "auth_failed", "credential_state": state}
        ],
    }
    wire = {
        "complete": True,
        "calls": [
            {
                "kind": "basic",
                "method": "GET",
                "path": "/api/v1/namespaces?limit=1",
                "username": "alice",
                "password": "bad",
                "status": 401,
            }
        ],
    }
    original = deepcopy(row)
    observed, error = wire_http_pair_record(row, wire, module="kubeapi")
    assert error is None and row == original
    assert observed["attempted_credentials"][0]["credential_state"] == state
    assert credential_summary(observed)["invalid"] == 0


def test_basic_acceptance_without_a_received_identity_review_is_not_proven():
    row = {
        "auth_mode": "basic",
        "attempted_credentials": [{"username": "alice", "password": "right", "status": "auth_valid"}],
    }
    wire = {
        "complete": True,
        "calls": [
            {
                "kind": "basic",
                "method": "GET",
                "path": "/api/v1/namespaces?limit=1",
                "username": "alice",
                "password": "right",
                "status": 200,
            }
        ],
    }
    assert wire_http_pair_record(row, wire, module="kubeapi")[1] == "missing verified Basic identity response"


def test_malformed_cookie_marks_wire_evidence_incomplete_instead_of_raising():
    ledger = HttpPairWireLedger()
    ledger.record(0, "gitlab", "POST", "/users/sign_in", {b"cookie": b"\xff"}, form(), 422)
    assert ledger.snapshot()["malformed"] == 1 and not ledger.pop(0)["complete"]
