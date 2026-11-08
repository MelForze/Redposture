"""Portainer profile proves login and current-user identity, separately from Docker ACL."""

from __future__ import annotations

import json
from contextlib import nullcontext
from copy import deepcopy
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from redposture_core import web_panels
from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.portainer import actions
from scripts.performance_contracts import HttpRouteStats, wire_http_pair_record
from scripts.performance_portainer import (
    ENVIRONMENTS,
    PortainerWireLedger,
    issued_token,
    portainer_inventory_errors,
    portainer_reply,
)

PAIR = ("qa-reader", " full:password ")


def reply(method, path, *, body=b"", token=None, limited=False):
    headers = {b"authorization": ("Bearer " + token).encode()} if token else {}
    raw = portainer_reply(method, path, headers, body, valid_pair=PAIR, limited=limited)
    head, data = raw.split(b"\r\n\r\n", 1)
    return int(head.split(b" ", 2)[1]), data, raw


@pytest.mark.parametrize("pair", [None, (PAIR[0], "wrong"), ("other", PAIR[1])])
def test_missing_and_wrong_pairs_cannot_get_a_session(pair):
    body = json.dumps({"Username": pair[0], "Password": pair[1]}).encode() if pair else b"{}"
    assert reply("POST", "/api/auth", body=body)[0] == (401 if pair else 400)
    assert reply("GET", "/api/users/me")[0] == 401
    assert reply("GET", "/api/endpoints")[0] == 401


@pytest.mark.parametrize("limited", [False, True])
def test_identity_does_not_imply_every_docker_resource_is_readable(limited):
    token = issued_token(PAIR[0], limited)
    status, body, _ = reply("GET", "/api/users/me", token=token, limited=limited)
    assert status == 200 and json.loads(body)["Role"] == (2 if limited else 1)
    endpoints = json.loads(reply("GET", "/api/endpoints?start=0&limit=100", token=token, limited=limited)[1])
    assert [r["Id"] for r in endpoints] == ([22] if limited else [11, 22, 33])
    assert reply("GET", "/api/endpoints/22/docker/containers/json?all=1", token=token, limited=limited)[0] == 200
    assert reply("GET", "/api/endpoints/22/docker/images/json", token=token, limited=limited)[0] == (
        403 if limited else 200
    )
    assert json.loads(reply("GET", "/api/endpoints?start=1&limit=1", token=token, limited=limited)[1]) == (
        [] if limited else [ENVIRONMENTS[1]]
    )


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE"])
def test_no_mutation_or_execution_can_succeed(method):
    assert reply(method, "/api/endpoints/11/docker/containers/abc/exec", token=issued_token(PAIR[0], False))[0] == 405
    assert reply(method, "/api/stacks", token=issued_token(PAIR[0], False))[0] == 405


def test_token_signature_unknown_routes_and_login_shapes_stay_strict():
    token = issued_token(PAIR[0], False)
    assert reply("GET", "/api/users/me", token=token + "wrong")[0] == 401
    assert reply("GET", "/api/not-real", token=token)[0] == 404
    assert reply("GET", "/not-portainer", token=token)[0] == 404
    for body in [b"null", b"[]", b"broken", b'{"Username":"u","Password":false}']:
        assert reply("POST", "/api/auth", body=body)[0] == 400


@pytest.fixture
def actual_auth(monkeypatch):
    def run(*, limited=False, pair=PAIR):
        ledger = PortainerWireLedger()

        class Pool:
            def request_once(self, method, url, **options):
                return self.request(method, url, **options)

            def request(self, method, url, **options):
                parsed = urlsplit(url)
                path = parsed.path + ("?" + parsed.query if parsed.query else "")
                body = options.get("body") or b""
                fields = {k.lower().encode(): v.encode() for k, v in options.get("headers", {}).items()}
                raw = portainer_reply(method, path, fields, body, valid_pair=PAIR, limited=limited)
                ledger.record_response(0, method, path, fields, body, raw)
                head, data = raw.split(b"\r\n\r\n", 1)
                return HttpResponse(int(head.split(b" ", 2)[1]), data, {})

        monkeypatch.setattr(web_panels, "_panel_http_scope", lambda ctx: nullcontext(Pool()))
        ctx = SimpleNamespace(
            args=SimpleNamespace(timeout=1, retries=0),
            host="qa.invalid",
            port=9000,
            lifecycle_state=actions.PortainerLifecycleState(),
            credential=SimpleNamespace(username=pair[0], password=pair[1], token=None),
        )
        record = {
            "is_portainer": True,
            "ui_product": "portainer",
            "credential_verification_status": "available",
            "status": "auth_required",
            "ui": {"endpoint": "http://qa.invalid:9000"},
        }
        result = actions.auth_record(ctx, record)
        return result, ledger.pop(0), ctx.lifecycle_state

    return run


@pytest.mark.parametrize("limited", [False, True])
def test_real_product_auth_correlates_full_pair_issued_token_and_identity(actual_auth, limited):
    record, wire, state = actual_auth(limited=limited)
    before = deepcopy(record)
    observed, error = wire_http_pair_record(record, wire, module="portainer")
    assert error is None and record == before and record["provided_credentials_ok"] is True
    assert observed["attempted_credentials"][0]["password"] == PAIR[1]
    login, identity = wire["calls"]
    assert login["password"] == PAIR[1] and identity["authorization"] == "Bearer " + login["response_jwt"]
    assert identity["response_identity"]["Role"] == (2 if limited else 1)
    assert state.sessions[(PAIR[0], PAIR[1], None)]["session_token"] == login["response_jwt"]
    assert "session_token" not in record["ui"]


def test_actual_wrong_password_has_one_rejection_and_no_identity_receipt(actual_auth):
    record, wire, _ = actual_auth(pair=(PAIR[0], "wrong"))
    assert record["provided_credentials_ok"] is False and record["credential_state"] == "invalid"
    assert len(wire["calls"]) == 1 and wire["calls"][0]["status"] == 401
    assert wire_http_pair_record(record, wire, module="portainer")[1] is None


@pytest.mark.parametrize(
    "fault",
    [
        "missing-login",
        "missing-identity",
        "extra-identity",
        "password",
        "identity-user",
        "identity-id",
        "identity-role",
        "login-status",
        "identity-status",
        "token",
        "both-tokens",
        "method",
        "path",
        "unverified",
        "malformed",
    ],
)
def test_same_count_or_valid_looking_token_cannot_hide_bad_auth_evidence(actual_auth, fault):
    record, wire, _ = actual_auth()
    if fault == "missing-login":
        wire["calls"].pop(0)
    elif fault == "missing-identity":
        wire["calls"].pop()
    elif fault == "extra-identity":
        wire["calls"].append(deepcopy(wire["calls"][1]))
    elif fault == "password":
        wire["calls"][0]["password"] += "wrong"
    elif fault == "identity-user":
        wire["calls"][1]["response_identity"]["Username"] = "other"
    elif fault == "identity-id":
        wire["calls"][1]["response_identity"]["Id"] = True
    elif fault == "identity-role":
        wire["calls"][1]["response_identity"]["Role"] = True
    elif fault == "login-status":
        wire["calls"][0]["status"] = 403
    elif fault == "identity-status":
        wire["calls"][1]["status"] = 403
    elif fault == "token":
        wire["calls"][1]["authorization"] += "bad"
    elif fault == "both-tokens":
        wire["calls"][0]["response_jwt"] += "bad"
        wire["calls"][1]["authorization"] += "bad"
    elif fault == "method":
        wire["calls"][1]["method"] = "POST"
    elif fault == "path":
        wire["calls"][1]["path"] = "/api/users"
    elif fault == "unverified":
        record["credential_state"] = "unverified"
    else:
        wire["calls"][0] = None
    assert wire_http_pair_record(record, wire, module="portainer")[1] is not None


def test_wire_capacity_is_bounded_and_consumption_releases_receipts():
    ledger = PortainerWireLedger(total_limit=1)
    body = json.dumps({"Username": PAIR[0], "Password": PAIR[1]}).encode()
    raw = reply("POST", "/api/auth", body=body)[2]
    ledger.record_response(0, "POST", "/api/auth", {}, body, raw)
    ledger.record_response(1, "POST", "/api/auth", {}, body, raw)
    assert ledger.snapshot()["overflow"] == 1 and not ledger.pop(0)["complete"]
    assert ledger.snapshot()["pending_calls"] == ledger.snapshot()["pending_targets"] == 0
    ledger.close()


def test_probe_stats_group_only_endpoint_while_full_bodies_remain_bounded_and_exact():
    routes, ledger = HttpRouteStats(), PortainerWireLedger(body_limit=10000)
    header = {b"authorization": ("Bearer " + issued_token(PAIR[0], False)).encode()}
    for i in range(100):
        body = json.dumps({"Cmd": ["/bin/sh", "-c", f"echo REDPOSTURE_RCE_{i:024x}"]}).encode()
        path = "/api/endpoints/11/docker/containers/abc/exec"
        raw = reply("POST", path, token=issued_token(PAIR[0], False))[2]
        routes.record("POST", path, header, body, body_group="portainer-exec-endpoint")
        ledger.record_response(i, "POST", path, header, body, raw)
        (actual,) = ledger.pop(i)["calls"]
        assert actual["body"].encode() == body and actual["status"] == 405
    assert len(routes.snapshot()["routes"]) == 1 and routes.snapshot()["complete"]
    assert routes.snapshot()["routes"][0]["requests"] == 100
    assert ledger.pending_body_bytes == 0


@pytest.mark.parametrize("limited", [False, True])
def test_actual_inventory_reader_preserves_selected_environment_and_docker_acl(actual_auth, limited):
    record, _, state = actual_auth(limited=limited)
    ctx = SimpleNamespace(
        args=SimpleNamespace(
            timeout=1,
            retries=0,
            endpoint="22",
            endpoints=True,
            containers=True,
            images=True,
            networks=True,
            volumes=True,
            system=True,
            discover=False,
        ),
        host="qa.invalid",
        port=9000,
        lifecycle_state=state,
        credential=SimpleNamespace(username=PAIR[0], password=PAIR[1], token=None),
    )
    result = actions.data_record(ctx, record)
    categories = ["containers", "images", "networks", "volumes", "system"]
    assert portainer_inventory_errors(result, limited=limited, selected="22", categories=categories) == []
    damaged = deepcopy(result)
    damaged["ui"]["inventory"]["containers"]["records"][0]["Names"] = ["/wrong"]
    assert portainer_inventory_errors(damaged, limited=limited, selected="22", categories=categories)
    assert len(result["ui"]["inventory"]["containers"]["records"]) == (1 if limited else 3)


@pytest.mark.parametrize("bad", [None, {}, {"ui": None}, {"ui": "bad"}, {"ui": {"inventory": []}}])
def test_malformed_inventory_is_a_quality_failure_not_a_crash(bad):
    assert portainer_inventory_errors(bad or {}, limited=False, selected=None, categories=["containers"])


@pytest.mark.parametrize("field", ["path", "kind"])
def test_malformed_receipt_fields_are_rejected_without_crashing_the_gate(actual_auth, field):
    record, wire, _ = actual_auth()
    wire["calls"][0][field] = []
    assert wire_http_pair_record(record, wire, module="portainer")[1] is not None
