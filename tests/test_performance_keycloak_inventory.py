"""Known paged Admin REST bodies and actual read-only data-hook contracts."""

from __future__ import annotations

import copy
import json
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.keycloak import actions
from scripts.performance_http_fixtures import keycloak_token_reply
from scripts.performance_keycloak import client_representation, keycloak_inventory_errors


def reply(path, *, token="correct", limited=False, method="GET"):
    headers = {b"authorization": b"Bearer " + token.encode()} if token else {}
    raw = keycloak_token_reply(method, path, headers, valid_token="correct", limited=limited, origin="http://qa.local")
    head, _, body = raw.partition(b"\r\n\r\n")
    return int(head.split()[1]), body


@pytest.mark.parametrize("realm", ["master", "corp", "partners"])
def test_full_client_pages_reach_tail_without_repeating_or_dropping_names(realm):
    rows = []
    for first, expected in ((0, 100), (100, 100), (200, 1), (300, 0)):
        code, body = reply(f"/admin/realms/{realm}/clients?first={first}&max=100")
        page = json.loads(body)
        assert code == 200 and len(page) == expected
        rows.extend(page)
    assert [row["clientId"] for row in rows] == [f"app-{index:03d}" for index in range(201)]


@pytest.mark.parametrize(
    "query", ["first=-1", "max=0", "max=1001", "first=bad", "first=", "first=0&first=1", "unknown=1"]
)
def test_paging_errors_cannot_turn_into_successful_empty_collections(query):
    assert reply("/admin/realms/master/clients?" + query)[0] == 400


def test_client_role_values_match_fixed_golden_examples():
    actual = [client_representation("corp", index) for index in range(6)]
    assert [row["publicClient"] for row in actual] == [True, False, False, True, False, False]
    assert [row["bearerOnly"] for row in actual] == [False, False, True, False, False, True]
    assert [row["directAccessGrantsEnabled"] for row in actual] == [True, False, False, False, False, True]
    assert all(row["implicitFlowEnabled"] is False for row in actual)


@pytest.mark.parametrize("path", ["/admin/realms/corp", "/admin/realms/corp/clients?first=0&max=100"])
def test_inventory_rights_are_distinct_from_valid_master_userinfo(path):
    assert reply(path, token=None)[0] == 401
    assert reply(path, token="wrong")[0] == 401
    assert reply(path, limited=True)[0] == 403
    assert reply("/realms/master/protocol/openid-connect/userinfo", limited=True)[0] == 200
    assert reply("/realms/corp/protocol/openid-connect/userinfo")[0] == 401
    assert reply(path, method="POST")[0] == 403


def collect(monkeypatch, *, realms, limit=True, limited=False, fault=None, show_realms=True):
    requests = []

    def get(_client, url, token):
        assert token == "correct"
        parsed = urlsplit(url)
        path = parsed.path + ("?" + parsed.query if parsed.query else "")
        requests.append(path)
        code, body = reply(path, limited=limited)
        if "/clients?first=100&" in path:
            if fault == "repeat":
                code, body = reply(path.replace("first=100", "first=0"), limited=limited)
            elif fault == "http":
                code, body = 503, b'{"error":"retry later"}'
            elif fault == "json":
                code, body = 200, b"{"
            elif fault == "timeout":
                return HttpResponse(0, b"", {}, error="timed out")
        return HttpResponse(code, body, {"Content-Type": "application/json"}, final_url=url)

    monkeypatch.setattr(actions, "_client", lambda _ctx: object())
    monkeypatch.setattr(actions, "_get", get)
    args = SimpleNamespace(
        enum_realms=False, show_realms=show_realms, show_clients=limit, realm=realms, _keycloak_token="correct"
    )
    record = actions.data_record(
        SimpleNamespace(args=args, target=SimpleNamespace(path="")),
        {"api_endpoint": "http://qa.local", "provided_credentials_ok": True, "credential_state": "valid"},
    )
    return record, requests


@pytest.mark.parametrize("limit", [True, 1, 100, 101, 201, 205])
def test_actual_data_hook_matches_full_values_scopes_limits_and_terminates(monkeypatch, limit):
    realms = ["master", "corp", "partners"]
    record, requests = collect(monkeypatch, realms=realms, limit=limit)
    assert (
        keycloak_inventory_errors(
            record,
            limited=False,
            realms=realms,
            limit=None if limit is True else limit,
            show_realms=True,
            show_clients=True,
        )
        == []
    )
    assert len(requests) <= 13
    assert "\x1b" not in json.dumps(record)


def test_selected_realm_limits_clients_without_losing_other_visible_realm_settings(monkeypatch):
    record, requests = collect(monkeypatch, realms=["corp"])
    assert len(record["visible_clients"]) == 201
    assert all(name.startswith("corp/") for name in record["visible_clients"])
    assert len(record["realm_settings"]) == 3
    assert len([path for path in requests if "/clients?" in path]) == 3


def test_limited_inventory_is_denied_partial_while_identity_stays_verified(monkeypatch):
    realms = ["master", "corp", "partners"]
    record, requests = collect(monkeypatch, realms=realms, limited=True)
    assert (
        keycloak_inventory_errors(record, limited=True, realms=realms, limit=None, show_realms=True, show_clients=True)
        == []
    )
    assert len(requests) == 4 and record["provided_credentials_ok"] is True


@pytest.mark.parametrize("fault", ["repeat", "http", "json", "timeout"])
def test_mid_page_fault_preserves_completed_clients_and_does_not_revoke_identity(monkeypatch, fault):
    record, requests = collect(monkeypatch, realms=["corp"], fault=fault, show_realms=False)
    assert record["visible_clients"] == [f"corp/app-{index:03d}" for index in range(100)]
    assert record["clients_partial"] is True and record["clients_errors"]["corp"]
    assert record["provided_credentials_ok"] is True and record["credential_state"] == "valid"
    assert len(requests) == 2
    assert keycloak_inventory_errors(
        record, limited=False, realms=["corp"], limit=None, show_realms=False, show_clients=True
    )


@pytest.mark.parametrize(
    "damage", ["missing", "duplicate", "order", "type", "flow", "redirect", "origin", "partial", "realms"]
)
def test_inventory_gate_rejects_correct_counts_with_wrong_values(monkeypatch, damage):
    record, _ = collect(monkeypatch, realms=["corp"], limit=1)
    bad = copy.deepcopy(record)
    if damage == "missing":
        bad["client_settings"] = []
    elif damage == "duplicate":
        bad["visible_clients"] *= 2
    elif damage == "order":
        bad["visible_realms"] = list(reversed(bad["visible_realms"]))
    elif damage == "type":
        bad["client_settings"][0]["type"] = "confidential"
    elif damage == "flow":
        bad["client_settings"][0]["direct_access_grants"] = False
    elif damage == "redirect":
        bad["client_settings"][0]["redirect_uris"] = ["https://wrong.invalid"]
    elif damage == "origin":
        bad["client_settings"][0]["web_origin_count"] = 0
    elif damage == "partial":
        bad["clients_partial"] = True
    else:
        bad["realm_settings"][0]["ssl_required"] = "none"
    assert keycloak_inventory_errors(bad, limited=False, realms=["corp"], limit=1, show_realms=True, show_clients=True)
