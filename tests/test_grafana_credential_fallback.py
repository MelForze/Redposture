"""Credential fallback must establish new access and retain the proved session."""

from __future__ import annotations

import json
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.grafana import actions


class GrafanaPeer:
    def __init__(self, mode="org"):
        self.mode = mode
        self.calls = []

    def request(self, method, url, *, headers=None, body=None, **_kwargs):
        path = urlsplit(url).path
        headers = dict(headers or {})
        self.calls.append((method, path, headers, body))
        normalized = {key.lower(): value for key, value in headers.items()}
        basic = normalized.get("authorization") == actions._auth_header("alice", "correct")
        cookie = "qa_session=verified" in normalized.get("cookie", "")
        identity = {"id": 42, "login": "alice", "orgId": 1, "isGrafanaAdmin": False}
        org = {"id": 1, "name": "QA", "address": {}}
        if self.mode == "rate":
            return self.response(429, {"message": "too many login attempts"}, {"Retry-After": "30"})
        if path == "/api/user":
            if self.mode == "any-basic-user" and normalized.get("authorization"):
                return self.response(200, identity)
            if cookie and self.mode != "cookie-only":
                return self.response(200, identity)
            return self.response(401 if self.mode in {"session", "cookie-only"} else 404, {})
        if path == "/api/org":
            if (
                self.mode == "public-org"
                or (self.mode == "any-basic-org" and normalized.get("authorization"))
                or (basic and self.mode == "org")
                or (cookie and self.mode != "cookie-only")
            ):
                return self.response(200, org)
            if self.mode == "cookie-only" and cookie:
                return HttpResponse(200, b"<html>Grafana login</html>", {"Content-Type": "text/html"})
            return self.response(401, {"message": "Unauthorized"})
        if path == "/login" and method == "POST":
            submitted = json.loads(body or b"{}")
            if (
                submitted.get("user") == "alice"
                and submitted.get("password") == "correct"
                and self.mode in {"session", "cookie-only"}
            ):
                return self.response(
                    200, {"message": "Logged in"}, {"Set-Cookie": "qa_session=verified; Path=/; HttpOnly"}
                )
            return self.response(401, {"message": "Invalid username or password"})
        if path == "/api/datasources":
            return (
                self.response(200, [{"id": 1, "name": "QA", "type": "prometheus"}])
                if cookie
                else self.response(403, {})
            )
        return self.response(404, {})

    @staticmethod
    def response(status, data, headers=None):
        return HttpResponse(status, json.dumps(data).encode(), {"Content-Type": "application/json", **(headers or {})})

    def close(self):
        pass


@pytest.fixture
def transport(monkeypatch):
    previous = getattr(actions._THREAD_LOCAL_HTTP, "state", None)
    made = []

    def setup(mode="org"):
        peer = GrafanaPeer(mode)
        state = actions.GrafanaLifecycleState(http=peer, host="qa", port=3000, scheme="http", origin_resolved=True)
        actions._activate_grafana_transport(state)
        made.append(state)
        return peer, state

    yield setup
    for state in made:
        state.close()
    if previous is None:
        monkeypatch.delattr(actions._THREAD_LOCAL_HTTP, "state", raising=False)
    else:
        monkeypatch.setattr(actions._THREAD_LOCAL_HTTP, "state", previous)


def context(state, password="correct"):
    return SimpleNamespace(
        host="qa",
        port=3000,
        lifecycle_state=state,
        credential=SimpleNamespace(username="alice", password=password, token=None, source="provided"),
        args=SimpleNamespace(timeout=1, defcreds=False, enum_cve=False),
    )


def test_user_404_can_be_verified_by_strict_org_differential(transport):
    transport("org")
    verified, reason = actions._verify_credentials("qa", 3000, 1, "alice", "correct")
    assert verified is True, reason


def test_public_org_response_does_not_verify_the_pair(transport):
    transport("public-org")
    verified, _reason = actions._verify_credentials("qa", 3000, 1, "alice", "correct")
    assert verified is not True


@pytest.mark.parametrize("mode", ["any-basic-user", "any-basic-org"])
def test_any_basic_header_acceptance_is_not_pair_specific_proof(transport, mode):
    transport(mode)
    verified, _reason = actions._verify_credentials("qa", 3000, 1, "alice", "correct")
    assert verified is not True


def test_basic_disabled_login_session_is_proved_and_used_for_data(transport):
    peer, state = transport("session")
    source = {"status": "auth_required", "auth_required": True, "is_grafana": True, "server_version": "13.0.2"}
    ctx = context(state)
    authenticated = actions.authenticate_grafana(ctx, source, {})
    assert authenticated["provided_credentials_ok"] is True
    record = actions.collect_grafana_data(ctx, authenticated, {"show_datasources": True, "check_urls": []})
    assert record["datasource_count"] == 1
    sent = [headers for _method, path, headers, _body in peer.calls if path == "/api/datasources"]
    assert sent and "qa_session=verified" in {key.lower(): value for key, value in sent[-1].items()}.get("cookie", "")


def test_defcreds_retains_capabilities_before_later_failed_pairs_lock_basic_auth(monkeypatch):
    state = actions.GrafanaLifecycleState()
    source = {"status": "auth_required", "auth_required": True, "is_grafana": True}
    calls = []
    locked = False

    def verify(_host, _port, _timeout, _username, password):
        nonlocal locked
        if password == "correct":
            return True, None
        locked = True
        return False, "invalid credentials"

    def datasources(_host, _port, _timeout, *, auth_header=None):
        calls.append(auth_header)
        if not locked:
            return [{"name": "QA", "type": "prometheus"}], None, 200
        return None, "authentication required", 401

    monkeypatch.setattr(actions, "_verify_credentials", verify)
    monkeypatch.setattr(actions, "_fetch_datasources", datasources)
    monkeypatch.setattr(actions, "_activate_grafana_transport", lambda _state: None)
    args = SimpleNamespace(timeout=1, defcreds=True, enum_cve=False, _spray_capabilities=False)

    def ctx(password):
        return SimpleNamespace(
            host="qa",
            port=3000,
            lifecycle_state=state,
            credential=SimpleNamespace(username="alice", password=password, token=None, source="default"),
            args=args,
        )

    accepted = actions.authenticate_grafana(ctx("correct"), source, {"show_datasources": True, "check_urls": []})
    assert accepted["default_credentials"] is True
    rejected = actions.authenticate_grafana(ctx("wrong"), accepted, {"show_datasources": True, "check_urls": []})
    assert rejected["attempted_credentials_count"] == 2
    selected = {**accepted, "attempted_credentials": rejected["attempted_credentials"]}
    result = actions.collect_grafana_data(ctx("wrong"), selected, {"show_datasources": True, "check_urls": []})
    assert result["datasource_count"] == 1
    assert result["error"] is None
    assert result["attempted_credentials_count"] == 2
    assert len(calls) == 1


def test_login_cookie_without_authenticated_api_proof_is_unverified(transport):
    transport("cookie-only")
    verified, _reason = actions._verify_credentials("qa", 3000, 1, "alice", "correct")
    assert verified is None


def test_invalid_candidate_cannot_inherit_a_previously_verified_session(transport):
    peer, state = transport("session")
    source = {"status": "auth_required", "auth_required": True, "is_grafana": True, "server_version": "13.0.2"}
    accepted = actions.authenticate_grafana(context(state), source, {})
    assert accepted["provided_credentials_ok"] is True
    before = len(peer.calls)
    rejected = actions.authenticate_grafana(context(state, "wrong"), source, {})
    assert rejected["provided_credentials_ok"] is False
    for _method, _path, headers, _body in peer.calls[before:]:
        assert "qa_session=verified" not in {key.lower(): value for key, value in headers.items()}.get("cookie", "")


def test_rate_limit_is_exposed_even_with_anonymous_data_access(transport):
    peer, state = transport("rate")
    result = actions.authenticate_grafana(
        context(state), {"status": "open_no_auth", "auth_required": False, "is_grafana": True}, {}
    )
    assert result["provided_credentials_ok"] is None
    assert result.get("auth_http_status") == 429
    assert result.get("auth_error_detail")
    assert not any(method == "POST" for method, _path, _headers, _body in peer.calls)


def test_identity_echo_for_any_basic_pair_is_not_password_proof(monkeypatch):
    import base64

    from redposture_core.modules.grafana import actions

    def request(_host, _port, path, _timeout, **kwargs):
        authorization = (kwargs.get("headers") or {}).get("Authorization")
        if path == "/api/user" and authorization:
            username = base64.b64decode(authorization.split()[1]).decode().split(":", 1)[0]
            return (
                200,
                json.dumps({"id": 1, "login": username, "email": username + "@qa.invalid", "isGrafanaAdmin": False}),
                {},
            )
        if path == "/login":
            return 401, '{"message":"Invalid username or password"}', {}
        return 401, "{}", {}

    monkeypatch.setattr(actions, "_http_request", request)
    assert actions._verify_credentials("qa", 3000, 1, "alice", "wrong")[0] is not True
