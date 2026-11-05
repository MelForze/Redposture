"""Missing legacy routes must not prevent independent credential proof."""

from __future__ import annotations

import base64
import json
from urllib.parse import urlsplit

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.grafana import actions

PAYLOADS = {
    "/api/user/orgs": [{"orgId": 1, "name": "Operations", "role": "Viewer"}],
    "/api/user/preferences": {"theme": "dark", "timezone": "utc", "homeDashboardUID": "ops"},
    "/api/access-control/user/permissions": {"dashboards:read": ["dashboards:*"]},
    "/api/user/teams": [{"id": 1, "orgId": 1, "name": "Operations", "email": "", "memberCount": 2}],
    "/api/org/users": [{"orgId": 1, "userId": 1, "login": "alice", "email": "a@qa", "role": "Viewer"}],
}


class Peer:
    def __init__(self, path, mode="basic", payload=None):
        self.path, self.mode = path, mode
        self.payload = PAYLOADS[path] if payload is None else payload
        self.calls = []

    def request(self, method, url, *, headers=None, body=None, **kwargs):
        path = urlsplit(url).path
        headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.calls.append((method, path, headers))
        authorization = headers.get("authorization", "")
        valid = authorization == actions._auth_header("alice", "correct")
        if self.mode == "username-only" and authorization.startswith("Basic "):
            valid = base64.b64decode(authorization[6:]).decode().startswith("alice:")
        if self.mode == "token":
            valid = authorization == "Bearer correct"
        if self.mode == "any-token":
            valid = authorization.startswith("Bearer ")
        if self.mode == "cookie":
            valid = headers.get("cookie") == "grafana_session=proof"
        if self.mode == "any-basic":
            valid = bool(authorization)
        if self.mode == "public":
            valid = True
        if path == self.path:
            if self.mode == "rate":
                return self.reply(429, {"message": "too many requests FULL-TAIL"})
            return self.reply(200, self.payload) if valid else self.reply(401, {"message": "Unauthorized"})
        if method == "POST" and path == "/login" and self.mode == "cookie":
            if json.loads(body) == {"user": "alice", "password": "correct"}:
                return self.reply(
                    200, {"message": "Logged in"}, {"Set-Cookie": "grafana_session=proof; Path=/; HttpOnly"}
                )
            return self.reply(401, {"message": "Invalid username or password"})
        return self.reply(404, {})

    @staticmethod
    def reply(status, body, headers=None):
        return HttpResponse(status, json.dumps(body).encode(), headers or {})

    def close(self):
        pass


@pytest.fixture
def setup():
    previous = vars(actions._THREAD_LOCAL_HTTP).copy()
    states = []

    def create(path, mode="basic", payload=None):
        peer = Peer(path, mode, payload)
        state = actions.GrafanaLifecycleState(http=peer, host="qa", port=3000, scheme="http")
        actions._activate_grafana_transport(state)
        actions._THREAD_LOCAL_HTTP.credential_result = {}
        states.append(state)
        return peer

    yield create
    for state in states:
        state.close()
    vars(actions._THREAD_LOCAL_HTTP).clear()
    vars(actions._THREAD_LOCAL_HTTP).update(previous)


@pytest.mark.parametrize("path", PAYLOADS)
@pytest.mark.parametrize("mode", ["basic", "cookie"])
def test_pair_proof_with_only_one_documented_route_available(setup, path, mode):
    setup(path, mode)
    ok, reason = actions._verify_credentials("qa", 3000, 1, "alice", "correct")
    assert ok is True, reason
    if mode == "cookie":
        assert actions._THREAD_LOCAL_HTTP.credential_result["session"]["cookie"] == "grafana_session=proof"


@pytest.mark.parametrize("path", PAYLOADS)
@pytest.mark.parametrize("mode", ["public", "any-basic", "username-only"])
def test_public_or_unchecked_password_never_proves_pair(setup, path, mode):
    setup(path, mode)
    assert actions._verify_credentials("qa", 3000, 1, "alice", "correct")[0] is not True


@pytest.mark.parametrize("path", PAYLOADS)
@pytest.mark.parametrize("payload", [{}, [], {"ok": True}, [{"id": True, "name": "Ops"}]])
def test_malformed_schema_cannot_prove_credentials(setup, path, payload):
    setup(path, payload=payload)
    assert actions._verify_credentials("qa", 3000, 1, "alice", "correct")[0] is not True


@pytest.mark.parametrize("path", PAYLOADS)
@pytest.mark.parametrize("mode,expected", [("basic", True), ("public", False), ("rate", None)])
def test_anonymous_inference_uses_documented_fallbacks(setup, path, mode, expected):
    peer = setup(path, mode)
    assert actions._infer_grafana_auth_required("qa", 3000, 1, health_status=200, health_api_ok=True) is expected
    if mode == "rate":
        assert peer.calls[-1][1] == path


@pytest.mark.parametrize("path", PAYLOADS)
@pytest.mark.parametrize("mode,expected", [("token", True), ("any-token", None), ("public", None), ("rate", None)])
def test_token_fallback_needs_invalid_token_and_anonymous_controls(setup, path, mode, expected):
    peer = setup(path, mode)
    assert actions._verify_apitoken("qa", 3000, 1, "correct")[0] is expected
    if mode == "rate":
        assert peer.calls[-1][1] == path


@pytest.mark.parametrize("path", PAYLOADS)
def test_fallback_rate_limit_stops_before_login(setup, path):
    peer = setup(path, "rate")
    ok, reason = actions._verify_credentials("qa", 3000, 1, "alice", "correct")
    assert ok is None and "FULL-TAIL" in reason
    assert peer.calls[-1][1] == path
    assert all(method == "GET" for method, _, _ in peer.calls)


@pytest.mark.parametrize("metadata", ["location", "final-url", "history"])
def test_sso_login_uses_redirect_evidence_without_moving_api_origin(setup, metadata):
    peer = setup("/api/user/orgs")
    idp = "https://identity.qa/realms/ops/protocol/openid-connect/auth?client_id=grafana&response_type=code&redirect_uri=https://qa/login/generic_oauth"
    original_request = peer.request

    def request(method, url, **kwargs):
        if urlsplit(url).path == "/login":
            peer.calls.append((method, "/login", kwargs))
            return HttpResponse(
                302 if metadata == "location" else 200,
                b"<title>Enter infrastructure</title>",
                {"Location": idp} if metadata == "location" else {},
                error="cross-origin redirect blocked: qa -> identity.qa" if metadata == "location" else None,
                final_url=idp if metadata == "final-url" else url,
                redirect_history=(idp,) if metadata == "history" else (),
            )
        return original_request(method, url, **kwargs)

    peer.request = request
    status, body, headers = actions._http_request("qa", 3000, "/login", 1)
    sso = actions._grafana_sso_response(body, headers)
    assert sso is not None and sso.provider == "keycloak"
    assert actions._THREAD_LOCAL_HTTP.state.host == "qa"
    assert actions._THREAD_LOCAL_HTTP.state.port == 3000
    actions._http_request("qa", 3000, "/api/user", 1)
    assert peer.calls[-1][1] == "/api/user"
    if metadata == "location":
        assert peer.calls[0][2]["allow_cross_origin_redirects"] is False


def test_non_sso_redirect_error_is_not_authentication_proof(setup):
    peer = setup("/api/user/orgs")
    peer.request = lambda *args, **kwargs: HttpResponse(
        302, b"", {"Location": "https://other.qa/landing"}, error="cross-origin redirect blocked: qa -> other.qa"
    )
    from urllib.error import URLError

    with pytest.raises(URLError):
        actions._http_request("qa", 3000, "/login", 1)


@pytest.mark.parametrize("path", PAYLOADS)
@pytest.mark.parametrize("mode", ["basic", "cookie"])
def test_wrong_pair_is_not_accepted_on_extended_routes(setup, path, mode):
    setup(path, mode)
    assert actions._verify_credentials("qa", 3000, 1, "alice", "wrong")[0] is not True


@pytest.mark.parametrize("legacy_status", [200, 403, 404, 405, 501])
def test_unusable_legacy_identity_routes_do_not_block_fallback(setup, legacy_status):
    peer = setup("/api/user/orgs")
    request = peer.request

    def wrapped(method, url, **kwargs):
        if urlsplit(url).path in {"/api/user", "/api/org"}:
            return peer.reply(legacy_status, {"message": "unavailable"})
        return request(method, url, **kwargs)

    peer.request = wrapped
    assert actions._verify_credentials("qa", 3000, 1, "alice", "correct")[0] is True


def test_preferences_without_optional_dashboard_fields_are_valid(setup):
    setup("/api/user/preferences", payload={"theme": "dark", "timezone": "utc"})
    assert actions._verify_credentials("qa", 3000, 1, "alice", "correct")[0] is True


def test_permission_actions_may_include_documented_legacy_dot_names(setup):
    setup(
        "/api/access-control/user/permissions", payload={"featuremgmt.read": [""], "dashboards:read": ["dashboards:*"]}
    )
    assert actions._verify_credentials("qa", 3000, 1, "alice", "correct")[0] is True


@pytest.mark.parametrize("identity_status,capability_status", [(401, 403), (401, 404), (200, 403), (200, 200)])
def test_restricted_or_replaced_token_endpoints_can_use_permissions(setup, identity_status, capability_status):
    peer = setup("/api/access-control/user/permissions", "token")
    request = peer.request

    def wrapped(method, url, **kwargs):
        path = urlsplit(url).path
        if path in {"/api/user", "/api/datasources"}:
            return peer.reply(identity_status if path == "/api/user" else capability_status, {"message": "unavailable"})
        return request(method, url, **kwargs)

    peer.request = wrapped
    assert actions._verify_apitoken("qa", 3000, 1, "correct")[0] is True


@pytest.mark.parametrize("missing_path", ["/api/user", "/api/org"])
def test_one_unusable_legacy_route_and_one_denial_still_allow_proof(setup, missing_path):
    peer = setup("/api/user/orgs")
    request = peer.request

    def wrapped(method, url, **kwargs):
        path = urlsplit(url).path
        if path in {"/api/user", "/api/org"}:
            return peer.reply(404 if path == missing_path else 401, {})
        return request(method, url, **kwargs)

    peer.request = wrapped
    assert actions._verify_credentials("qa", 3000, 1, "alice", "correct")[0] is True


@pytest.mark.parametrize("datasource_status", [200, 500, 501])
def test_anonymous_inference_can_recover_from_broken_datasource_route(setup, datasource_status):
    peer = setup("/api/user/orgs", "public")
    request = peer.request

    def wrapped(method, url, **kwargs):
        if urlsplit(url).path == "/api/datasources":
            return peer.reply(datasource_status, {"message": "unavailable"})
        return request(method, url, **kwargs)

    peer.request = wrapped
    assert actions._infer_grafana_auth_required("qa", 3000, 1, health_status=200, health_api_ok=True) is False


@pytest.mark.parametrize(
    "failed_path", ["/api/datasources", "/api/user", "/api/org", "/api/login/ping", "/api/user/preferences"]
)
def test_single_failed_route_does_not_hide_other_available_auth_proof(setup, failed_path):
    from urllib.error import URLError

    peer = setup("/api/access-control/user/permissions", "public")
    request = peer.request

    def wrapped(method, url, **kwargs):
        if urlsplit(url).path == failed_path:
            raise URLError("one route disconnected")
        return request(method, url, **kwargs)

    peer.request = wrapped
    assert actions._infer_grafana_auth_required("qa", 3000, 1, health_status=200, health_api_ok=True) is False


@pytest.mark.parametrize("failed_path", ["/api/user", "/api/org"])
def test_failed_identity_route_does_not_erase_pair_proof(setup, failed_path):
    from urllib.error import URLError

    peer = setup("/api/user/orgs")
    request = peer.request

    def wrapped(method, url, **kwargs):
        if urlsplit(url).path == failed_path:
            raise URLError("one route disconnected")
        return request(method, url, **kwargs)

    peer.request = wrapped
    assert actions._verify_credentials("qa", 3000, 1, "alice", "correct")[0] is True


def test_ordinary_invalid_pair_does_not_probe_extended_routes(setup):
    peer = setup("/api/user/orgs")
    request = peer.request

    def wrapped(method, url, **kwargs):
        path = urlsplit(url).path
        if path in {"/api/user", "/api/org", "/login"}:
            peer.calls.append((method, path, kwargs.get("headers", {})))
            return peer.reply(401, {"message": "Invalid username or password"})
        return request(method, url, **kwargs)

    peer.request = wrapped
    assert actions._verify_credentials("qa", 3000, 1, "alice", "wrong")[0] is False
    assert [(method, path) for method, path, _ in peer.calls] == [
        ("GET", "/api/user"),
        ("GET", "/api/org"),
        ("POST", "/login"),
    ]


@pytest.mark.parametrize("path", PAYLOADS)
def test_previous_extended_session_cannot_authenticate_next_pair(setup, path):
    from types import SimpleNamespace

    peer = setup(path, "cookie")
    state = actions._THREAD_LOCAL_HTTP.state
    source = {"is_grafana": True, "status": "auth_required", "auth_required": True, "server_version": "13.0.2"}

    def context(password):
        return SimpleNamespace(
            host="qa",
            port=3000,
            lifecycle_state=state,
            credential=SimpleNamespace(username="alice", password=password, token=None, source="provided"),
            args=SimpleNamespace(timeout=1, defcreds=False, enum_cve=False),
        )

    assert actions.authenticate_grafana(context("correct"), source, {})["provided_credentials_ok"] is True
    first = len(peer.calls)
    assert actions.authenticate_grafana(context("wrong"), source, {})["provided_credentials_ok"] is False
    assert all("cookie" not in headers for _, _, headers in peer.calls[first:])
