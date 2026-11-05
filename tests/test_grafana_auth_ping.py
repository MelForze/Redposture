"""A blocked legacy identity API still needs pair-specific session proof."""

from __future__ import annotations

import json
from urllib.parse import urlsplit

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.grafana import actions


class Peer:
    def __init__(self, mode):
        self.mode = mode
        self.calls = []

    def request(self, method, url, *, headers=None, body=None, **kwargs):
        path = urlsplit(url).path
        headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.calls.append((method, path, headers))
        basic = headers.get("authorization") == actions._auth_header("alice", "correct")
        if self.mode == "username-only" and headers.get("authorization"):
            import base64

            basic = base64.b64decode(headers["authorization"].split()[1]).decode().split(":", 1)[0] == "alice"
        cookie = headers.get("cookie") == "grafana_session=proof"
        if path in {"/api/user", "/api/org", "/api/datasources"}:
            return self.reply(404, {"message": "Not found"})
        if path == "/api/login/ping":
            if self.mode == "rate":
                return self.reply(429, {"message": "too many login attempts"})
            if self.mode == "unavailable":
                return self.reply(404, {})
            accepted = (
                basic
                if self.mode in {"basic", "username-only"}
                else cookie
                if self.mode in {"cookie", "login-username-only"}
                else True
            )
            if self.mode == "any-basic":
                accepted = bool(headers.get("authorization"))
            if not accepted:
                return self.reply(401, {"message": "Unauthorized"})
            return self.reply(200, {"message": "Logged in"} if self.mode != "bad-json" else {"ok": True})
        if path == "/login" and method == "POST":
            candidate = json.loads(body)
            if self.mode in {"cookie", "login-username-only"}:
                if candidate == {"user": "alice", "password": "correct"} or (
                    self.mode == "login-username-only" and candidate.get("user") == "alice"
                ):
                    return self.reply(
                        200, {"message": "Logged in"}, {"Set-Cookie": "grafana_session=proof; Path=/; HttpOnly"}
                    )
                return self.reply(401, {"message": "Invalid username or password"})
            return self.reply(405, {})
        return self.reply(404, {})

    @staticmethod
    def reply(status, body, headers=None):
        return HttpResponse(status, json.dumps(body).encode(), {"Content-Type": "application/json", **(headers or {})})

    def close(self):
        pass


@pytest.fixture
def setup():
    previous = dict(vars(actions._THREAD_LOCAL_HTTP))
    states = []

    def create(mode):
        peer = Peer(mode)
        state = actions.GrafanaLifecycleState(http=peer, host="qa", port=3000, scheme="http", origin_resolved=True)
        actions._activate_grafana_transport(state)
        actions._THREAD_LOCAL_HTTP.credential_result = {}
        states.append(state)
        return peer, state

    yield create
    for state in states:
        state.close()
    vars(actions._THREAD_LOCAL_HTTP).clear()
    vars(actions._THREAD_LOCAL_HTTP).update(previous)


@pytest.mark.parametrize("mode", ["basic", "cookie"])
def test_user_org_404_can_verify_pair_via_signed_in_ping(setup, mode):
    peer, state = setup(mode)
    verified, reason = actions._verify_credentials("qa", 3000, 1, "alice", "correct")
    assert verified is True, reason
    assert any(path == "/api/login/ping" for _, path, _ in peer.calls)
    if mode == "cookie":
        assert actions._THREAD_LOCAL_HTTP.credential_result["session"]["cookie"] == "grafana_session=proof"


@pytest.mark.parametrize("mode", ["basic", "cookie"])
def test_unavailable_datasources_can_still_confirm_auth_required(setup, mode):
    setup(mode)
    assert actions._infer_grafana_auth_required("qa", 3000, 1, health_status=200, health_api_ok=True) is True


@pytest.mark.parametrize("mode", ["public", "any-basic", "bad-json", "unavailable"])
def test_ping_never_confirms_an_unproved_pair(setup, mode):
    setup(mode)
    assert actions._verify_credentials("qa", 3000, 1, "alice", "correct")[0] is not True


def test_404_everywhere_remains_inconclusive(setup):
    setup("unavailable")
    assert actions._infer_grafana_auth_required("qa", 3000, 1, health_status=200, health_api_ok=True) is None


def test_ping_rate_limit_stops_fallback_login(setup):
    peer, _state = setup("rate")
    verified, reason = actions._verify_credentials("qa", 3000, 1, "alice", "correct")
    assert verified is None and "stopped" in reason
    assert not any(method == "POST" for method, _, _ in peer.calls)


def test_unverified_pair_is_not_rendered_as_rejected():
    record = {
        "host": "qa",
        "port": 3000,
        "service": "grafana",
        "auth_attempts": [{"username": "alice", "password": "correct", "ok": None, "error": "API unavailable"}],
    }
    lines = actions._format_auth_attempt_detail_records(record, "txt")
    assert len(lines) == 1 and "[*] alice:correct (unverified:" in lines[0]
    assert "[-]" not in lines[0] and "\x1b" not in lines[0]


def test_auth_required_summary_leaves_unverified_state_in_attempt_details():
    record = {
        "host": "qa",
        "port": 3000,
        "service": "grafana",
        "is_grafana": True,
        "status": "auth_required",
        "auth_required": True,
        "attempted_credentials_count": 1,
        "auth_attempts": [{"username": "alice", "password": "correct", "ok": None, "error": "API unavailable"}],
    }
    text = actions._format_record(record, "txt")
    assert "credentials invalid" not in text
    assert text == ""
    assert "[*]" in actions._format_auth_attempt_detail_records(record, "txt")[0]


@pytest.mark.parametrize("mode,expected", [("public", False), ("bad-json", None), ("unavailable", None)])
def test_auth_fallback_needs_a_valid_public_schema(setup, mode, expected):
    setup(mode)
    assert actions._infer_grafana_auth_required("qa", 3000, 1, health_status=200, health_api_ok=True) is expected


@pytest.mark.parametrize(
    "ok,marker,pair_color", [(True, "[+]", "true_red"), (False, "[-]", "white"), (None, "[*]", "white")]
)
def test_credential_palette_keeps_verified_rejected_and_unknown_distinct(ok, marker, pair_color, capsys):
    from redposture_core.console import Console
    from tests.test_stage_color_renderers import _contains_paint, _RecordingConsole

    record = {
        "host": "qa",
        "port": 3000,
        "auth_attempts": [{"username": "alice", "password": "correct", "ok": ok, "error": "API unavailable"}],
    }
    line = actions._format_auth_attempt_detail_records(record, "txt")[0]
    assert marker in line
    console = _RecordingConsole()
    assert actions._render_colored_grafana_line(console, line)
    assert _contains_paint(console.paint_calls, "alice:correct", pair_color)
    if ok is None:
        assert _contains_paint(console.paint_calls, "unverified:", "orange")
        assert all("(" not in text and ")" not in text for text, color in console.paint_calls if color == "orange")
    assert actions._render_colored_grafana_line(Console(no_color=True), line)
    assert "\x1b" not in capsys.readouterr().out


def test_wrong_pair_cannot_reuse_verified_ping_cookie(setup):
    from types import SimpleNamespace

    peer, state = setup("cookie")
    source = {"status": "auth_required", "auth_required": True, "is_grafana": True, "server_version": "13.0.1"}

    def context(password):
        return SimpleNamespace(
            host="qa",
            port=3000,
            lifecycle_state=state,
            credential=SimpleNamespace(username="alice", password=password, token=None, source="provided"),
            args=SimpleNamespace(timeout=1, defcreds=False, enum_cve=False),
        )

    accepted = actions.authenticate_grafana(context("correct"), source, {})
    assert accepted["provided_credentials_ok"] is True
    mark = len(peer.calls)
    rejected = actions.authenticate_grafana(context("wrong"), source, {})
    assert rejected["provided_credentials_ok"] is False
    assert all("cookie" not in headers for _, _, headers in peer.calls[mark:])


@pytest.mark.parametrize("mode", ["username-only", "login-username-only"])
def test_known_username_without_password_validation_is_not_accepted(setup, mode):
    setup(mode)
    assert actions._verify_credentials("qa", 3000, 1, "alice", "correct")[0] is not True
