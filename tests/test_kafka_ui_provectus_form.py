"""Real v0.7.2 protects /api/* and serves Spring form login at /auth."""

from __future__ import annotations

import asyncio
import json
from copy import deepcopy
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.clients.http_session import HttpSessionPool
from redposture_core.detection_io import run_async
from redposture_core.modules.kafka import ui

ACTUATOR: dict[str, Any] = {
    "git": {"commit": {"id": "83b5a60"}},
    "build": {"artifact": "kafka-ui-api", "name": "kafka-ui-api", "version": "v0.7.2", "group": "com.provectus"},
}
FORM = '<html><title>Please sign in</title><form method="post" action="/prefix/auth"><input name="username"><input name="password"></form></html>'


def reply(status: int, data: Any, **kwargs: Any) -> HttpResponse:
    return HttpResponse(
        status, (json.dumps(data) if not isinstance(data, str) else data).encode(), kwargs.pop("headers", {}), **kwargs
    )


class Pool:
    def __init__(self, actuator=ACTUATOR, form=FORM):
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self.authenticated = False
        self.routes = {
            ("GET", "/"): reply(
                200,
                form,
                final_url="http://qa.invalid:8080/prefix/auth",
                redirect_history=("http://qa.invalid:8080/prefix/",),
            ),
            ("GET", "/auth"): reply(200, form),
            ("GET", "/actuator/info"): reply(200, actuator),
        }
        for path in ["/api/info", "/api/config/authentication", "/api/authorization", "/api/clusters"]:
            self.routes["GET", path] = reply(
                200,
                form,
                final_url="http://qa.invalid:8080/prefix/auth",
                redirect_history=("http://qa.invalid:8080/prefix" + path,),
            )

    def request(self, method, url, **kwargs):
        path = urlsplit(url).path
        self.calls.append((method, path, kwargs))
        if not path.startswith("/prefix/"):
            return reply(404, {})
        path = path[len("/prefix") :]
        if self.authenticated and path in {"/api/authorization", "/api/info"}:
            assert kwargs.get("headers", {}).get("Cookie") == "SESSION=qa-confirmed"
        return self.routes.get((method, path), reply(404, {}))

    request_once = request


def context(path="/prefix"):
    return SimpleNamespace(
        host="qa.invalid",
        port=8080,
        args=SimpleNamespace(timeout=1),
        target=SimpleNamespace(path=path, scheme="http", explicit_port=8080),
        credential=SimpleNamespace(username="profile-user", password="profile-password", source="provided"),
    )


def state(pool):
    return SimpleNamespace(
        ui_http=pool, ui_base=None, ui_auth_type=None, ui_vendor=None, ui_cookie="", ui_anonymous_clusters=None
    )


@pytest.mark.parametrize("path", ["/prefix", "/prefix/auth", "/prefix/actuator/info"])
def test_real_auth_redirect_and_strict_actuator_confirm_ui_with_login_path(path):
    pool = Pool()
    current = state(pool)
    result = ui.detect_ui(context(path), current)
    assert result["is_kafka"] is True and result["is_kafka_ui"] is True
    assert result["ui_vendor"] == "provectus" and result["version"] == "v0.7.2"
    assert result["auth_required"] is True and result["credential_verification_status"] == "available"
    assert current.ui_base == "http://qa.invalid:8080/prefix" and current.ui_login_path == "/auth"
    assert any(path == "/prefix/actuator/info" for _, path, _ in pool.calls)
    assert all(method == "GET" for method, _, _ in pool.calls)


def test_detected_form_endpoint_is_used_and_identity_is_verified():
    pool = Pool()
    current = state(pool)
    ctx = context()
    detected = ui.detect_ui(ctx, current)
    pool.routes["POST", "/auth"] = reply(
        302, "", headers={"Location": "/prefix/", "Set-Cookie": "SESSION=qa-confirmed; Path=/prefix; HttpOnly"}
    )
    pool.routes["GET", "/api/authorization"] = reply(
        200, {"rbacEnabled": False, "userInfo": {"username": "profile-user", "permissions": []}}
    )
    pool.routes["GET", "/api/info"] = reply(200, {"build": {"commitId": "83b5a60", "version": "v0.7.2"}})
    pool.authenticated = True
    result = ui.authenticate_ui(ctx, detected, current)
    assert result["provided_credentials_ok"] is True and result["status"] == "valid_credentials"
    assert current.ui_cookie == "SESSION=qa-confirmed"
    posts = [(path, parse_qs(options["body"].decode())) for method, path, options in pool.calls if method == "POST"]
    assert posts == [("/prefix/auth", {"username": ["profile-user"], "password": ["profile-password"]})]


@pytest.mark.parametrize(
    "fault",
    ["artifact", "group", "version", "git", "external-action", "no-form", "cross-origin-redirect", "no-redirect"],
)
def test_generic_spring_forms_or_malformed_builds_do_not_identify_kafka_ui(fault):
    actuator = deepcopy(ACTUATOR)
    if fault in {"artifact", "group", "version"}:
        actuator["build"][fault] = "unrelated"
    elif fault == "git":
        actuator["git"] = {}
    form = (
        FORM.replace("/prefix/auth", "https://other.invalid/auth")
        if fault == "external-action"
        else "<html><title>Please sign in</title></html>"
        if fault == "no-form"
        else FORM
    )
    pool = Pool(actuator, form)
    if fault in {"cross-origin-redirect", "no-redirect"}:
        for key in list(pool.routes):
            if key[1].startswith("/api/"):
                pool.routes[key] = reply(
                    200,
                    form,
                    final_url="https://other.invalid/auth"
                    if fault == "cross-origin-redirect"
                    else "http://qa.invalid:8080/prefix" + key[1],
                    redirect_history=("old",) if fault == "cross-origin-redirect" else (),
                )
    result = ui.detect_ui(context(), state(pool))
    assert result["is_kafka"] is False
    assert all(method == "GET" for method, _, _ in pool.calls)


def test_existing_api_fingerprint_does_not_add_actuator_requests():
    pool = Pool()
    pool.routes["GET", "/api/info"] = reply(
        200, {"build": {"commitId": "83b5a60", "version": "v0.7.2"}, "name": "Provectus"}
    )
    pool.routes["GET", "/api/config/authentication"] = reply(200, {"authType": "LOGIN_FORM"})
    pool.routes["GET", "/api/authorization"] = reply(200, {"rbacEnabled": False, "userInfo": None})
    result = ui.detect_ui(context(), state(pool))
    assert result["is_kafka"] is True
    assert all(path != "/prefix/actuator/info" for _, path, _ in pool.calls)


def test_real_json_accept_redirect_406_fetches_html_before_release_identity():
    """Spring rejects JSON Accept at its generated login page with HTTP 406."""
    pool = Pool()
    for key in list(pool.routes):
        if key[1].startswith("/api/"):
            pool.routes[key] = reply(
                406,
                {"code": 5000, "message": "Could not find acceptable representation"},
                final_url="http://qa.invalid:8080/prefix/auth",
                redirect_history=("http://qa.invalid:8080/prefix" + key[1],),
            )
    current = state(pool)
    result = ui.detect_ui(context(), current)
    assert result["is_kafka"] is True and current.ui_login_path == "/auth"
    html_calls = [options for method, path, options in pool.calls if path == "/prefix/auth"]
    assert len(html_calls) == 1 and html_calls[0]["headers"]["Accept"] == "text/html"


def test_async_detect_uses_native_http_for_negotiated_form(monkeypatch):
    model = Pool()
    for key in list(model.routes):
        if key[1].startswith("/api/"):
            model.routes[key] = reply(
                406,
                {},
                final_url="http://qa.invalid:8080/prefix/auth",
                redirect_history=("http://qa.invalid:8080/prefix" + key[1],),
            )
    pool = HttpSessionPool(timeout=1, retries=0)
    current = state(pool)
    monkeypatch.setattr(pool, "request", lambda *a, **k: pytest.fail("sync HTTP used during async detect"))

    class Native:
        timeout = 1
        retries = 0
        max_bytes = 262144
        ssl_context = None

        async def close(self):
            pass

        async def get(self, url, **kwargs):
            return model.request("GET", url, **kwargs)

    try:
        registry: dict[Any, Any] = {**ui._ASYNC_RETAINED_STEPS, **ui.http_surfaces._ASYNC_RETAINED_STEPS}
        result = asyncio.run(
            run_async(
                ui._detect_ui_detect_steps(context(), current),
                Native(),
                registry,
            )
        )
    finally:
        pool.close()
    assert result["is_kafka"] is True and current.ui_login_path == "/auth"
    assert any((options.get("headers") or {}).get("Accept") == "text/html" for _, _, options in model.calls)


@pytest.mark.parametrize(
    "final_url",
    [
        "http://other.invalid:8080/prefix/auth",
        "http://qa.invalid:8081/prefix/auth",
        "https://qa.invalid:8080/prefix/auth",
        "http://other@qa.invalid:8080/prefix/auth",
    ],
)
def test_form_redirect_requires_each_origin_component(final_url):
    pool = Pool()
    for key in list(pool.routes):
        if key[1].startswith("/api/"):
            pool.routes[key] = reply(200, FORM, final_url=final_url, redirect_history=("original",))
    assert ui.detect_ui(context(), state(pool))["is_kafka"] is False
    assert not any(path == "/prefix/actuator/info" for _, path, _ in pool.calls)


@pytest.mark.parametrize("user_info", [{"username": "another-user"}, None])
def test_login_redirect_or_other_identity_does_not_accept_pair(user_info):
    pool = Pool()
    current = state(pool)
    record = ui.detect_ui(context(), current)
    pool.routes["POST", "/auth"] = reply(
        302, "", headers={"Location": "/prefix/", "Set-Cookie": "SESSION=qa-confirmed; Path=/prefix"}
    )
    pool.routes["GET", "/api/authorization"] = reply(200, {"rbacEnabled": False, "userInfo": user_info})
    result = ui.authenticate_ui(context(), record, current)
    assert result["provided_credentials_ok"] is None
    assert not current.ui_cookie


@pytest.mark.parametrize(
    "status,truncated,error", [(403, False, None), (200, True, None), (0, False, "connection reset")]
)
def test_unfinished_or_denied_release_identity_never_confirms_ui(status, truncated, error):
    pool = Pool()
    pool.routes["GET", "/actuator/info"] = reply(status, ACTUATOR, truncated=truncated, error=error)
    assert ui.detect_ui(context(), state(pool))["is_kafka"] is False
    assert all(method == "GET" for method, _, _ in pool.calls)


@pytest.mark.parametrize("path", ["https://other.invalid/auth", "/prefix/auth", "/api/authorization", 123])
def test_login_endpoint_from_record_cannot_send_credentials_to_unobserved_path(path):
    pool = Pool()
    current = state(pool)
    record = ui.detect_ui(context(), current)
    record["ui_login_path"] = path
    start = len(pool.calls)
    result = ui.authenticate_ui(context(), record, current)
    assert result["provided_credentials_ok"] is None
    assert pool.calls[start:] == []


@pytest.mark.parametrize(
    "status,location,expected",
    [(302, "/prefix/auth?error", False), (401, "", False), (403, "", None), (429, "", None), (503, "", None)],
)
def test_real_auth_endpoint_preserves_rejection_vs_unavailable(status, location, expected):
    pool = Pool()
    current = state(pool)
    record = ui.detect_ui(context(), current)
    pool.routes["POST", "/auth"] = reply(status, "", headers={"Location": location})
    result = ui.authenticate_ui(context(), record, current)
    assert result["provided_credentials_ok"] is expected
    assert result["credential_attempts"][0]["ok"] is expected
    assert not current.ui_cookie
