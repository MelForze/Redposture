"""Inconclusive identity transport responses never become rejected credentials."""

from __future__ import annotations

import json
from types import SimpleNamespace as NS
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.gitlab import actions as gitlab
from redposture_core.modules.registry import actions as registry


@pytest.mark.parametrize("product", ["harbor", "nexus"])
@pytest.mark.parametrize("fault", ["transport", "forbidden", "malformed_json", "wrong_identity"])
def test_registry_identity_fault_is_unverified(monkeypatch: pytest.MonkeyPatch, product: str, fault: str) -> None:
    payload = {"username": "other", "user_id": 1} if product == "harbor" else [{"userId": "other"}]
    responses = {
        "transport": (0, b"", {}, "reset"),
        "forbidden": (403, b"{}", {}, None),
        "malformed_json": (200, b"not-json", {}, None),
        "wrong_identity": (200, json.dumps(payload).encode(), {}, None),
    }
    calls = []
    monkeypatch.setattr(
        registry, "_http_request", lambda *args, **kwargs: calls.append((args, kwargs)) or responses[fault]
    )
    valid, reason = registry._verify_registry_credential(
        product, "qa", 8080, 1, "alice", "secret", None, anonymous_probe=None
    )
    assert valid is None and reason
    expected_paths = (
        ["/service/rest/v1/security/users", "/service/rest/v1/status"]
        if product == "nexus" and fault == "forbidden"
        else ["/service/rest/v1/security/users"]
        if product == "nexus"
        else ["/api/v2.0/users/current"]
    )
    assert [args[3] for args, _kwargs in calls] == expected_paths
    assert all(kwargs["headers"]["Authorization"].startswith("Basic ") for _args, kwargs in calls)


@pytest.mark.parametrize("fault", ["transport", "unexpected_status"])
def test_nexus_inconclusive_anonymous_comparison_cannot_prove_pair(monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    calls = []

    def request(*args: Any, **kwargs: Any) -> Any:
        calls.append(kwargs)
        if len(calls) == 1:
            return 200, b'[{"userId":"alice"}]', {}, None
        return (0, b"", {}, "reset") if fault == "transport" else (503, b"", {}, None)

    monkeypatch.setattr(registry, "_http_request", request)
    valid, reason = registry._verify_registry_credential(
        "nexus", "qa", 8081, 1, "alice", "secret", None, anonymous_probe=None
    )
    assert valid is None and reason and reason.startswith("anonymous Nexus identity comparison unavailable")
    assert len(calls) == 2 and "headers" not in calls[1]


@pytest.mark.parametrize("fault", ["transport", "rejected", "forbidden", "invalid_json", "wrong_shape", "no_subject"])
def test_gitlab_registry_token_realm_faults_have_precise_tristate(monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    headers = {
        "www-authenticate": 'Bearer realm="https://gitlab.test/jwt/auth?existing=1",service="container_registry"'
    }
    responses = {
        "transport": (0, b"", {}, "reset"),
        "rejected": (401, b"{}", {}, None),
        "forbidden": (403, b"{}", {}, None),
        "invalid_json": (200, b"invalid", {}, None),
        "wrong_shape": (200, b"[]", {}, None),
        "no_subject": (200, b'{"token":"opaque"}', {}, None),
    }
    calls = []
    monkeypatch.setattr(
        registry, "_http_request_url", lambda *args, **kwargs: calls.append((args, kwargs)) or responses[fault]
    )
    valid, reason = registry._verify_registry_credential(
        "gitlab", "qa", 5000, 1, "alice", "secret", None, anonymous_probe=(401, b"", headers, None)
    )
    assert valid is (False if fault == "rejected" else None) and reason
    assert len(calls) == 1
    parsed = urlsplit(calls[0][0][0])
    assert parsed.scheme == "https" and parsed.netloc == "gitlab.test" and parsed.path == "/jwt/auth"
    assert parse_qs(parsed.query) == {"existing": ["1"], "service": ["container_registry"]}


@pytest.mark.parametrize("stage", ["login", "post", "identity"])
def test_gitlab_web_transport_failure_is_unverified(monkeypatch: pytest.MonkeyPatch, stage: str) -> None:
    calls = []
    form = b'<form action="/users/sign_in"><input name="authenticity_token" value="csrf"></form>'

    class Pool:
        def request_once(self, method: str, url: str, **kwargs: Any) -> HttpResponse:
            calls.append((method, url, kwargs))
            current = ["login", "post", "identity"][len(calls) - 1]
            if current == stage:
                return HttpResponse(0, b"", {}, error=f"{stage} reset")
            if current == "login":
                return HttpResponse(200, form, {"Set-Cookie": "_gitlab_session=session"})
            return HttpResponse(302, b"", {"location": "/"})

    ctx = NS(
        host="qa",
        port=80,
        args=NS(),
        lifecycle_state=gitlab.GitLabLifecycleState(http=Pool(), host="qa", port=80, scheme="http"),
    )
    valid, reason = gitlab.verify_gitlab_web_credentials(ctx, "alice", "secret")
    assert valid is None and reason == f"{stage} reset"
    assert len(calls) == {"login": 1, "post": 2, "identity": 3}[stage]
    assert ctx.lifecycle_state.web_auth_blocked is False


@pytest.mark.parametrize("fault", ["rate", "captcha", "redirect", "server", "rejected"])
def test_gitlab_web_post_barriers_stop_identity_and_repeat_attempts(
    monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    calls = []
    form = b'<form action="/users/sign_in"><input name="authenticity_token" value="csrf"></form>'
    responses = {
        "rate": HttpResponse(429, b"", {}),
        "captcha": HttpResponse(200, b'<div class="g-recaptcha"></div>', {}),
        "redirect": HttpResponse(302, b"", {"location": "https://identity.test/login"}),
        "server": HttpResponse(503, b"", {}),
        "rejected": HttpResponse(422, b"", {}),
    }

    class Pool:
        def request_once(self, method: str, url: str, **kwargs: Any) -> HttpResponse:
            calls.append((method, url))
            if method == "GET":
                return HttpResponse(200, form, {"Set-Cookie": "_gitlab_session=session"})
            return responses[fault]

    ctx = NS(
        host="qa",
        port=80,
        args=NS(),
        lifecycle_state=gitlab.GitLabLifecycleState(http=Pool(), host="qa", port=80, scheme="http"),
    )
    valid, reason = gitlab.verify_gitlab_web_credentials(ctx, "alice", "secret")
    assert valid is (False if fault == "rejected" else None) and reason and len(calls) == 2
    blocked = fault in {"rate", "captcha", "redirect"}
    assert ctx.lifecycle_state.web_auth_blocked is blocked
    if blocked:
        valid, reason = gitlab.verify_gitlab_web_credentials(ctx, "alice", "other")
        assert valid is None and reason and "attempts stopped" in reason and len(calls) == 2


@pytest.mark.parametrize("identity", [b"invalid", b'{"id":1,"username":"other","name":"Other","state":"active"}'])
def test_gitlab_web_success_redirect_still_requires_matching_identity(identity: bytes) -> None:
    calls = []
    form = b'<form action="/users/sign_in"><input name="authenticity_token" value="csrf"></form>'

    class Pool:
        def request_once(self, method: str, url: str, **kwargs: Any) -> HttpResponse:
            calls.append(kwargs)
            if len(calls) == 1:
                return HttpResponse(200, form, {"set-cookie": "_gitlab_session=initial"})
            if len(calls) == 2:
                return HttpResponse(302, b"", {"location": "/", "set-cookie": "_gitlab_session=rotated"})
            assert kwargs["headers"] == {"Cookie": "_gitlab_session=rotated"}
            return HttpResponse(200, identity, {})

    ctx = NS(
        host="qa",
        port=80,
        args=NS(),
        lifecycle_state=gitlab.GitLabLifecycleState(http=Pool(), host="qa", port=80, scheme="http"),
    )
    assert gitlab.verify_gitlab_web_credentials(ctx, "alice", "secret") == (
        None,
        "GitLab identity was not confirmed after login",
    )
    assert len(calls) == 3
