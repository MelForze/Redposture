"""A CSRF/session or proxy response does not reject a GitLab password."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.gitlab import actions

FORM = (
    b'<title>Sign in - GitLab</title><form action="/users/sign_in">'
    b'<input name="authenticity_token" value="csrf">'
    b'<input name="user[login]"><input name="user[password]" type="password"></form>'
)


def verify(response: HttpResponse, *, identity: bool = False) -> tuple[bool | None, str | None]:
    calls = []

    class Pool:
        def request_once(self, method: str, url: str, **options: Any) -> HttpResponse:
            calls.append((method, url, options))
            if len(calls) == 1:
                assert method == "GET"
                return HttpResponse(200, FORM, {"Set-Cookie": "_gitlab_session=before"})
            if len(calls) == 3:
                assert method == "GET" and url.endswith("/api/v4/user")
                if identity:
                    assert options["headers"]["Cookie"] == "_gitlab_session=after"
                    return HttpResponse(
                        200, json.dumps({"id": 7, "username": "alice", "name": "Alice", "state": "active"}).encode(), {}
                    )
                return HttpResponse(401, b'{"message":"401 Unauthorized"}', {})
            assert len(calls) == 2 and method == "POST"
            assert parse_qs(options["body"].decode()) == {
                "authenticity_token": ["csrf"],
                "user[login]": ["alice"],
                "user[password]": ["secret"],
            }
            assert options["headers"]["Cookie"] == "_gitlab_session=before"
            return response

    ctx = SimpleNamespace(
        host="qa",
        port=80,
        args=SimpleNamespace(timeout=1),
        lifecycle_state=actions.GitLabLifecycleState(http=Pool(), host="qa", port=80, scheme="http"),
    )
    result = actions.verify_gitlab_web_credentials(ctx, "alice", "secret")
    expected_calls = 3 if response.status == 200 and result[0] is not False else 2
    assert len(calls) == expected_calls and not ctx.lifecycle_state.web_auth_blocked
    return result


@pytest.mark.parametrize(
    "status,body",
    [
        (422, b"Can't verify CSRF token authenticity"),
        (422, b"The change you requested was rejected (422)."),
        (422, b"ActionController::InvalidAuthenticityToken"),
        (422, b""),
        (401, b"Unauthorized by upstream authentication proxy"),
        (200, FORM),
        (200, b'<form action="/users/sign_in"><input name="user[otp_attempt]"></form>'),
        (422, b'<script>const msg="Invalid Login or password.";</script>' + FORM),
        (200, b'<template><div class="flash-alert">Invalid Login or password.</div></template>' + FORM),
        (422, b"Help: Invalid Login or password. Contact your administrator."),
    ],
)
def test_form_or_generic_401_422_never_proves_a_wrong_password(status, body):
    valid, reason = verify(HttpResponse(status, body, {}))
    assert valid is None and reason
    assert ("identity was not confirmed" if status == 200 else "inconclusive") in reason


@pytest.mark.parametrize("status", [200, 401, 422])
@pytest.mark.parametrize("css", ["flash-alert", "gl-alert-danger", "alert-danger"])
def test_explicit_visible_gitlab_credential_rejection_remains_invalid(status, css):
    body = f'<div class="{css}">Invalid Login or password.</div>'.encode() + FORM
    assert verify(HttpResponse(status, body, {})) == (False, "GitLab login rejected")


def test_ambiguous_200_form_with_rotated_session_still_checks_the_actual_identity():
    assert verify(HttpResponse(200, FORM, {"Set-Cookie": "_gitlab_session=after"}), identity=True) == (True, None)
