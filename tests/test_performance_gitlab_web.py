"""CSRF web-login peer is separate from API tokens and OCI access."""

from __future__ import annotations

import json
from urllib.parse import urlencode

import pytest

from scripts import performance_http_fixtures as fixtures


def request(method, path, headers=None, body=b"", *, valid=True, origin="http://qa.invalid"):
    reply = getattr(fixtures, "gitlab_web_reply", None)
    assert callable(reply), "missing CSRF/session-aware GitLab web peer"
    wire = reply(
        method,
        path,
        headers or {},
        body,
        valid_pair=("admin", "admin") if valid else None,
        limited=False,
        origin=origin,
    )
    head, _, payload = wire.partition(b"\r\n\r\n")
    fields = {
        k.lower(): v.strip()
        for line in head.split(b"\r\n")[1:]
        if (k := line.partition(b":")[0])
        for v in [line.partition(b":")[2]]
    }
    return int(head.split()[1]), fields, payload


def login(password="admin", *, csrf_ok=True, cookie_ok=True, valid=True):
    status, fields, html = request("GET", "/users/sign_in", valid=valid)
    from redposture_core.modules.gitlab.actions import _GitLabLoginForm

    form = _GitLabLoginForm()
    form.feed(html.decode())
    assert status == 200 and form.token
    cookie = fields[b"set-cookie"].split(b";", 1)[0]
    return request(
        "POST",
        "/users/sign_in",
        {
            b"cookie": cookie if cookie_ok else b"_gitlab_session=other",
            b"content-type": b"application/x-www-form-urlencoded",
        },
        urlencode(
            {
                "authenticity_token": form.token if csrf_ok else "other",
                "user[login]": "admin",
                "user[password]": password,
            }
        ).encode(),
        valid=valid,
    )


def test_valid_csrf_login_rotates_cookie_and_only_session_proves_identity():
    status, fields, _ = login()
    assert status == 302 and fields[b"location"] == b"/"
    cookie = fields[b"set-cookie"].split(b";", 1)[0]
    status, _, body = request("GET", "/api/v4/user", {b"cookie": cookie})
    assert status == 200 and json.loads(body)["username"] == "admin"
    assert request("GET", "/api/v4/user")[0] == 401
    assert request("GET", "/v2/", {b"cookie": cookie})[0] == 404


@pytest.mark.parametrize("valid,password", [(True, "incorrect"), (False, "admin")])
def test_complete_wrong_pair_has_explicit_rendered_credential_error(valid, password):
    status, fields, body = login(password, valid=valid)
    assert status == 422 and b"Invalid Login or password." in body
    assert b"flash-alert" in body and b"set-cookie" not in fields


@pytest.mark.parametrize("option", ["csrf_ok", "cookie_ok"])
def test_csrf_failure_is_distinct_from_a_wrong_password(option):
    status, _, body = login(**{option: False})
    assert status == 422 and b"CSRF" in body and b"Invalid Login or password" not in body


def test_session_is_bound_to_origin_and_does_not_turn_random_routes_into_success():
    _, fields, _ = login()
    cookie = fields[b"set-cookie"].split(b";", 1)[0]
    assert request("GET", "/api/v4/user", {b"cookie": cookie}, origin="http://another.invalid")[0] == 401
    assert request("POST", "/execute")[0] == 403
