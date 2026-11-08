"""Fixture controls must distinguish identity, permission and protocol errors."""

from __future__ import annotations

import base64
import json

import pytest

from scripts.performance_http_fixtures import GRAFANA_AUTH_SURFACES, grafana_reply, jenkins_reply


def get(path, pair=None, *, valid=("user", "password"), limited=False):
    headers = {b"authorization": b"Basic " + base64.b64encode(":".join(pair).encode())} if pair else {}
    reply = grafana_reply("GET", path, headers, b"", valid_pair=valid, limited=limited)
    assert reply is not None
    head, _, body = reply.partition(b"\r\n\r\n")
    return int(head.split(b" ")[1]), json.loads(body)


@pytest.mark.parametrize("pair", [None, ("user", "wrong"), ("other", "password")])
def test_anonymous_unknown_user_and_wrong_password_do_not_get_identity(pair):
    assert get("/api/user", pair)[0] == 401


def test_valid_identity_and_limited_permissions_are_independent():
    assert get("/api/user", ("user", "password"), limited=True) == (
        200,
        {"id": 1, "login": "user", "email": "profile@example.invalid", "orgId": 1},
    )
    assert get("/api/datasources", ("user", "password"), limited=True)[0] == 403
    status, sources = get("/api/datasources", ("user", "password"))
    assert status == 200 and {row["uid"] for row in sources} == {"metrics", "logs"}


def test_nonexistent_route_is_not_an_identity_or_an_inventory_success():
    assert get("/api/does-not-exist", ("user", "password"))[0] == 404


@pytest.mark.parametrize("login", [b"broken", b"[]", b'{"user":"user","password":"wrong"}'])
def test_post_is_not_automatically_an_auth_success(login):
    reply = grafana_reply("POST", "/login", {}, login, valid_pair=("user", "password"))
    assert reply is not None
    assert int(reply.split(b" ")[1]) in {400, 401}


def test_valid_login_cookie_and_invalid_control_are_distinct():
    valid = grafana_reply(
        "POST", "/login", {}, b'{"user":"user","password":"password"}', valid_pair=("user", "password")
    )
    assert valid is not None and valid.startswith(b"HTTP/1.1 200") and b"Set-Cookie:" in valid
    assert get("/api/user", ("user", "password"), valid=None)[0] == 401


@pytest.mark.parametrize("surface", GRAFANA_AUTH_SURFACES)
def test_grafana_fallback_fixture_has_independent_negative_controls_and_real_schema(surface):
    from redposture_core.modules.grafana import actions

    path = GRAFANA_AUTH_SURFACES[surface]
    kwargs = {"valid_pair": ("alice", "correct"), "auth_surface": surface}
    assert grafana_reply("GET", path, {}, b"", **kwargs).startswith(b"HTTP/1.1 401")
    correct = {b"authorization": b"Basic " + base64.b64encode(b"alice:correct")}
    wrong = {b"authorization": b"Basic " + base64.b64encode(b"alice:wrong")}
    assert grafana_reply("GET", path, wrong, b"", **kwargs).startswith(b"HTTP/1.1 401")
    reply = grafana_reply("GET", path, correct, b"", **kwargs)
    payload = reply.partition(b"\r\n\r\n")[2].decode()
    validator = {
        "user": actions._looks_like_grafana_user,
        "org": actions._looks_like_grafana_org,
        "ping": actions._looks_like_grafana_login_ping,
    }.get(surface, lambda body: actions._looks_like_grafana_auth_fallback(path, body))
    assert reply.startswith(b"HTTP/1.1 200") and validator(payload)
    for unavailable in list(GRAFANA_AUTH_SURFACES.values())[: list(GRAFANA_AUTH_SURFACES).index(surface)]:
        assert grafana_reply("GET", unavailable, correct, b"", **kwargs).startswith(b"HTTP/1.1 404")


def test_jenkins_auth_and_projection_are_independent_and_script_is_denied():
    headers = {b"authorization": b"Basic " + base64.b64encode(b"admin:pass")}
    kwargs = {"valid_pair": ("admin", "pass")}
    who = jenkins_reply("GET", "/whoAmI/api/json", headers, b"", **kwargs)
    assert json.loads(who.partition(b"\r\n\r\n")[2])["authenticated"] is True
    names = jenkins_reply("GET", "/api/json?tree=jobs[name]", headers, b"", **kwargs)
    data = json.loads(names.partition(b"\r\n\r\n")[2])
    assert len(data["jobs"]) == 3 and all(set(row) == {"name"} for row in data["jobs"])
    rich = jenkins_reply("GET", "/api/json?tree=jobs[name,color]", headers, b"", **kwargs)
    assert all(set(row) == {"name", "color"} for row in json.loads(rich.partition(b"\r\n\r\n")[2])["jobs"])
    denied = jenkins_reply("POST", "/scriptText", headers, b"any script", **kwargs)
    assert denied.startswith(b"HTTP/1.1 403")


def test_jenkins_limited_identity_is_real_but_job_read_is_denied():
    headers = {b"authorization": b"Basic " + base64.b64encode(b"admin:pass")}
    who = jenkins_reply("GET", "/whoAmI/api/json", headers, b"", valid_pair=("admin", "pass"), limited=True)
    assert json.loads(who.partition(b"\r\n\r\n")[2])["name"] == "admin"
    assert jenkins_reply("GET", "/api/json", headers, b"", valid_pair=("admin", "pass"), limited=True).startswith(
        b"HTTP/1.1 403"
    )
