from __future__ import annotations

import base64

from redposture_core.clients import airflow_api


class _FakePool:
    def __init__(self, status=200, body=b"", headers=None):
        self._status = status
        self._body = body
        self._headers = headers or {}
        self.calls: list[dict] = []

    def request(self, method, url, *, headers=None, body=None, timeout=None, response_size_cap=10 * 1024 * 1024):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": headers or {},
                "body": body,
                "response_size_cap": response_size_cap,
            }
        )
        return _Resp(self._status, self._body, self._headers)


class _Resp:
    def __init__(self, status, body, headers):
        self.status = status
        self.body = body
        self.headers = headers
        self.error = None


_FAB_FORM = (
    b'<link href="/static/appbuilder/css/ab.css" rel="stylesheet">'
    b'<form name="login" method="post" action="">'
    b'<input name="csrf_token" value="csrf123">'
    b'<input name="username"><input name="password" type="password"></form>'
)


class _FabPool:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request_once(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.responses.pop(0)


def _fab_response(status, body=b"", headers=None):
    response = _Resp(status, body, headers or {})
    response.truncated = False
    return response


def test_fab_login_proves_identity_or_explicit_rejection_without_post_replay():
    first = _fab_response(200, _FAB_FORM, {"Content-Type": "text/html", "Set-Cookie": "session=one; HttpOnly"})
    for destination, page, expected in (
        ("/airflow/home", b'<a href="/logout/">Log Out</a>', "valid"),
        (
            "/airflow/login/?next=%2Fhome",
            _FAB_FORM + b'<div class="alert alert-warning">Invalid login. Please try again.</div>',
            "invalid",
        ),
    ):
        pool = _FabPool(
            [
                first,
                _fab_response(302, headers={"Location": destination, "Set-Cookie": "session=two; HttpOnly"}),
                _fab_response(200, page),
            ]
        )
        client = airflow_api.AirflowClient(
            pool, scheme="https", host="airflow.example", port=8443, base_path="/airflow"
        )
        assert client.verify_fab_login("admin", "p&ss") == expected
        assert [call[0] for call in pool.calls] == ["GET", "POST", "GET"]
        assert pool.calls[1][2]["headers"]["Cookie"] == "session=one"
        assert b"password=p%26ss" in pool.calls[1][2]["body"]
        assert pool.calls[2][2]["headers"]["Cookie"] == "session=two"


def test_fab_login_rejects_sso_and_cross_origin_action_without_post():
    for body in (
        b'<form name="login" method="post"><input name="csrf_token" value="csrf123"></form>',
        _FAB_FORM.replace(b'action=""', b'action="https://idp.example/login"'),
    ):
        pool = _FabPool([_fab_response(200, body, {"Content-Type": "text/html", "Set-Cookie": "session=one"})])
        client = airflow_api.AirflowClient(pool, scheme="http", host="airflow.example", port=8080)
        assert client.verify_fab_login("admin", "pass") == "unverified"
        assert [call[0] for call in pool.calls] == ["GET"]


def test_fab_login_does_not_treat_generic_redirect_as_success_or_failure():
    pool = _FabPool(
        [
            _fab_response(200, _FAB_FORM, {"Content-Type": "text/html", "Set-Cookie": "session=one"}),
            _fab_response(302, headers={"Location": "https://idp.example/home"}),
        ]
    )
    client = airflow_api.AirflowClient(pool, scheme="http", host="airflow.example", port=8080)
    assert client.verify_fab_login("admin", "pass") == "unverified"
    assert [call[0] for call in pool.calls] == ["GET", "POST"]


def test_fab_login_does_not_inherit_public_home_or_stale_session():
    for post_headers in ({"Location": "/home/"}, {"Location": "/home", "Set-Cookie": "session=one"}):
        pool = _FabPool(
            [
                _fab_response(200, _FAB_FORM, {"Content-Type": "text/html", "Set-Cookie": "session=one"}),
                _fab_response(302, headers=post_headers),
                _fab_response(200, b'<a href="/logout/">Log Out</a>'),
            ]
        )
        client = airflow_api.AirflowClient(pool, scheme="http", host="airflow.example", port=8080)
        assert client.verify_fab_login("admin", "pass") == "unverified"


def test_fab_login_requires_rejection_flash_not_static_copy():
    pool = _FabPool(
        [
            _fab_response(200, _FAB_FORM, {"Content-Type": "text/html", "Set-Cookie": "session=one"}),
            _fab_response(302, headers={"Location": "/login/"}),
            _fab_response(200, _FAB_FORM + b"Invalid login. Please try again."),
        ]
    )
    client = airflow_api.AirflowClient(pool, scheme="http", host="airflow.example", port=8080)
    assert client.verify_fab_login("admin", "pass") == "unverified"


def test_get_unauthenticated_has_no_auth_header():
    pool = _FakePool(200, b'{"version":"2.9.3"}')
    client = airflow_api.AirflowClient(pool, scheme="http", host="h", port=8080)
    resp = client.get("/api/v1/version", authed=False)
    assert resp.http_status == 200
    assert resp.json() == {"version": "2.9.3"}
    assert "Authorization" not in pool.calls[0]["headers"]
    assert pool.calls[0]["url"] == "http://h:8080/api/v1/version"


def test_get_with_basic_auth_sets_header():
    pool = _FakePool(200, b"[]")
    client = airflow_api.AirflowClient(
        pool, scheme="http", host="h", port=8080, basic_user="airflow", basic_password="airflow"
    )
    client.get("/api/v1/dags")
    sent = pool.calls[0]["headers"]["Authorization"]
    assert sent == "Basic " + base64.b64encode(b"airflow:airflow").decode()


def test_get_with_bearer_token_sets_header():
    pool = _FakePool(200, b"[]")
    client = airflow_api.AirflowClient(pool, scheme="https", host="h", port=8443, bearer_token="JWT123")
    client.get("/api/v2/dags")
    assert pool.calls[0]["headers"]["Authorization"] == "Bearer JWT123"
    assert pool.calls[0]["url"] == "https://h:8443/api/v2/dags"


def test_post_json_sends_body_and_content_type_unauthenticated():
    pool = _FakePool(200, b'{"access_token":"tok","token_type":"Bearer"}')
    client = airflow_api.AirflowClient(pool, scheme="http", host="h", port=8080)
    resp = client.post_json("/auth/token", {"username": "airflow", "password": "airflow"})
    call = pool.calls[0]
    assert call["method"] == "POST"
    assert call["headers"]["Content-Type"] == "application/json"
    assert b'"username"' in call["body"] and b'"password"' in call["body"]
    assert "Authorization" not in call["headers"]  # token exchange carries creds in body
    assert resp.json()["access_token"] == "tok"


def test_transport_error_normalized():
    class _BoomPool:
        def request(self, *a, **k):
            raise OSError("connection refused")

    client = airflow_api.AirflowClient(_BoomPool(), scheme="http", host="h", port=8080)
    resp = client.get("/api/v1/version", authed=False)
    assert resp.http_status == 0
    assert resp.transport_error and "connection refused" in resp.transport_error
    assert resp.json() is None


def test_get_log_passes_accept_header_and_response_cap():
    pool = _FakePool(200, b'{"content":"log"}')
    client = airflow_api.AirflowClient(pool, scheme="http", host="h", port=8080)
    client.get(
        "/api/v1/dags/d/dagRuns/r/taskInstances/t/logs/1",
        extra_headers={"Accept": "application/json"},
        response_size_cap=512,
    )
    assert pool.calls[0]["headers"]["Accept"] == "application/json"
    assert pool.calls[0]["response_size_cap"] == 512
