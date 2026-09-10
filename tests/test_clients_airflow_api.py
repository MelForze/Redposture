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
        self.calls.append({"method": method, "url": url, "headers": headers or {}, "body": body})
        return _Resp(self._status, self._body, self._headers)


class _Resp:
    def __init__(self, status, body, headers):
        self.status = status
        self.body = body
        self.headers = headers
        self.error = None


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
