"""Negative and edge scenarios for the Airflow REST client.

Auth-header precedence and construction, pool error normalization, unicode
request bodies, and defensive coercion of missing/None response fields.
"""

from __future__ import annotations

import base64
from types import SimpleNamespace

from redposture_core.clients import airflow_api


class _CapturePool:
    def __init__(self, *, status=200, body=b"", headers=None):
        self._status = status
        self._body = body
        self._headers = headers or {}
        self.calls: list[dict] = []

    def request(self, method, url, *, headers=None, body=None, response_size_cap=None):
        self.calls.append({"method": method, "url": url, "headers": dict(headers or {}), "body": body})
        return SimpleNamespace(status=self._status, body=self._body, headers=self._headers, error=None)


def _client(pool=None, **kw):
    return airflow_api.AirflowClient(pool or object(), scheme="http", host="h", port=8080, **kw)


# --- auth header precedence and construction ------------------------------


def test_bearer_takes_precedence_over_basic():
    client = _client(basic_user="u", basic_password="p", bearer_token="JWT")
    assert client._auth_header() == {"Authorization": "Bearer JWT"}


def test_basic_requires_both_user_and_password():
    assert _client(basic_user="u")._auth_header() == {}
    assert _client(basic_password="p")._auth_header() == {}


def test_no_creds_yields_empty_auth_header():
    assert _client()._auth_header() == {}


def test_basic_with_empty_password_still_builds_header():
    client = _client(basic_user="u", basic_password="")
    assert client._auth_header()["Authorization"] == "Basic " + base64.b64encode(b"u:").decode()


def test_basic_with_empty_user_still_builds_header():
    client = _client(basic_user="", basic_password="p")
    assert client._auth_header()["Authorization"] == "Basic " + base64.b64encode(b":p").decode()


def test_unauthenticated_get_omits_auth_even_with_creds():
    pool = _CapturePool(body=b"[]")
    _client(pool, basic_user="u", basic_password="p").get("/api/v1/dags", authed=False)
    assert "Authorization" not in pool.calls[0]["headers"]


def test_authed_get_includes_bearer_by_default():
    pool = _CapturePool(body=b"[]")
    _client(pool, bearer_token="T").get("/x")  # authed defaults to True
    assert pool.calls[0]["headers"]["Authorization"] == "Bearer T"


# --- transport / response normalization -----------------------------------


def test_pool_error_field_is_normalized_to_transport_error():
    class _ErrPool:
        def request(self, *a, **k):
            return SimpleNamespace(status=0, body=b"", headers={}, error="boom")

    resp = airflow_api.AirflowClient(_ErrPool(), scheme="http", host="h", port=8080).get("/x", authed=False)
    assert resp.http_status == 0 and resp.transport_error == "boom" and resp.json() is None


def test_raised_exception_is_normalized():
    class _BoomPool:
        def request(self, *a, **k):
            raise TimeoutError("timed out")

    resp = airflow_api.AirflowClient(_BoomPool(), scheme="http", host="h", port=8080).get("/x", authed=False)
    assert resp.http_status == 0 and "timed out" in (resp.transport_error or "")


def test_none_body_and_headers_coerced():
    class _NonePool:
        def request(self, *a, **k):
            return SimpleNamespace(status=204, body=None, headers=None, error=None)

    resp = airflow_api.AirflowClient(_NonePool(), scheme="http", host="h", port=8080).get("/x", authed=False)
    assert resp.body == b"" and resp.headers == {} and resp.json() is None


def test_response_headers_and_body_preserved():
    pool = _CapturePool(status=200, body=b"hello", headers={"X-Test": "1"})
    resp = _client(pool).get("/x", authed=False)
    assert resp.http_status == 200 and resp.body == b"hello" and resp.headers == {"X-Test": "1"}


def test_base_url_composition():
    client = airflow_api.AirflowClient(object(), scheme="https", host="airflow.local", port=8443)
    assert client.base_url == "https://airflow.local:8443"
    assert client.port == 8443 and isinstance(client.port, int)


# --- request shaping -------------------------------------------------------


def test_post_json_body_is_utf8_not_ascii_escaped():
    pool = _CapturePool(body=b"{}")
    _client(pool).post_json("/auth/token", {"username": "админ", "password": "пароль"})
    body = pool.calls[0]["body"]
    assert "админ".encode() in body and "пароль".encode() in body


def test_post_json_sets_content_type_and_is_unauthenticated_by_default():
    pool = _CapturePool(body=b"{}")
    _client(pool, basic_user="u", basic_password="p").post_json("/auth/token", {"a": 1})
    call = pool.calls[0]
    assert call["method"] == "POST"
    assert call["headers"]["Content-Type"] == "application/json"
    assert "Authorization" not in call["headers"]


def test_get_url_is_scheme_host_port_path():
    pool = _CapturePool(body=b"[]")
    _client(pool).get("/api/v1/version", authed=False)
    assert pool.calls[0]["url"] == "http://h:8080/api/v1/version"
