from __future__ import annotations

import io
from datetime import timezone

import pytest
from urllib3 import HTTPResponse

from redposture_core.http_headers import custom_http_headers
from redposture_core.modules.clickhouse import actions


@pytest.fixture
def sdk_requests(monkeypatch):
    from clickhouse_connect.driver import httpclient
    from clickhouse_connect.driver.client import Client

    requests = []

    class Pool:
        def clear(self):
            pass

        def request(self, method, url, **kwargs):
            requests.append((method, url, dict(kwargs["headers"])))
            return HTTPResponse(status=200, body=io.BytesIO(b"ok"), preload_content=False)

    pool = Pool()
    monkeypatch.setattr(httpclient, "default_pool_manager", lambda: pool)

    def init(self, tz_source):
        self.server_tz = timezone.utc
        self.server_version = "24.8.14.39"
        self.server_settings = {}
        # Retain the installed SDK constructor and transport. Only metadata
        # parsing is replaced; a request is made during its initialization.
        self._raw_request(b"metadata", {}).close()

    monkeypatch.setattr(Client, "_init_common_settings", init)
    return requests


def test_installed_clickhouse_sdk_receives_headers_during_constructor(sdk_requests):
    with custom_http_headers([("authorization", "Bearer operator"), ("X-QA", "checked")]):
        client = actions._open_clickhouse_client("http", "qa.local", 8123, 5, "builtin", "builtin-pass", "default")
        with client.raw_stream("SELECT 1", fmt="Native"):
            pass
    assert len(sdk_requests) == 2
    for _, url, headers in sdk_requests:
        from urllib.parse import urlsplit

        assert urlsplit(url).hostname == "qa.local" and urlsplit(url).port == 8123
        assert {k.lower(): v for k, v in headers.items()}["authorization"] == "Bearer operator"
        assert sum(k.lower() == "authorization" for k in headers) == 1
        assert headers["X-QA"] == "checked"
    client.close()


def test_installed_sdk_lowercase_user_agent_overrides_its_default(sdk_requests):
    with custom_http_headers([("user-agent", "operator-agent"), ("authorization", "Bearer operator")]):
        client = actions._open_clickhouse_client("http", "qa.local", 8123, 5, "builtin", "builtin-pass", "default")
        with client.raw_stream("SELECT 1", fmt="Native"):
            pass
    for _, _, headers in sdk_requests:
        matching = [value for name, value in headers.items() if name.lower() == "user-agent"]
        assert matching == ["operator-agent"]
    client.close()


@pytest.mark.parametrize("authorization", ["Authorization", "authorization"])
def test_header_compatibility_snapshots_operator_and_overrides_request_auth(sdk_requests, authorization):
    from redposture_core.clients.clickhouse_http import create_http_client_with_headers

    headers = {authorization: "Bearer operator", "Cookie": "session=operator"}
    client = create_http_client_with_headers(
        {
            "interface": "http",
            "secure": False,
            "host": "qa.local",
            "port": 8123,
            "username": "builtin",
            "password": "builtin-pass",
            "database": "default",
        },
        headers,
    )
    headers[authorization] = "mutated"
    client._raw_request(b"query", {}, headers={"Authorization": "Basic other", "Cookie": "session=other"}).close()
    for _, _, sent in sdk_requests:
        assert {name.lower(): value for name, value in sent.items()}["authorization"] == "Bearer operator"
        assert sent["Cookie"] == "session=operator"
        assert sum(name.lower() == "authorization" for name in sent) == 1
    client.close()
