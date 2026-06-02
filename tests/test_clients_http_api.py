from __future__ import annotations

import urllib.error
from typing import Any

from redposture_core.clients.http_api import HttpApiClient, HttpClientConfig, normalize_http_error


class _FakeResponse:
    status = 200

    def __init__(self, body: bytes = b'{"ok":true}', headers: dict[str, str] | None = None) -> None:
        self._body = body
        self.headers = headers or {"Content-Type": "application/json"}

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def close(self) -> None:
        return None

    def read(self, _size: int = -1) -> bytes:
        return self._body

    def getcode(self) -> int:
        return int(self.status)


class _FakeOpener:
    def __init__(self, result: Any) -> None:
        self.result = result
        self.requests: list[Any] = []

    def open(self, req: Any, timeout: float) -> Any:
        self.requests.append((req, timeout))
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


def test_http_api_client_get_success(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    opener = _FakeOpener(_FakeResponse(b'{"status":"ok"}', {"X-Test": "1"}))
    monkeypatch.setattr("redposture_core.clients.http_api.urllib.request.urlopen", opener.open)

    client = HttpApiClient(HttpClientConfig(timeout=2.5))
    response = client.get("http://127.0.0.1:8080/api", headers={"Accept": "application/json"})

    assert response.status == 200
    assert response.json() == {"status": "ok"}
    assert response.headers["X-Test"] == "1"
    req, timeout = opener.requests[0]
    assert req.full_url == "http://127.0.0.1:8080/api"
    assert req.get_method() == "GET"
    assert timeout == 2.5
    assert req.get_header("Accept") == "application/json"


def test_http_api_client_post_json_and_response_cap(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    opener = _FakeOpener(_FakeResponse(b"abcdef"))
    monkeypatch.setattr("redposture_core.clients.http_api.urllib.request.urlopen", opener.open)

    client = HttpApiClient(HttpClientConfig(response_size_cap=3))
    response = client.post("http://127.0.0.1:8080/api", json_body={"a": 1})

    assert response.body == b"abc"
    req, _timeout = opener.requests[0]
    assert req.data == b'{"a":1}'
    assert req.get_header("Content-type") == "application/json"


def test_http_api_client_http_error_is_response(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    error = urllib.error.HTTPError(
        "http://127.0.0.1/api",
        403,
        "Forbidden",
        {"Content-Type": "text/plain"},
        _FakeResponse(b"denied"),
    )
    opener = _FakeOpener(error)
    monkeypatch.setattr("redposture_core.clients.http_api.urllib.request.urlopen", opener.open)

    response = HttpApiClient().get("http://127.0.0.1/api")

    assert response.status == 403
    assert response.body == b"denied"
    assert response.error is None


def test_http_api_client_transport_error_is_normalized(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    opener = _FakeOpener(urllib.error.URLError("[Errno 111] Connection refused"))
    monkeypatch.setattr("redposture_core.clients.http_api.urllib.request.urlopen", opener.open)

    response = HttpApiClient(HttpClientConfig(retries=1, backoff=0)).get("http://127.0.0.1/api")

    assert response.status == 0
    assert "Connection refused" in str(response.error)
    assert normalize_http_error(urllib.error.URLError("timed out"))
