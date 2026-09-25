"""At-most-once contracts for requests that may change remote state."""

from __future__ import annotations

import pytest

from redposture_core.clients.http_api import HttpApiClient, HttpClientConfig, HttpRequest, HttpResponse
from redposture_core.clients.http_session import HttpSessionPool


def _transport_failure(request: HttpRequest) -> HttpResponse:
    return HttpResponse(
        status=0,
        body=b"",
        headers={},
        error="connection timeout",
        request_url=request.url,
        final_url=request.url,
    )


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
@pytest.mark.parametrize("client_kind", ["api", "pool"])
def test_mutating_http_requests_are_never_replayed_after_ambiguous_transport_failure(
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    client_kind: str,
) -> None:
    calls: list[str] = []
    if client_kind == "api":
        api_client = HttpApiClient(HttpClientConfig(retries=4, backoff=0))

        def send_once(_self: object, request: HttpRequest, *, timeout: float | None = None) -> HttpResponse:
            _ = timeout
            calls.append(request.method)
            return _transport_failure(request)

        monkeypatch.setattr(HttpApiClient, "_send_once", send_once)
        response = api_client.request(method, "http://127.0.0.1:1/action", body=b"payload")
    else:
        pool = HttpSessionPool(timeout=0.01, retries=4)

        def request_once(
            request_method: str,
            request_url: str,
            **_kwargs: object,
        ) -> tuple[HttpResponse, BaseException, bool]:
            calls.append(request_method)
            return _transport_failure(HttpRequest(request_method, request_url)), TimeoutError("timeout"), False

        monkeypatch.setattr(pool, "_request_once", request_once)
        response = pool.request(method, "http://127.0.0.1:1/action", body=b"payload")
        pool.close()

    assert response.error == "connection timeout"
    assert calls == [method]


@pytest.mark.parametrize("method", ["GET", "HEAD"])
@pytest.mark.parametrize("client_kind", ["api", "pool"])
def test_read_only_http_requests_retain_bounded_transport_retries(
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    client_kind: str,
) -> None:
    calls: list[str] = []
    if client_kind == "api":
        api_client = HttpApiClient(HttpClientConfig(retries=2, backoff=0))

        def send_once(_self: object, request: HttpRequest, *, timeout: float | None = None) -> HttpResponse:
            _ = timeout
            calls.append(request.method)
            return _transport_failure(request)

        monkeypatch.setattr(HttpApiClient, "_send_once", send_once)
        api_client.request(method, "http://127.0.0.1:1/read")
    else:
        pool = HttpSessionPool(timeout=0.01, retries=2)

        def request_once(
            request_method: str, request_url: str, **_kwargs: object
        ) -> tuple[HttpResponse, BaseException, bool]:
            calls.append(request_method)
            return _transport_failure(HttpRequest(request_method, request_url)), TimeoutError("timeout"), False

        monkeypatch.setattr(pool, "_request_once", request_once)
        monkeypatch.setattr("redposture_core.clients.http_session.time.sleep", lambda _delay: None)
        pool.request(method, "http://127.0.0.1:1/read")
        pool.close()

    assert calls == [method, method, method]


@pytest.mark.parametrize(
    ("status", "expected_method", "expected_body"),
    [
        (301, "GET", None),
        (302, "GET", None),
        (303, "GET", None),
        (307, "POST", b"payload"),
        (308, "POST", b"payload"),
    ],
)
def test_redirect_replay_semantics_are_explicit_and_independent_from_failure_retries(
    status: int,
    expected_method: str,
    expected_body: bytes | None,
) -> None:
    from redposture_core.clients.http_redirects import follow_redirects

    calls: list[tuple[str, str, bytes | None]] = []

    def send(method: str, url: str, _headers: dict[str, str], body: bytes | None) -> HttpResponse:
        calls.append((method, url, body))
        if len(calls) == 1:
            return HttpResponse(status, b"", {"Location": "/final"})
        return HttpResponse(200, b"ok", {})

    response = follow_redirects(send, "POST", "http://example.test/start", body=b"payload")

    assert response.status == 200
    assert calls == [
        ("POST", "http://example.test/start", b"payload"),
        (expected_method, "http://example.test/final", expected_body),
    ]


def test_mutating_failure_contract_does_not_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    sleeps: list[float] = []
    calls: list[HttpRequest] = []
    client = HttpApiClient(HttpClientConfig(retries=10, backoff=10))

    def send_once(_self: object, request: HttpRequest, *, timeout: float | None = None) -> HttpResponse:
        _ = timeout
        calls.append(request)
        return _transport_failure(request)

    monkeypatch.setattr(HttpApiClient, "_send_once", send_once)
    monkeypatch.setattr("redposture_core.clients.http_api.time.sleep", sleeps.append)
    client.post("http://127.0.0.1:1/action", json_body={"enabled": True})

    assert len(calls) == 1
    assert sleeps == []
