from __future__ import annotations

import errno
import socket
import urllib.error
from typing import Any

import pytest

from redposture_core.exporters import http_client, http_pool


class _Response:
    def __init__(self, status: int = 200, body: bytes = b"body", headers: dict[str, str] | None = None) -> None:
        self.status = status
        self._body = body
        self.headers = headers or {"Content-Type": "text/plain"}

    def __enter__(self):
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            return self._body
        return self._body[:size]

    def close(self) -> None:
        return None


class _URLopener:
    def __init__(self, *results: Any) -> None:
        self.results = list(results)
        self.calls = 0

    def __call__(self, *_args: Any, **_kwargs: Any) -> Any:
        self.calls += 1
        result = self.results.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result


def test_http_get_text_and_details_cover_urlopen_error_paths() -> None:
    assert http_client.retry_delay(0) == pytest.approx(0.2)
    assert http_client.retry_delay(10) == pytest.approx(1.5)
    assert http_client.should_retry_http_exception(TimeoutError("timeout")) is True
    assert http_client.should_retry_http_exception(OSError(errno.EINTR, "interrupted")) is True
    assert http_client.should_retry_http_exception(OSError(errno.ECONNREFUSED, "refused")) is False
    assert http_client.unwrap_network_error(urllib.error.URLError(TimeoutError("timeout"))).args[0] == "timeout"

    http_error = urllib.error.HTTPError(
        "http://example.test/path",
        404,
        "not found",
        {"Content-Type": "text/plain"},
        _Response(404, b"missing"),
    )
    status, body = http_client.http_get_text(
        "http://example.test/path",
        timeout=1.0,
        retries=0,
        urlopen_fn=_URLopener(http_error),
    )
    assert (status, body) == (404, "missing")

    details = http_client.http_get_details(
        "http://example.test/path",
        timeout=1.0,
        retries=0,
        max_bytes=3,
        urlopen_fn=_URLopener(_Response(200, b"abcdef", {"Content-Type": "text/custom"})),
        monotonic_fn=iter([1.0, 1.2]).__next__,
    )
    assert details["status"] == 200
    assert details["body"] == "abc"
    assert details["truncated"] is True
    assert details["content_type"] == "text/custom"

    failures = _URLopener(urllib.error.URLError(TimeoutError("timed out")), _Response(200, b"ok"))
    sleeps: list[float] = []
    status, body = http_client.http_get_text(
        "http://example.test/path",
        timeout=1.0,
        retries=1,
        urlopen_fn=failures,
        sleep_fn=sleeps.append,
    )
    assert (status, body) == (200, "ok")
    assert sleeps == [pytest.approx(0.2)]


def test_http_client_retry_classifier_and_final_error_paths() -> None:
    temporary_dns = socket.gaierror(getattr(socket, "EAI_AGAIN", -3), "temporary")
    permanent_dns = socket.gaierror(getattr(socket, "EAI_NONAME", -2), "not found")
    assert http_client.should_retry_http_exception(temporary_dns) is True
    assert http_client.should_retry_http_exception(permanent_dns) is False
    assert http_client.should_retry_http_exception(RuntimeError("no retry")) is False

    opener = _URLopener(OSError(errno.ECONNREFUSED, "refused"))
    with pytest.raises(OSError):
        http_client.http_get_text("http://example.test/path", 1.0, retries=1, urlopen_fn=opener)
    assert opener.calls == 1

    retrying_opener = _URLopener(OSError(errno.EINTR, "interrupted"), OSError(errno.ECONNREFUSED, "refused"))
    sleeps: list[float] = []
    details = http_client.http_get_details(
        "http://example.test/path",
        1.0,
        retries=1,
        urlopen_fn=retrying_opener,
        sleep_fn=sleeps.append,
        monotonic_fn=iter([1.0, 1.1, 2.0, 2.2]).__next__,
    )
    assert details["status"] is None
    assert "refused" in details["error"]
    assert sleeps == [pytest.approx(0.2)]


def test_http_get_details_http_error_truncates_body_without_headers() -> None:
    http_error = urllib.error.HTTPError(
        "http://example.test/path",
        503,
        "unavailable",
        None,
        _Response(503, b"service unavailable"),
    )
    details = http_client.http_get_details(
        "http://example.test/path",
        1.0,
        retries=0,
        max_bytes=7,
        urlopen_fn=_URLopener(http_error),
        monotonic_fn=iter([10.0, 10.25]).__next__,
    )
    assert details == {
        "status": 503,
        "body": "service",
        "content_type": None,
        "elapsed_ms": 250,
        "truncated": True,
        "error": None,
    }


def test_http_connection_pool_target_release_and_compat_paths(monkeypatch) -> None:
    with pytest.raises(ValueError):
        http_pool.HTTPConnectionPool._target_from_url("https://example.test/")
    with pytest.raises(ValueError):
        http_pool.HTTPConnectionPool._target_from_url("http:///missing-host")
    assert http_pool.HTTPConnectionPool._target_from_url("http://example.test:8080/a?b=1") == (
        "example.test",
        8080,
        "/a?b=1",
    )

    class FakeHTTPResponse:
        status = 200
        will_close = False

        def __init__(self, body: bytes = b"abcdef") -> None:
            self.body = body

        def read(self, size: int = -1) -> bytes:
            return self.body if size < 0 else self.body[:size]

        def getheader(self, name: str) -> str | None:
            return "text/plain" if name == "Content-Type" else None

    class FakeConnection:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            self.host = host
            self.port = port
            self.timeout = timeout
            self.closed = False
            self.requests: list[tuple[str, str]] = []

        def request(self, method: str, path: str, headers: dict[str, str]) -> None:
            self.requests.append((method, path))

        def getresponse(self) -> FakeHTTPResponse:
            return FakeHTTPResponse()

        def close(self) -> None:
            self.closed = True

    created: list[FakeConnection] = []

    def fake_connection(host: str, port: int, timeout: float) -> FakeConnection:
        conn = FakeConnection(host, port, timeout)
        created.append(conn)
        return conn

    monkeypatch.setattr(http_pool.http.client, "HTTPConnection", fake_connection)
    pool = http_pool.HTTPConnectionPool(max_idle_total=1, max_idle_per_host=1)
    status, raw, content_type, error, truncated = pool.get("http://example.test/data", 1.0, max_bytes=3)
    assert status == 200
    assert raw == b"abc"
    assert content_type == "text/plain"
    assert error is None
    assert truncated is True
    assert pool._idle_total == 1

    old = created[0]
    new = FakeConnection("other.test", 80, 1.0)
    pool._release("other.test", 80, new, True)
    assert old.closed is True
    assert pool._idle_total == 1
    pool.close()
    assert pool._idle_total == 0

    assert http_pool.pool_get_compat(
        type("P", (), {"get": lambda self, url, timeout: (200, b"ok", "text", None)})(), "http://x", 1.0
    ) == (200, b"ok", "text", None, False)
    with pytest.raises(ValueError):
        http_pool.pool_get_compat(type("P", (), {"get": lambda self, url, timeout: (1, 2, 3)})(), "http://x", 1.0)


def test_http_connection_pool_close_error_and_exception_paths(monkeypatch) -> None:
    class CloseRaises:
        def __init__(self) -> None:
            self.timeout = None

        def request(self, *_args: object, **_kwargs: object) -> None:
            raise http_pool.http.client.HTTPException("bad response")

        def close(self) -> None:
            raise OSError("close failed")

    monkeypatch.setattr(http_pool.http.client, "HTTPConnection", lambda *_a, **_k: CloseRaises())
    pool = http_pool.HTTPConnectionPool(max_idle_total=1, max_idle_per_host=1)
    status, raw, content_type, error, truncated = pool.get("http://example.test/metrics", 1.0)
    assert status is None
    assert raw == b""
    assert content_type is None
    assert isinstance(error, http_pool.http.client.HTTPException)
    assert truncated is False

    reusable = CloseRaises()
    pool._release("example.test", 80, reusable, True)
    duplicate = CloseRaises()
    pool._release("example.test", 80, duplicate, True)
    assert pool._idle_total == 1
    pool.close()
    assert pool._idle_total == 0

    non_reusable = CloseRaises()
    pool._release("example.test", 80, non_reusable, False)


def test_activate_http_pool_restores_previous_and_http_client_pooled_paths() -> None:
    class FakePool:
        def __init__(self, *results: tuple[int | None, bytes, str | None, BaseException | None, bool]) -> None:
            self.results = list(results)
            self.calls = 0

        def get(
            self, *_args: object, **_kwargs: object
        ) -> tuple[int | None, bytes, str | None, BaseException | None, bool]:
            self.calls += 1
            return self.results.pop(0)

        def close(self) -> None:
            return None

    previous = FakePool((200, b"previous", "text/plain", None, False))
    replacement = FakePool((200, b"ok", "text/plain", None, False))

    with http_pool.activate_http_pool(previous):
        assert http_pool.get_active_http_pool() is previous
        with http_pool.activate_http_pool(replacement):
            assert http_pool.get_active_http_pool() is replacement
            assert http_client.http_get_text("http://example.test/metrics", 1.0) == (200, "ok")
        assert http_pool.get_active_http_pool() is previous
    assert http_pool.get_active_http_pool() is None

    retry_pool = FakePool(
        (None, b"", None, http_pool.http.client.HTTPException("temporary"), False),
        (200, b"ok", "text/plain", None, False),
    )
    sleeps: list[float] = []
    with http_pool.activate_http_pool(retry_pool):
        assert http_client.http_get_text("http://example.test/metrics", 1.0, retries=1, sleep_fn=sleeps.append) == (
            200,
            "ok",
        )
    assert sleeps == [pytest.approx(0.2)]

    error_pool = FakePool((None, b"", None, OSError("hard failure"), False))
    with http_pool.activate_http_pool(error_pool):
        details = http_client.http_get_details(
            "http://example.test/metrics",
            1.0,
            retries=0,
            monotonic_fn=iter([2.0, 2.5]).__next__,
        )
    assert details["status"] is None
    assert details["error"] == "hard failure"
    assert details["elapsed_ms"] == 500
