from __future__ import annotations

import http.client
from typing import Any

import pytest

from redposture_core import scanner


class _DummyPool:
    def __init__(self, results: list[tuple[int | None, bytes, str | None, BaseException | None]]) -> None:
        self._results = list(results)
        self.calls: list[tuple[str, float]] = []
        self.closed = False

    def get(self, url: str, timeout: float) -> tuple[int | None, bytes, str | None, BaseException | None]:
        self.calls.append((url, timeout))
        if not self._results:
            raise AssertionError("unexpected extra pooled request")
        return self._results.pop(0)

    def close(self) -> None:
        self.closed = True


def test_http_get_text_retries_http_exception_with_active_pool(monkeypatch: pytest.MonkeyPatch) -> None:
    sleep_calls: list[float] = []
    pool = _DummyPool(
        [
            (None, b"", None, http.client.RemoteDisconnected("first failure")),
            (200, b"ok", "text/plain", None),
        ]
    )

    monkeypatch.setattr("redposture_core.scanner.time.sleep", sleep_calls.append)

    with scanner._activate_http_pool(pool):  # type: ignore[arg-type]
        status, body = scanner.http_get_text("http://example.test/metrics", timeout=1.5, retries=1)

    assert status == 200
    assert body == "ok"
    assert len(pool.calls) == 2
    assert sleep_calls == [pytest.approx(0.2)]
    assert pool.closed is True


def test_http_get_details_reports_error_after_pooled_http_exception_retries_exhausted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sleep_calls: list[float] = []
    pool = _DummyPool(
        [
            (None, b"", None, http.client.CannotSendRequest("boom-1")),
            (None, b"", None, http.client.CannotSendRequest("boom-2")),
        ]
    )

    monkeypatch.setattr("redposture_core.scanner.time.sleep", sleep_calls.append)

    with scanner._activate_http_pool(pool):  # type: ignore[arg-type]
        result = scanner.http_get_details("http://example.test/debug/vars", timeout=2.0, retries=1)

    assert result["status"] is None
    assert result["body"] == ""
    assert "boom-2" in str(result["error"])
    assert len(pool.calls) == 2
    assert sleep_calls == [pytest.approx(0.2)]
    assert pool.closed is True


def test_activate_http_pool_restores_previous_pool() -> None:
    previous = _DummyPool([])
    replacement = _DummyPool([])
    scanner._ACTIVE_HTTP_POOL = previous

    with scanner._activate_http_pool(replacement):  # type: ignore[arg-type]
        assert scanner._ACTIVE_HTTP_POOL is replacement

    assert scanner._ACTIVE_HTTP_POOL is previous
    assert replacement.closed is True
    scanner._ACTIVE_HTTP_POOL = None


def test_http_get_text_without_pool_does_not_retry_http_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    call_counter = {"count": 0}

    def fake_urlopen(*args: Any, **kwargs: Any) -> Any:
        _ = (args, kwargs)
        call_counter["count"] += 1
        raise http.client.RemoteDisconnected("plain-http-failure")

    monkeypatch.setattr("redposture_core.scanner.urllib.request.urlopen", fake_urlopen)

    with pytest.raises(http.client.RemoteDisconnected):
        scanner.http_get_text("http://example.test/metrics", timeout=1.0, retries=3)

    assert call_counter["count"] == 1
