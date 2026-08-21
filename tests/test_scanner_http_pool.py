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

    with scanner._activate_http_pool(pool):
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

    with scanner._activate_http_pool(pool):
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

    with scanner._activate_http_pool(replacement):
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


def test_http_pool_get_propagates_keyboard_interrupt() -> None:
    pool = scanner._HTTPConnectionPool()

    class _InterruptConn:
        def __init__(self) -> None:
            self.timeout = None

        def request(self, *_args: Any, **_kwargs: Any) -> None:
            raise KeyboardInterrupt("stop")

        def close(self) -> None:
            return

    conn = _InterruptConn()
    releases: list[bool] = []

    def fake_acquire(_scheme: str, _host: str, _port: int, _timeout: float) -> _InterruptConn:
        return conn

    def fake_release(_scheme: str, _host: str, _port: int, _conn: _InterruptConn, reusable: bool) -> None:
        releases.append(reusable)

    pool._acquire = fake_acquire  # type: ignore[method-assign, assignment]
    pool._release = fake_release  # type: ignore[method-assign, assignment]

    with pytest.raises(KeyboardInterrupt, match="stop"):
        pool.get("http://example.test/metrics", timeout=1.0)

    assert releases == [False]


def test_scan_exporter_presence_activates_http_pool(monkeypatch: pytest.MonkeyPatch) -> None:
    created_pools: list[Any] = []

    class _ScanPool:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            self.closed = False
            created_pools.append(self)

        def close(self) -> None:
            self.closed = True

    def fake_scan_task(
        host: str,
        port: int,
        _exporters: list[dict[str, Any]],
        _timeout: float,
        _retries: int,
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        assert scanner._ACTIVE_HTTP_POOL is created_pools[0]
        return (
            {
                "timestamp": "now",
                "host": host,
                "exporter": "unknown",
                "port": port,
                "url": f"http://{host}:{port}/metrics",
                "detected": False,
                "method": "none",
                "status": 404,
                "marker_hit": None,
                "elapsed_ms": 1,
                "content_type": "text/plain",
                "error": None,
                "truncated": False,
                "body": "",
            },
            None,
        )

    monkeypatch.setattr("redposture_core.scanner._HTTPConnectionPool", _ScanPool)
    monkeypatch.setattr("redposture_core.scanner._scan_presence_port_task", fake_scan_task)

    checks, found, by_host = scanner.scan_exporter_presence(
        hosts=["127.0.0.1"],
        timeout=1.0,
        output_path=None,
        output_format="json",
        logger=None,
        emit_line=None,
        workers=1,
        retries=0,
        discovery_exporters=[{"name": "node_exporter", "port": 9100, "markers": ("node_exporter_build_info",)}],
        custom_ports=[9100],
    )

    assert checks == 1
    assert found == 0
    assert by_host["127.0.0.1"] == []
    assert len(created_pools) == 1
    assert created_pools[0].closed is True
    assert scanner._ACTIVE_HTTP_POOL is None


def test_scan_exporter_presence_restores_previous_pool_on_emit_error(monkeypatch: pytest.MonkeyPatch) -> None:
    created_pools: list[Any] = []

    class _ScanPool:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            self.closed = False
            created_pools.append(self)

        def close(self) -> None:
            self.closed = True

    def fake_scan_task(
        host: str,
        port: int,
        _exporters: list[dict[str, Any]],
        _timeout: float,
        _retries: int,
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        return (
            {
                "timestamp": "now",
                "host": host,
                "exporter": "unknown",
                "port": port,
                "url": f"http://{host}:{port}/metrics",
                "detected": False,
                "method": "none",
                "status": 404,
                "marker_hit": None,
                "elapsed_ms": 1,
                "content_type": "text/plain",
                "error": None,
                "truncated": False,
                "body": "",
            },
            None,
        )

    previous_pool = object()
    scanner._ACTIVE_HTTP_POOL = previous_pool
    monkeypatch.setattr("redposture_core.scanner._HTTPConnectionPool", _ScanPool)
    monkeypatch.setattr("redposture_core.scanner._scan_presence_port_task", fake_scan_task)

    def _emit_fail(_line: str) -> None:
        raise RuntimeError("emit failed")

    with pytest.raises(RuntimeError, match="emit failed"):
        scanner.scan_exporter_presence(
            hosts=["127.0.0.1"],
            timeout=1.0,
            output_path=None,
            output_format="json",
            logger=None,
            emit_line=_emit_fail,
            workers=1,
            retries=0,
            discovery_exporters=[{"name": "node_exporter", "port": 9100, "markers": ("node_exporter_build_info",)}],
            custom_ports=[9100],
        )

    assert len(created_pools) == 1
    assert created_pools[0].closed is True
    assert scanner._ACTIVE_HTTP_POOL is previous_pool
    scanner._ACTIVE_HTTP_POOL = None
