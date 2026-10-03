"""Exporter pooled transport ownership under caps, faults and reuse."""

from __future__ import annotations

from redposture_core.exporters.http_pool import HTTPConnectionPool, activate_http_pool, get_active_http_pool


class _Connection:
    def __init__(self) -> None:
        self.closed = 0
        self.timeout = 0.0

    def close(self) -> None:
        self.closed += 1


def test_pool_evicts_oldest_origin_and_never_reuses_dropped_connection() -> None:
    pool = HTTPConnectionPool(max_idle_total=2, max_idle_per_host=1)
    first, second, third = _Connection(), _Connection(), _Connection()
    pool._release("http", "first.local", 80, first, True)
    pool._release("http", "second.local", 80, second, True)
    pool._release("http", "third.local", 80, third, True)
    assert first.closed == 1
    assert second.closed == third.closed == 0
    assert pool._idle_total == 2
    assert pool._acquire("http", "second.local", 80, 0.5) is second
    assert second.timeout == 0.5
    pool._release("http", "second.local", 80, second, False)
    assert second.closed == 1
    pool.close()
    assert third.closed == 1
    assert pool._idle_total == 0


def test_pool_per_origin_cap_and_context_cleanup() -> None:
    pool = HTTPConnectionPool(max_idle_total=5, max_idle_per_host=1)
    first, second = _Connection(), _Connection()
    pool._release("https", "host.local", 443, first, True)
    pool._release("https", "host.local", 443, second, True)
    assert second.closed == 1
    assert pool._idle_total == 1
    with activate_http_pool(pool):
        assert get_active_http_pool() is pool
    assert get_active_http_pool() is None
    assert first.closed == 1
