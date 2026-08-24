"""HTTP keep-alive pool used by exporter scan/collect flows."""

from __future__ import annotations

import http.client
import ssl
import threading
import urllib.parse
from contextlib import contextmanager
from typing import Any

from ..clients.tls_cache import shared_client_ssl_context

HTTP_POOL_MAX_IDLE_TOTAL = 512
HTTP_POOL_MAX_IDLE_PER_HOST = 4


class HTTPConnectionPool:
    def __init__(
        self,
        *,
        max_idle_total: int = HTTP_POOL_MAX_IDLE_TOTAL,
        max_idle_per_host: int = HTTP_POOL_MAX_IDLE_PER_HOST,
        tls_context: ssl.SSLContext | None = None,
    ) -> None:
        self._max_idle_total = max(1, int(max_idle_total))
        self._max_idle_per_host = max(1, int(max_idle_per_host))
        self._tls_context = tls_context or shared_client_ssl_context(insecure=False)
        self._idle: dict[tuple[str, str, int], list[http.client.HTTPConnection]] = {}
        self._idle_total = 0
        self._lock = threading.Lock()

    @staticmethod
    def _target_from_url(url: str) -> tuple[str, str, int, str]:
        parsed = urllib.parse.urlsplit(url)
        scheme = parsed.scheme.lower() or "http"
        if scheme not in {"http", "https"}:
            raise ValueError(f"unsupported URL scheme for pooled request: {scheme}")
        host = parsed.hostname
        if not host:
            raise ValueError("invalid URL host")
        port = int(parsed.port or (443 if scheme == "https" else 80))
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return scheme, host, port, path

    def _acquire(
        self,
        scheme: str,
        host: str | int,
        port: int | float,
        timeout: float | None = None,
    ) -> http.client.HTTPConnection:
        # Preserve the pre-HTTPS private-call shape `_acquire(host, port,
        # timeout)` used by integrations while allowing scheme-aware pooling.
        if timeout is None:
            timeout = float(port)
            port = int(host)
            host = scheme
            scheme = "http"
        host = str(host)
        port = int(port)
        key = (scheme, host, port)
        with self._lock:
            bucket = self._idle.get(key)
            if bucket:
                conn = bucket.pop()
                self._idle_total = max(0, self._idle_total - 1)
                if not bucket:
                    self._idle.pop(key, None)
                conn.timeout = timeout
                return conn
        if scheme == "https":
            return http.client.HTTPSConnection(host, port, timeout=timeout, context=self._tls_context)
        return http.client.HTTPConnection(host, port, timeout=timeout)

    def _evict_one(self) -> None:
        for key in list(self._idle):
            bucket = self._idle.get(key)
            if not bucket:
                continue
            victim = bucket.pop(0)
            self._idle_total = max(0, self._idle_total - 1)
            if not bucket:
                self._idle.pop(key, None)
            try:
                victim.close()
            except OSError:
                pass
            return

    def _release(
        self,
        scheme: str,
        host: str,
        port: int,
        conn: http.client.HTTPConnection,
        reusable: bool,
    ) -> None:
        if not reusable:
            try:
                conn.close()
            except OSError:
                pass
            return

        key = (scheme, host, port)
        with self._lock:
            bucket = self._idle.setdefault(key, [])
            if len(bucket) >= self._max_idle_per_host:
                try:
                    conn.close()
                except OSError:
                    pass
                return
            while self._idle_total >= self._max_idle_total:
                self._evict_one()
                if self._idle_total < self._max_idle_total:
                    break
            if self._idle_total >= self._max_idle_total:
                try:
                    conn.close()
                except OSError:
                    pass
                return
            bucket.append(conn)
            self._idle_total += 1

    def get(
        self,
        url: str,
        timeout: float,
        *,
        max_bytes: int | None = None,
    ) -> tuple[int | None, bytes, str | None, BaseException | None, bool]:
        scheme, host, port, path = self._target_from_url(url)
        conn = self._acquire(scheme, host, port, timeout)
        reusable = False
        try:
            conn.request(
                "GET",
                path,
                headers={
                    "User-Agent": "RedPosture/1.0",
                    "Connection": "keep-alive",
                },
            )
            response = conn.getresponse()
            truncated = False
            if max_bytes is None:
                raw = response.read()
            else:
                raw = response.read(max_bytes + 1)
                truncated = len(raw) > max_bytes
                if truncated:
                    raw = raw[:max_bytes]
            # A capped read leaves the remainder of a keep-alive response on
            # the socket. Returning that connection to the pool makes the
            # next request fail with ``ResponseNotReady`` or consume stale
            # framing bytes. Do not drain here: that would defeat the cap on
            # a peer that keeps sending an unbounded body.
            reusable = not truncated and not response.will_close
            return int(response.status), raw, response.getheader("Content-Type"), None, truncated
        except Exception as exc:
            return None, b"", None, exc, False
        finally:
            self._release(scheme, host, port, conn, reusable)

    def close(self) -> None:
        with self._lock:
            buckets = list(self._idle.values())
            self._idle.clear()
            self._idle_total = 0
        for bucket in buckets:
            for conn in bucket:
                try:
                    conn.close()
                except OSError:
                    pass


_ACTIVE_HTTP_POOL: HTTPConnectionPool | None = None
_ACTIVE_HTTP_POOL_LOCK = threading.Lock()


@contextmanager
def activate_http_pool(pool: HTTPConnectionPool | None):
    global _ACTIVE_HTTP_POOL
    if pool is None:
        yield
        return

    with _ACTIVE_HTTP_POOL_LOCK:
        previous = _ACTIVE_HTTP_POOL
        _ACTIVE_HTTP_POOL = pool
    try:
        yield
    finally:
        with _ACTIVE_HTTP_POOL_LOCK:
            _ACTIVE_HTTP_POOL = previous
        pool.close()


def get_active_http_pool() -> HTTPConnectionPool | None:
    return _ACTIVE_HTTP_POOL


def pool_get_compat(
    pool: Any,
    url: str,
    timeout: float,
    *,
    max_bytes: int | None = None,
) -> tuple[int | None, bytes, str | None, BaseException | None, bool]:
    try:
        result = pool.get(url, timeout, max_bytes=max_bytes)
    except TypeError:
        result = pool.get(url, timeout)

    if isinstance(result, tuple) and len(result) == 4:
        status, raw, content_type, error = result
        return status, raw, content_type, error, False
    if isinstance(result, tuple) and len(result) == 5:
        status, raw, content_type, error, truncated = result
        return status, raw, content_type, error, bool(truncated)
    raise ValueError("invalid pooled HTTP response tuple")


__all__ = [
    "HTTPConnectionPool",
    "HTTP_POOL_MAX_IDLE_PER_HOST",
    "HTTP_POOL_MAX_IDLE_TOTAL",
    "activate_http_pool",
    "get_active_http_pool",
    "pool_get_compat",
]
