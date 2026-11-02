"""HTTP keep-alive pool used by exporter scan/collect flows."""

from __future__ import annotations

import http.client
import selectors
import socket
import ssl
import threading
import urllib.parse
from contextlib import contextmanager
from typing import Any

from ..clients.http_api import HttpResponse, check_http_body_complete
from ..clients.http_handoff import HttpHandoffBudget
from ..clients.http_redirects import follow_redirects
from ..clients.http_session import HttpSessionPool
from ..clients.tls_cache import shared_client_ssl_context
from ..http_headers import merge_custom_http_headers

HTTP_POOL_MAX_IDLE_TOTAL = 512
HTTP_POOL_MAX_IDLE_PER_HOST = 4


class _DetectionPool(HttpSessionPool):
    def __init__(self, owner: Any) -> None:
        self.owner = owner
        super().__init__(timeout=1, max_idle_per_origin=owner._max_idle_per_host)

    def _target_context(self) -> ssl.SSLContext:
        return self.owner._tls_context

    def adopt_socket(self, *args: Any, **kwargs: Any) -> bool:
        owner = self.owner
        with owner._lock:
            if owner._closed:
                return False
            key = args[0]
            with self._lock:
                pending = len(self._idle.get(key, ()))
            ordinary = owner._idle.get(key, [])
            while len(ordinary) + pending >= owner._max_idle_per_host and ordinary:
                victim = ordinary.pop(0)
                owner._connections.discard(victim)
                owner._idle_total -= 1
                victim.close()
            if not ordinary:
                owner._idle.pop(key, None)
            if len(ordinary) + pending >= owner._max_idle_per_host:
                return False
            while owner._idle_total + owner._handoff_budget.active > owner._max_idle_total and owner._idle_total:
                owner._evict_one()
            if owner._idle_total + owner._handoff_budget.active > owner._max_idle_total:
                return False
            return super().adopt_socket(*args, **kwargs)

    def take_handoff(
        self, key: tuple[str, str, int], *, timeout: float, method: str
    ) -> http.client.HTTPConnection | None:
        try:
            return super().take_handoff(key, timeout=timeout, method=method)
        finally:
            with self._lock:
                if not self._idle.get(key):
                    self._idle.pop(key, None)

    def discard_socket(self, sock: Any) -> None:
        with self._lock:
            for connection, release in list(self._retained_claims.items()):
                if connection.sock is sock:
                    self._retained_claims.pop(connection)
                    self._connections.discard(connection)
                    for key, bucket in list(self._idle.items()):
                        if connection in bucket:
                            bucket.remove(connection)
                            if not bucket:
                                self._idle.pop(key, None)
                    release()
                    connection.close()
                    return


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
        self._closed = False
        self._connections: set[http.client.HTTPConnection] = set()
        self._active_sockets: set[Any] = set()
        self._lock = threading.Lock()
        self._handoff_budget = HttpHandoffBudget(min(64, self._max_idle_total))
        self._handoff_policy = _DetectionPool(self)

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
        retained = self._handoff_policy.take_handoff(key, timeout=timeout, method="GET")
        if retained is not None:
            with self._lock:
                if self._closed:
                    retained.close()
                    raise ValueError("HTTP connection pool is closed")
                self._connections.add(retained)
                # Ownership is now atomic with terminal close of this pool.
                # Do not retain one HTTPConnection object for every scanned host.
                with self._handoff_policy._lock:
                    self._handoff_policy._connections.discard(retained)
            HttpSessionPool._claim_handoff(retained)
            return retained
        with self._lock:
            if self._closed:
                raise ValueError("HTTP connection pool is closed")
            bucket = self._idle.get(key)
            while bucket:
                conn = bucket.pop()
                self._idle_total = max(0, self._idle_total - 1)
                if not bucket:
                    self._idle.pop(key, None)
                if self._stale(conn):
                    self._connections.discard(conn)
                    conn.close()
                    continue
                conn.timeout = timeout
                if conn.sock is not None:
                    conn.sock.settimeout(timeout)
                return conn
        connection: http.client.HTTPConnection
        if scheme == "https":
            connection = http.client.HTTPSConnection(host, port, timeout=timeout, context=self._tls_context)
        else:
            connection = http.client.HTTPConnection(host, port, timeout=timeout)
        with self._lock:
            if self._closed:
                connection.close()
                raise ValueError("HTTP connection pool is closed")
            self._connections.add(connection)
        return connection

    @staticmethod
    def _stale(connection: http.client.HTTPConnection) -> bool:
        sock = connection.sock
        if sock is None or not callable(getattr(sock, "fileno", None)):
            return False
        try:
            pending = getattr(sock, "pending", None)
            if callable(pending) and pending():
                return True
            # Readable idle sockets are EOF or unsolicited data, neither is a
            # clean response boundary. Selectors also work above FD_SETSIZE.
            with selectors.DefaultSelector() as selector:
                selector.register(sock, selectors.EVENT_READ)
                return bool(selector.select(0))
        except (OSError, ValueError):
            return True

    def _evict_one(self) -> None:
        for key in list(self._idle):
            bucket = self._idle.get(key)
            if not bucket:
                continue
            victim = bucket.pop(0)
            self._connections.discard(victim)
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
            with self._lock:
                self._connections.discard(conn)
            try:
                conn.close()
            except OSError:
                pass
            return

        key = (scheme, host, port)
        with self._lock:
            bucket = self._idle.setdefault(key, [])
            if self._closed or len(bucket) >= self._max_idle_per_host:
                if not bucket:
                    self._idle.pop(key, None)
                self._connections.discard(conn)
                try:
                    conn.close()
                except OSError:
                    pass
                return
            while self._idle_total + self._handoff_budget.active >= self._max_idle_total:
                self._evict_one()
                if self._idle_total + self._handoff_budget.active < self._max_idle_total or not self._idle_total:
                    break
            if self._idle_total + self._handoff_budget.active >= self._max_idle_total:
                self._connections.discard(conn)
                try:
                    conn.close()
                except OSError:
                    pass
                return
            # Eviction may remove the last item of this same origin bucket.
            self._idle.setdefault(key, []).append(conn)
            self._idle_total += 1

    def get(
        self,
        url: str,
        timeout: float,
        *,
        max_bytes: int | None = None,
    ) -> tuple[int | None, bytes, str | None, BaseException | None, bool]:
        failure: BaseException | None = None

        def send(method: str, url: str, headers: dict[str, str], body: bytes | None) -> HttpResponse:
            nonlocal failure
            status, raw, content_type, failure, truncated, response_headers = self._get_once(
                url,
                timeout,
                max_bytes=max_bytes,
                headers=headers,
            )
            return HttpResponse(
                status or 0, raw, response_headers, error=str(failure) if failure else None, truncated=truncated
            )

        response = follow_redirects(send, "GET", url, headers=merge_custom_http_headers({}))
        if response.error:
            return None, b"", None, failure or ValueError(response.error), response.truncated
        content_type = next((v for k, v in response.headers.items() if k.lower() == "content-type"), None)
        return response.status, response.body, content_type, None, response.truncated

    def _get_once(
        self,
        url: str,
        timeout: float,
        *,
        max_bytes: int | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int | None, bytes, str | None, BaseException | None, bool, dict[str, str]]:
        scheme, host, port, path = self._target_from_url(url)
        conn = None
        active_sock = None
        reusable = False
        try:
            conn = self._acquire(scheme, host, port, timeout)
            conn.request(
                "GET",
                path,
                headers=merge_custom_http_headers(
                    {
                        "User-Agent": "RedPosture/1.0",
                        "Connection": "keep-alive",
                        **(headers or {}),
                    }
                ),
            )
            active_sock = getattr(conn, "sock", None)
            if active_sock is not None:
                with self._lock:
                    closed = self._closed
                    if not closed:
                        self._active_sockets.add(active_sock)
                if closed:
                    active_sock.shutdown(socket.SHUT_RDWR)
            response = conn.getresponse()
            truncated = False
            if max_bytes is None:
                raw = response.read()
            else:
                raw = response.read(max_bytes + 1)
                truncated = len(raw) > max_bytes
                if truncated:
                    raw = raw[:max_bytes]
            if not truncated:
                check_http_body_complete(response, len(raw))
            # A capped read leaves the remainder of a keep-alive response on
            # the socket. Returning that connection to the pool makes the
            # next request fail with ``ResponseNotReady`` or consume stale
            # framing bytes. Do not drain here: that would defeat the cap on
            # a peer that keeps sending an unbounded body.
            reusable = not truncated and not response.will_close
            response_headers = (
                {str(k): str(v) for k, v in response.getheaders()}
                if callable(getattr(response, "getheaders", None))
                else {k: v for k in ("Content-Type", "Location") if (v := response.getheader(k)) is not None}
            )
            return int(response.status), raw, response.getheader("Content-Type"), None, truncated, response_headers
        except Exception as exc:
            return None, b"", None, exc, False, {}
        finally:
            with self._lock:
                if active_sock is not None:
                    self._active_sockets.discard(active_sock)
            if conn is not None:
                self._release(scheme, host, port, conn, reusable)

    def close(self) -> None:
        with self._lock:
            self._closed = True
            connections = list(self._connections)
            active_sockets = list(self._active_sockets)
            # Include caller-provided idle connection objects as before.
            connections.extend(conn for bucket in self._idle.values() for conn in bucket)
            self._connections.clear()
            self._active_sockets.clear()
            self._idle.clear()
            self._idle_total = 0
        self._handoff_policy.close()
        for sock in active_sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        for conn in set(connections):
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
