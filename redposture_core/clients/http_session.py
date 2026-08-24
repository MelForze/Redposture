"""Reusable HTTP/1.1 transport for one audit target lifecycle."""

from __future__ import annotations

import http.client
import io
import socket
import ssl
import threading
import time
import urllib.parse
from collections import defaultdict
from collections.abc import Mapping
from typing import Any

from ..network_proxy import ProxyConfig, open_connection_via_proxy
from .http_api import HttpResponse, normalize_http_error
from .tls_cache import shared_client_ssl_context

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_MAX_REDIRECTS = 5


def _origin(url: str) -> tuple[str, str, int]:
    parsed = urllib.parse.urlsplit(url)
    scheme = parsed.scheme.lower()
    host = str(parsed.hostname or "").lower()
    port = int(parsed.port or (443 if scheme == "https" else 80))
    return scheme, host, port


def _request_path(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))


def _transient_error(exc: BaseException) -> bool:
    if isinstance(exc, ssl.SSLCertVerificationError):
        return False
    return isinstance(
        exc,
        (
            TimeoutError,
            ConnectionError,
            OSError,
            ssl.SSLError,
            http.client.CannotSendRequest,
            http.client.RemoteDisconnected,
            http.client.ResponseNotReady,
        ),
    )


class _LayeredTlsRaw(io.RawIOBase):
    def __init__(self, transport: _LayeredTlsSocket) -> None:
        self._transport = transport

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        payload = self._transport.recv(len(buffer))
        size = len(payload)
        buffer[:size] = payload
        return size


class _LayeredTlsSocket:
    """Socket-like TLS layer over an already TLS-wrapped HTTPS proxy tunnel."""

    def __init__(self, outer: socket.socket, context: ssl.SSLContext, server_hostname: str) -> None:
        self._outer = outer
        self._incoming = ssl.MemoryBIO()
        self._outgoing = ssl.MemoryBIO()
        self._ssl = context.wrap_bio(self._incoming, self._outgoing, server_hostname=server_hostname)
        self._closed = False
        self._handshake()

    def _flush(self) -> None:
        while True:
            payload = self._outgoing.read()
            if not payload:
                return
            self._outer.sendall(payload)

    def _feed(self) -> None:
        payload = self._outer.recv(64 * 1024)
        if not payload:
            self._incoming.write_eof()
            return
        self._incoming.write(payload)

    def _handshake(self) -> None:
        while True:
            try:
                self._ssl.do_handshake()
                self._flush()
                return
            except ssl.SSLWantReadError:
                self._flush()
                self._feed()
            except ssl.SSLWantWriteError:
                self._flush()

    def sendall(self, payload: bytes) -> None:
        view = memoryview(payload)
        while view:
            try:
                written = self._ssl.write(view)
                view = view[written:]
                self._flush()
            except ssl.SSLWantReadError:
                self._flush()
                self._feed()
            except ssl.SSLWantWriteError:
                self._flush()

    def recv(self, size: int) -> bytes:
        while True:
            try:
                return self._ssl.read(max(1, int(size)))
            except ssl.SSLWantReadError:
                self._flush()
                self._feed()
            except ssl.SSLWantWriteError:
                self._flush()
            except ssl.SSLZeroReturnError:
                return b""

    def makefile(self, mode: str = "r", buffering: int | None = None, **_kwargs: Any) -> io.BufferedReader:
        if "r" not in mode:
            raise ValueError("layered TLS socket supports read makefiles only")
        return io.BufferedReader(_LayeredTlsRaw(self), buffer_size=max(1, int(buffering or io.DEFAULT_BUFFER_SIZE)))

    def settimeout(self, timeout: float | None) -> None:
        self._outer.settimeout(timeout)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._outer.close()
        except OSError:
            pass


class HttpSessionPool:
    """Thread-safe connection pool scoped to one target lifecycle."""

    def __init__(
        self,
        *,
        timeout: float,
        insecure: bool = False,
        ca_file: str | None = None,
        cert_file: str | None = None,
        key_file: str | None = None,
        proxy: ProxyConfig | None = None,
        max_idle_per_origin: int = 4,
        retries: int = 0,
    ) -> None:
        self.timeout = max(0.1, float(timeout))
        self.insecure = bool(insecure)
        self.ca_file = ca_file
        self.cert_file = cert_file
        self.key_file = key_file
        self.proxy = proxy
        self.max_idle_per_origin = max(1, int(max_idle_per_origin))
        self.default_retries = max(0, int(retries))
        self._idle: dict[tuple[str, str, int], list[http.client.HTTPConnection]] = defaultdict(list)
        self._connections: set[http.client.HTTPConnection] = set()
        self._lock = threading.Lock()
        self._closed = False
        self._stats = {"connections": 0, "reused": 0, "requests": 0, "retries": 0}

    def _target_context(self) -> ssl.SSLContext:
        return shared_client_ssl_context(
            insecure=self.insecure,
            ca_file=self.ca_file,
            cert_file=self.cert_file,
            key_file=self.key_file,
        )

    def _new_connection(self, key: tuple[str, str, int], timeout: float) -> http.client.HTTPConnection:
        scheme, host, port = key
        if self.proxy is None:
            if scheme == "https":
                connection: http.client.HTTPConnection = http.client.HTTPSConnection(
                    host, port, timeout=timeout, context=self._target_context()
                )
            else:
                connection = http.client.HTTPConnection(host, port, timeout=timeout)
        else:
            tunnel = open_connection_via_proxy(self.proxy, (host, port), timeout=timeout)
            tunnel.settimeout(timeout)
            transport: Any = tunnel
            if scheme == "https":
                context = self._target_context()
                if self.proxy.scheme == "https":
                    transport = _LayeredTlsSocket(tunnel, context, host)
                else:
                    transport = context.wrap_socket(tunnel, server_hostname=host)
                transport.settimeout(timeout)
            connection = http.client.HTTPConnection(host, port, timeout=timeout)
            connection.sock = transport
        with self._lock:
            if self._closed:
                connection.close()
                raise RuntimeError("HTTP session pool is closed")
            self._connections.add(connection)
            self._stats["connections"] += 1
        return connection

    def _acquire(self, key: tuple[str, str, int], timeout: float) -> tuple[http.client.HTTPConnection, bool]:
        with self._lock:
            if self._closed:
                raise RuntimeError("HTTP session pool is closed")
            bucket = self._idle.get(key)
            if bucket:
                connection = bucket.pop()
                connection.timeout = timeout
                self._stats["reused"] += 1
                return connection, True
        return self._new_connection(key, timeout), False

    def _release(self, key: tuple[str, str, int], connection: http.client.HTTPConnection, reusable: bool) -> None:
        close_connection = not reusable
        with self._lock:
            if self._closed or connection not in self._connections:
                close_connection = True
            elif reusable:
                bucket = self._idle[key]
                if len(bucket) < self.max_idle_per_origin:
                    bucket.append(connection)
                    return
                close_connection = True
            self._connections.discard(connection)
        if close_connection:
            try:
                connection.close()
            except OSError:
                pass

    def _request_once(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout: float,
        response_size_cap: int,
    ) -> tuple[HttpResponse, BaseException | None, bool]:
        key = _origin(url)
        connection, reused = self._acquire(key, timeout)
        response: http.client.HTTPResponse | None = None
        reusable = False
        try:
            request_headers = {str(name): str(value) for name, value in headers.items()}
            lowered = {name.lower() for name in request_headers}
            if "connection" not in lowered:
                request_headers["Connection"] = "keep-alive"
            connection.request(method, _request_path(url), body=body, headers=request_headers)
            response = connection.getresponse()
            cap = max(0, int(response_size_cap))
            payload = response.read(cap + 1)
            truncated = len(payload) > cap
            if truncated:
                payload = payload[:cap]
            reusable = not truncated and not response.will_close
            with self._lock:
                self._stats["requests"] += 1
            return (
                HttpResponse(
                    status=int(response.status),
                    body=payload,
                    headers={str(name): str(value) for name, value in response.getheaders()},
                    error=None,
                    truncated=truncated,
                    request_url=url,
                    final_url=url,
                ),
                None,
                reused,
            )
        except BaseException as exc:  # noqa: BLE001 - normalized for callers
            return HttpResponse(status=0, body=b"", headers={}, error=normalize_http_error(exc)), exc, reused
        finally:
            if response is not None:
                try:
                    response.close()
                except OSError:
                    reusable = False
            self._release(key, connection, reusable)

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | str | None = None,
        timeout: float | None = None,
        response_size_cap: int = 10 * 1024 * 1024,
        retries: int | None = None,
        replay_safe: bool | None = None,
        allow_cross_origin_redirects: bool = False,
        preserve_authorization_on_cross_origin: bool = False,
    ) -> HttpResponse:
        method_value = str(method or "GET").upper()
        body_value = body.encode("utf-8") if isinstance(body, str) else body
        headers_value = {str(name): str(value) for name, value in (headers or {}).items()}
        timeout_value = self.timeout if timeout is None else max(0.1, float(timeout))
        original_url = str(url)
        current_url = original_url
        history: list[str] = []
        visited = {current_url}
        safe = method_value in {"GET", "HEAD"} if replay_safe is None else bool(replay_safe)

        for _redirect in range(_MAX_REDIRECTS + 1):
            response: HttpResponse | None = None
            attempts = max(1, int(self.default_retries if retries is None else retries) + 1)
            for attempt in range(attempts):
                response, request_error, _reused = self._request_once(
                    method_value,
                    current_url,
                    headers=headers_value,
                    body=body_value,
                    timeout=timeout_value,
                    response_size_cap=response_size_cap,
                )
                if request_error is None or not safe or not _transient_error(request_error) or attempt >= attempts - 1:
                    break
                with self._lock:
                    self._stats["retries"] += 1
                time.sleep(min(1.5, 0.2 * (2**attempt)))
            assert response is not None
            if response.error or response.status not in _REDIRECT_STATUSES:
                return HttpResponse(
                    status=response.status,
                    body=response.body,
                    headers=response.headers,
                    error=response.error,
                    truncated=response.truncated,
                    request_url=original_url,
                    final_url=current_url,
                    redirect_history=tuple(history),
                )
            if not safe:
                return HttpResponse(
                    status=response.status,
                    body=response.body,
                    headers=response.headers,
                    error="redirect suppressed after non-replay-safe request",
                    request_url=original_url,
                    final_url=current_url,
                    redirect_history=tuple(history),
                )
            location = next((value for name, value in response.headers.items() if name.lower() == "location"), "")
            if not location:
                return response
            redirected = urllib.parse.urljoin(current_url, location)
            if redirected in visited:
                return HttpResponse(status=0, body=b"", headers={}, error="redirect loop detected")
            cross_origin = _origin(current_url) != _origin(redirected)
            if cross_origin and not allow_cross_origin_redirects:
                return HttpResponse(
                    status=response.status,
                    body=response.body,
                    headers=response.headers,
                    error=f"cross-origin redirect blocked: {current_url} -> {redirected}",
                )
            if cross_origin and not preserve_authorization_on_cross_origin:
                headers_value = {
                    name: value for name, value in headers_value.items() if name.lower() != "authorization"
                }
            history.append(current_url)
            visited.add(redirected)
            current_url = redirected
            if response.status in {301, 302, 303} and method_value == "POST":
                method_value = "GET"
                body_value = None
                headers_value = {
                    name: value
                    for name, value in headers_value.items()
                    if name.lower() not in {"content-length", "content-type"}
                }
                safe = True
        return HttpResponse(status=0, body=b"", headers={}, error=f"redirect limit exceeded ({_MAX_REDIRECTS})")

    def stats(self) -> dict[str, int]:
        with self._lock:
            return dict(self._stats)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            connections = list(self._connections)
            self._connections.clear()
            self._idle.clear()
        for connection in connections:
            try:
                connection.close()
            except OSError:
                pass


__all__ = ["HttpSessionPool"]
