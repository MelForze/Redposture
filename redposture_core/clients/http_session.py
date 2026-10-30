"""Reusable HTTP/1.1 transport for one audit target lifecycle."""

from __future__ import annotations

import http.client
import io
import socket
import ssl
import threading
import time
import urllib.parse
import zlib
from collections import defaultdict
from collections.abc import Callable, Mapping
from typing import Any

from ..http_headers import merge_custom_http_headers
from ..network_proxy import ProxyConfig, open_connection_via_proxy
from . import transport
from .http_api import HttpResponse, decode_http_content, normalize_http_error, pin_http_redirect_path
from .http_redirects import RequestPreparer, follow_redirects
from .tls_cache import shared_client_ssl_context


def _origin(url: str) -> tuple[str, str, int]:
    parsed = urllib.parse.urlsplit(url)
    scheme = parsed.scheme.lower()
    host = str(parsed.hostname or "").lower()
    port = int(parsed.port or (443 if scheme == "https" else 80))
    return scheme, host, port


def _request_path(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))


def _response_headers(values: list[tuple[str, str]]) -> dict[str, str]:
    """Keep Set-Cookie fields separate; commas also occur inside Expires."""
    result: dict[str, str] = {}
    cookie_name: str | None = None
    for name, value in values:
        name, value = str(name), str(value)
        if name.lower() == "set-cookie":
            if cookie_name is None:
                cookie_name = name
                result[name] = value
            else:
                result[cookie_name] += "\n" + value
        else:
            result[name] = value
    return result


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

    def shutdown(self, how: int) -> None:
        self._outer.shutdown(how)

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
        # A Connection: close response can detach the socket from HTTPConnection
        # before its body has been read. Keep it reachable for pool.close().
        self._active_sockets: set[Any] = set()
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
                if connection.sock is not None:
                    connection.sock.settimeout(timeout)
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
        preserve_partial_body: bool = False,
        deadline: float | None = None,
    ) -> tuple[HttpResponse, BaseException | None, bool]:
        key = _origin(url)
        connection: http.client.HTTPConnection | None = None
        reused = False
        response: http.client.HTTPResponse | None = None
        reusable = False
        active_sock: Any | None = None
        received = bytearray()
        try:
            connection, reused = self._acquire(key, timeout)

            def apply_deadline() -> None:
                if deadline is None:
                    return
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("HTTP request timeout budget exhausted while reading response")
                connection.timeout = remaining
                if connection.sock is not None:
                    connection.sock.settimeout(remaining)

            request_headers = {str(name): str(value) for name, value in headers.items()}
            lowered = {name.lower() for name in request_headers}
            if "connection" not in lowered:
                request_headers["Connection"] = "keep-alive"
            apply_deadline()
            connection.request(method, _request_path(url), body=body, headers=request_headers)
            active_sock = getattr(connection, "sock", None)
            if active_sock is not None:
                with self._lock:
                    closed = self._closed
                    if not closed:
                        self._active_sockets.add(active_sock)
                if closed:
                    active_sock.shutdown(socket.SHUT_RDWR)
            apply_deadline()
            response = connection.getresponse()
            cap = max(0, int(response_size_cap))
            if preserve_partial_body or deadline is not None:
                while len(received) <= cap:
                    apply_deadline()
                    chunk = response.read1(min(64 * 1024, cap + 1 - len(received)))
                    if not chunk:
                        break
                    received.extend(chunk)
                payload = bytes(received)
            else:
                payload = response.read(cap + 1)
            truncated = len(payload) > cap
            remaining_length = getattr(response, "length", None)
            if not truncated and remaining_length is not None and remaining_length > 0:
                raise ConnectionError(
                    f"unexpected EOF: incomplete HTTP response body "
                    f"({len(payload)} bytes received, {remaining_length} more expected)"
                )
            if truncated:
                payload = payload[:cap]
            reusable = not truncated and not response.will_close
            with self._lock:
                self._stats["requests"] += 1
            return (
                decode_http_content(
                    HttpResponse(
                        status=int(response.status),
                        body=payload,
                        headers=_response_headers(response.getheaders()),
                        error=None,
                        truncated=truncated,
                        request_url=url,
                        final_url=url,
                    ),
                    max_bytes=cap,
                ),
                None,
                reused,
            )
        except BaseException as exc:  # noqa: BLE001 - normalized for callers
            if preserve_partial_body and response is not None and received:
                prefix = bytes(received[: max(0, int(response_size_cap))])
                if str(response.getheader("Content-Encoding", "")).strip().lower() == "gzip":
                    try:
                        prefix = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(
                            prefix, max(1, int(response_size_cap))
                        )[: max(0, int(response_size_cap))]
                    except zlib.error:
                        prefix = b""
                return (
                    HttpResponse(
                        status=int(response.status),
                        body=prefix,
                        headers=_response_headers(response.getheaders()),
                        error=normalize_http_error(exc),
                        truncated=True,
                        request_url=url,
                        final_url=url,
                    ),
                    exc,
                    reused,
                )
            return HttpResponse(status=0, body=b"", headers={}, error=normalize_http_error(exc)), exc, reused
        finally:
            if active_sock is not None:
                with self._lock:
                    self._active_sockets.discard(active_sock)
            if response is not None:
                try:
                    response.close()
                except OSError:
                    reusable = False
            if connection is not None:
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
        allow_cross_origin_redirects: bool = True,
        preserve_authorization_on_cross_origin: bool = True,
        prepare_request: RequestPreparer | None = None,
        preserve_partial_body: bool = False,
    ) -> HttpResponse:
        if self._closed:
            raise RuntimeError("HTTP session pool is closed")
        timeout_value = self.timeout if timeout is None else max(0.001, float(timeout))
        deadline = time.monotonic() + timeout_value if timeout is not None else None
        safe = str(method or "GET").upper() in {"GET", "HEAD"} if replay_safe is None else bool(replay_safe)
        request_count = 0

        def send(
            method_value: str, current_url: str, headers_value: dict[str, str], body_value: bytes | None
        ) -> HttpResponse:
            nonlocal request_count
            headers_value = merge_custom_http_headers(headers_value)
            if not preserve_authorization_on_cross_origin and _origin(current_url) != _origin(url):
                headers_value = {key: value for key, value in headers_value.items() if key.lower() != "authorization"}
            attempts = max(1, int(self.default_retries if retries is None else retries) + 1)
            last_response: HttpResponse | None = None
            for attempt in range(attempts):
                attempt_timeout = (
                    timeout_value
                    if deadline is not None or attempts == 1
                    else transport.escalating_timeout(timeout_value, attempt)
                )
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        if last_response is not None:
                            return last_response
                        raise TimeoutError("HTTP request timeout budget exhausted before redirect")
                    if request_count or attempt:
                        attempt_timeout = min(attempt_timeout, remaining)
                request_count += 1
                optional_kwargs: dict[str, Any] = {}
                if deadline is not None:
                    optional_kwargs["deadline"] = deadline
                if preserve_partial_body:
                    optional_kwargs["preserve_partial_body"] = True
                response, request_error, _reused = self._request_once(
                    method_value,
                    current_url,
                    headers=headers_value,
                    body=body_value,
                    timeout=attempt_timeout,
                    response_size_cap=response_size_cap,
                    **optional_kwargs,
                )
                last_response = response
                # Closing the pool is a cancellation, not a transient network
                # failure. Retrying would delay shutdown or race _acquire().
                if (
                    self._closed
                    or request_error is None
                    or not safe
                    or attempt >= attempts - 1
                    or (preserve_partial_body and response.body)
                ):
                    return response
                reason = transport.classify_failure_reason(response.error)
                stale_protocol = isinstance(
                    request_error,
                    (http.client.CannotSendRequest, http.client.RemoteDisconnected, http.client.ResponseNotReady),
                )
                if not (transport.is_escalating_reason(reason) or stale_protocol):
                    return response
                if deadline is not None and deadline <= time.monotonic():
                    return response
                with self._lock:
                    self._stats["retries"] += 1
                delay = min(1.5, 0.2 * (2**attempt))
                if deadline is not None:
                    delay = min(delay, max(0.0, deadline - time.monotonic()))
                time.sleep(delay)
            raise AssertionError("unreachable")

        response = follow_redirects(
            send,
            method,
            url,
            headers=merge_custom_http_headers(headers),
            body=body,
            allow_cross_origin=allow_cross_origin_redirects,
            preserve_authorization=preserve_authorization_on_cross_origin,
            prepare_request=prepare_request,
        )
        pin_http_redirect_path(response, method=method)
        return response

    def request_stream(
        self,
        method: str,
        url: str,
        *,
        on_chunk: Callable[[bytes], Any],
        body: bytes | None = None,
        on_response: Callable[[int, Mapping[str, str]], Any] | None = None,
        chunk_size: int = 64 * 1024,
        headers: Mapping[str, str] | None = None,
        timeout: float | None = None,
        deadline: float | None = None,
        allow_cross_origin_redirects: bool = True,
        preserve_authorization_on_cross_origin: bool = False,
    ) -> HttpResponse:
        """Read one HTTP response without buffering it; never replay body chunks."""
        if self._closed:
            raise RuntimeError("HTTP session pool is closed")
        if str(method).upper() not in {"GET", "HEAD", "POST"}:
            raise ValueError("streaming is supported only for GET/HEAD/POST")
        read_size = max(1, int(chunk_size))
        idle_timeout = self.timeout if timeout is None else max(0.001, float(timeout))

        def send(
            method_value: str, current_url: str, headers_value: dict[str, str], body_value: bytes | None
        ) -> HttpResponse:
            key = _origin(current_url)
            connection: http.client.HTTPConnection | None = None
            response: http.client.HTTPResponse | None = None
            active_sock: Any | None = None
            reusable = False
            received = 0
            status = 0
            response_headers: dict[str, str] = {}
            try:
                connection, _reused = self._acquire(key, idle_timeout)

                def apply_deadline() -> None:
                    assert connection is not None
                    remaining = deadline - time.monotonic() if deadline is not None else idle_timeout
                    if remaining <= 0:
                        raise TimeoutError("HTTP stream deadline exceeded")
                    connection.timeout = min(idle_timeout, remaining)
                    if connection.sock is not None:
                        connection.sock.settimeout(connection.timeout)

                apply_deadline()
                connection.request(method_value, _request_path(current_url), body=body_value, headers=headers_value)
                active_sock = connection.sock
                if active_sock is not None:
                    with self._lock:
                        closed = self._closed
                        if not closed:
                            self._active_sockets.add(active_sock)
                    if closed:
                        active_sock.shutdown(socket.SHUT_RDWR)
                apply_deadline()
                response = connection.getresponse()
                status = int(response.status)
                response_headers = {str(name): str(value) for name, value in response.getheaders()}
                with self._lock:
                    self._stats["requests"] += 1
                if on_response is not None:
                    on_response(status, response_headers)
                redirect = status in {301, 302, 303, 307, 308}
                encoding = str(response.getheader("Content-Encoding") or "").strip().lower()
                if 200 <= status < 300 and not redirect:
                    if encoding not in {"", "identity"}:
                        return HttpResponse(status, b"", response_headers, error="unsupported_content_encoding")
                    while True:
                        apply_deadline()
                        chunk = response.read1(read_size)
                        if not chunk:
                            break
                        received += len(chunk)
                        on_chunk(chunk)
                    remaining_length = getattr(response, "length", None)
                    if isinstance(remaining_length, int) and remaining_length > 0:
                        raise ConnectionError("unexpected EOF: incomplete HTTP stream")
                    reusable = not response.will_close
                return HttpResponse(status, b"", response_headers)
            except Exception as exc:
                return HttpResponse(
                    status, b"", response_headers, error=normalize_http_error(exc), truncated=received > 0
                )
            finally:
                if active_sock is not None:
                    with self._lock:
                        self._active_sockets.discard(active_sock)
                if response is not None:
                    try:
                        response.close()
                    except OSError:
                        reusable = False
                if connection is not None:
                    self._release(key, connection, reusable)

        result = follow_redirects(
            send,
            method,
            url,
            headers=merge_custom_http_headers({"Accept-Encoding": "identity", **dict(headers or {})}),
            body=body,
            allow_cross_origin=allow_cross_origin_redirects,
            preserve_authorization=preserve_authorization_on_cross_origin,
        )
        pin_http_redirect_path(result, method=method)
        return result

    def request_once(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
        timeout: float | None = None,
        response_size_cap: int = 256 * 1024,
    ) -> HttpResponse:
        """Send one request without following redirects (for CSRF/session login flows)."""
        if self._closed:
            raise RuntimeError("HTTP session pool is closed")
        timeout_value = self.timeout if timeout is None else max(0.001, float(timeout))
        optional_kwargs: dict[str, Any] = {}
        if timeout is not None:
            optional_kwargs["deadline"] = time.monotonic() + timeout_value
        response, _error, _reused = self._request_once(
            str(method).upper(),
            str(url),
            headers=merge_custom_http_headers(headers),
            body=body,
            timeout=timeout_value,
            response_size_cap=response_size_cap,
            **optional_kwargs,
        )
        return response

    def stats(self) -> dict[str, int]:
        with self._lock:
            return dict(self._stats)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            connections = list(self._connections)
            active_sockets = list(self._active_sockets)
            self._connections.clear()
            self._active_sockets.clear()
            self._idle.clear()
        for sock in active_sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        for connection in connections:
            try:
                sock = getattr(connection, "sock", None)
                if sock is not None:
                    shutdown = getattr(sock, "shutdown", None)
                    try:
                        if callable(shutdown):
                            shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                connection.close()
            except OSError:
                pass


__all__ = ["HttpSessionPool"]
