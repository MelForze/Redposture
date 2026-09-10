"""Thread-confined persistent HTTP transport for Kubernetes API targets."""

from __future__ import annotations

import http.client
import os
import threading
import urllib.parse
from collections.abc import Mapping
from functools import lru_cache
from typing import Any

from ...clients.http_api import (
    HttpApiClient,
    HttpClientConfig,
    HttpResponse,
    join_http_target_path,
    normalize_http_error,
)
from ...clients.http_redirects import follow_redirects, http_origin
from ...clients.tls_cache import clear_tls_context_cache, shared_client_ssl_context


def _ca_cache_key(ca_file: str | None) -> tuple[str, int, int] | None:
    raw = str(ca_file or "").strip()
    if not raw:
        return None
    path = os.path.realpath(raw)
    stat = os.stat(path)
    return path, int(stat.st_mtime_ns), int(stat.st_size)


def shared_ssl_context(*, insecure: bool, ca_file: str | None):
    return shared_client_ssl_context(insecure=insecure, ca_file=ca_file)


@lru_cache(maxsize=32)
def _cached_proxy_client(
    proxy: Any,
    insecure: bool,
    ca_key: tuple[str, int, int] | None,
    response_size_cap: int,
) -> HttpApiClient:
    context = shared_client_ssl_context(
        insecure=bool(insecure),
        ca_file=ca_key[0] if ca_key else None,
    )
    return HttpApiClient(
        HttpClientConfig(
            insecure=bool(insecure),
            ca_file=ca_key[0] if ca_key else None,
            proxy=proxy,
            response_size_cap=max(0, int(response_size_cap)),
            ssl_context=context,
        )
    )


def shared_proxy_client(
    proxy: Any,
    *,
    insecure: bool,
    ca_file: str | None,
    response_size_cap: int,
) -> HttpApiClient:
    return _cached_proxy_client(
        proxy,
        bool(insecure),
        None if insecure else _ca_cache_key(ca_file),
        max(0, int(response_size_cap)),
    )


def clear_transport_caches() -> None:
    """Clear process caches for deterministic tests and changed trust stores."""

    _cached_proxy_client.cache_clear()
    clear_tls_context_cache()


class KubeApiHttpSession:
    """One direct HTTP/1.1 connection owned by one target worker."""

    def __init__(
        self,
        host: str,
        port: int,
        *,
        use_https: bool,
        timeout: float,
        insecure: bool,
        ca_file: str | None,
    ) -> None:
        normalized_host = str(host or "").strip().strip("[]")
        if not normalized_host or any(char in normalized_host for char in "\r\n"):
            raise ValueError("invalid Kubernetes API target host")
        self.host = normalized_host
        self.port = int(port)
        self.use_https = bool(use_https)
        self.timeout = max(0.1, float(timeout))
        self.insecure = bool(insecure)
        self.ca_file = ca_file
        self._connection_origin = ("https" if use_https else "http", self.host, self.port)
        self._connection: http.client.HTTPConnection | None = None
        self._owner_thread_id: int | None = None
        self._closed = False
        self._stats = {"connections": 0, "reused": 0, "requests": 0, "retries": 0}

    def _claim_thread(self) -> None:
        owner = threading.get_ident()
        if self._owner_thread_id is None:
            self._owner_thread_id = owner
        elif self._owner_thread_id != owner:
            raise RuntimeError("KubeApiHttpSession cannot be shared across threads")

    def _new_connection(self) -> http.client.HTTPConnection:
        self._stats["connections"] += 1
        scheme, host, port = self._connection_origin
        if scheme == "https":
            return http.client.HTTPSConnection(
                host,
                port,
                timeout=self.timeout,
                context=shared_ssl_context(insecure=self.insecure, ca_file=self.ca_file),
            )
        return http.client.HTTPConnection(host, port, timeout=self.timeout)

    def _close_connection(self) -> None:
        connection = self._connection
        self._connection = None
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass

    def close(self) -> None:
        self._closed = True
        self._close_connection()

    def stats(self) -> dict[str, int]:
        return dict(self._stats)

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | str | None = None,
        timeout: float | None = None,
        response_size_cap: int = 10 * 1024 * 1024,
    ) -> HttpResponse:
        self._claim_thread()
        if self._closed:
            raise RuntimeError("KubeApiHttpSession is closed")
        parsed = urllib.parse.urlsplit(url)
        initial_url = urllib.parse.urlunsplit(
            (parsed.scheme, parsed.netloc, join_http_target_path(parsed.path), parsed.query, "")
        )

        def send(method: str, url: str, headers: dict[str, str], body: bytes | None) -> HttpResponse:
            origin = http_origin(url)
            if origin != self._connection_origin:
                self._close_connection()
                self._connection_origin = origin
            parsed = urllib.parse.urlsplit(url)
            path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
            return self._request_once(method, path, headers, body, timeout=timeout, response_size_cap=response_size_cap)

        return follow_redirects(send, method, initial_url, headers=headers, body=body)

    def _request_once(
        self,
        method: str,
        path: str,
        headers: Mapping[str, str],
        body: bytes | None,
        *,
        timeout: float | None,
        response_size_cap: int,
    ) -> HttpResponse:
        response: http.client.HTTPResponse | None = None
        try:
            if self._connection is None:
                self._connection = self._new_connection()
            else:
                self._stats["reused"] += 1
            self._connection.timeout = float(timeout if timeout is not None else self.timeout)
            connection_socket = getattr(self._connection, "sock", None)
            if connection_socket is not None:
                connection_socket.settimeout(self._connection.timeout)
            self._connection.request(method, path, body=body, headers=dict(headers))
            response = self._connection.getresponse()
            self._stats["requests"] += 1
            cap = max(0, int(response_size_cap))
            payload = response.read(cap + 1)
            truncated = len(payload) > cap
            if truncated:
                payload = payload[:cap]
            result = HttpResponse(
                status=int(response.status),
                body=payload,
                headers={str(key): str(value) for key, value in response.getheaders()},
                truncated=truncated,
            )
            if truncated or response.will_close:
                self._close_connection()
            return result
        except Exception as exc:
            self._close_connection()
            return HttpResponse(status=0, body=b"", headers={}, error=normalize_http_error(exc))
        finally:
            if response is not None:
                try:
                    response.close()
                except Exception:
                    pass


__all__ = [
    "KubeApiHttpSession",
    "clear_transport_caches",
    "shared_proxy_client",
    "shared_ssl_context",
]
