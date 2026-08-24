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
from ...clients.tls_cache import clear_tls_context_cache, shared_client_ssl_context

_MAX_REDIRECTS = 5


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
        if self.use_https:
            return http.client.HTTPSConnection(
                self.host,
                self.port,
                timeout=self.timeout,
                context=shared_ssl_context(insecure=self.insecure, ca_file=self.ca_file),
            )
        return http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)

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
        method_value = str(method or "GET").upper()
        body_value = body.encode("utf-8") if isinstance(body, str) else body
        headers_value = {str(key): str(value) for key, value in (headers or {}).items()}
        parsed = urllib.parse.urlsplit(str(url))
        original_origin = (
            parsed.scheme.lower(),
            str(parsed.hostname or "").lower(),
            parsed.port or (443 if parsed.scheme == "https" else 80),
        )
        path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        request_url = str(url)
        current_url = request_url

        for _redirect in range(_MAX_REDIRECTS + 1):
            response = self._request_once(
                method_value,
                path,
                headers_value,
                body_value,
                timeout=timeout,
                response_size_cap=response_size_cap,
            )
            if response.error or response.status not in {301, 302, 303, 307, 308}:
                return HttpResponse(
                    status=response.status,
                    body=response.body,
                    headers=response.headers,
                    error=response.error,
                    truncated=response.truncated,
                    request_url=request_url,
                    final_url=current_url,
                    redirect_history=(request_url,) if current_url != request_url else (),
                )
            location = next((value for key, value in response.headers.items() if key.lower() == "location"), "")
            if not location:
                return response
            redirected_url = urllib.parse.urljoin(current_url, location)
            redirected = urllib.parse.urlsplit(redirected_url)
            redirect_origin = (
                redirected.scheme.lower(),
                str(redirected.hostname or "").lower(),
                redirected.port or (443 if redirected.scheme == "https" else 80),
            )
            if redirect_origin != original_origin:
                return HttpResponse(
                    status=response.status,
                    body=response.body,
                    headers=response.headers,
                    error=f"cross-origin redirect blocked: {current_url} -> {redirected_url}",
                    request_url=request_url,
                    final_url=current_url,
                )
            current_url = redirected_url
            path = urllib.parse.urlunsplit(("", "", redirected.path or "/", redirected.query, ""))
            if response.status in {301, 302, 303} and method_value == "POST":
                method_value = "GET"
                body_value = None
                headers_value = {
                    k: v for k, v in headers_value.items() if k.lower() not in {"content-length", "content-type"}
                }
        return HttpResponse(
            status=0,
            body=b"",
            headers={},
            error="too many redirects",
            request_url=request_url,
            final_url=current_url,
        )

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
            normalized_path = join_http_target_path(path)
            self._connection.request(method, normalized_path, body=body, headers=dict(headers))
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
