"""Thread-confined persistent HTTP/1.1 transport for direct Elastic targets.

The shared :class:`~redposture_core.clients.http_api.HttpApiClient` remains the
transport for proxy-aware requests.  This small client is intentionally direct
only and is designed to be owned by one Elastic worker for the lifetime of one
target phase.
"""

from __future__ import annotations

import errno
import http.client
import ssl
import threading
from collections.abc import Mapping
from types import TracebackType

from ...clients.http_api import HttpResponse, join_http_target_path, normalize_http_error
from ...clients.tls_cache import shared_client_ssl_context

_STALE_SOCKET_ERRNOS = frozenset(
    value
    for value in (
        getattr(errno, "ECONNABORTED", None),
        getattr(errno, "ECONNRESET", None),
        getattr(errno, "ENOTCONN", None),
        getattr(errno, "EPIPE", None),
        getattr(errno, "ESHUTDOWN", None),
    )
    if value is not None
)


def _is_read_only_elastic_request(method: str, path: str) -> bool:
    if method in {"GET", "HEAD"}:
        return True
    if method != "POST":
        return False
    normalized_path = path.partition("?")[0].rstrip("/") or "/"
    return (
        normalized_path.endswith("/_search")
        or normalized_path.endswith("/_msearch")
        or normalized_path.endswith("/_field_caps")
        or normalized_path == "/_security/user/_has_privileges"
    )


def _build_ssl_context(*, insecure: bool, ca_file: str | None) -> ssl.SSLContext:
    return shared_client_ssl_context(insecure=insecure, ca_file=ca_file)


def _is_stale_keep_alive_error(exc: BaseException) -> bool:
    if isinstance(
        exc,
        (
            http.client.CannotSendRequest,
            http.client.RemoteDisconnected,
            http.client.ResponseNotReady,
            BrokenPipeError,
            ConnectionAbortedError,
            ConnectionResetError,
            ssl.SSLEOFError,
            ssl.SSLZeroReturnError,
        ),
    ):
        return True
    if isinstance(exc, OSError) and exc.errno in _STALE_SOCKET_ERRNOS:
        return True
    if isinstance(exc, ssl.SSLError):
        detail = str(exc).lower()
        return "eof" in detail or "closed" in detail
    return False


class ElasticHttpSession:
    """A single-target direct HTTP/1.1 keep-alive session.

    The instance is deliberately not thread-safe.  Its first request or
    reusable ``close_connection()`` claims the current thread, and later use
    from another thread raises :class:`RuntimeError`.  Create one instance per
    worker/target phase.  Terminal ``close()`` is the sole exception so the
    runtime's supervisor can release sockets during cancellation.

    ``close_connection()`` drops the active socket while leaving the session
    reusable.  ``close()`` permanently closes the session.
    """

    def __init__(
        self,
        host: str,
        port: int,
        timeout: float = 1.0,
        insecure: bool = False,
        ca_file: str | None = None,
        response_cap: int = 10 * 1024 * 1024,
    ) -> None:
        normalized_host = str(host or "").strip()
        if normalized_host.startswith("[") and normalized_host.endswith("]"):
            normalized_host = normalized_host[1:-1]
        if not normalized_host or "\r" in normalized_host or "\n" in normalized_host:
            raise ValueError("invalid Elastic target host")
        normalized_port = int(port)
        if not 1 <= normalized_port <= 65535:
            raise ValueError("invalid Elastic target port")

        self.host = normalized_host
        self.port = normalized_port
        self.timeout = max(0.0, float(timeout))
        self.response_cap = max(0, int(response_cap))
        # Loading the platform CA bundle is relatively expensive.  Keep HTTP
        # mass scans cheap by constructing the context only if this target
        # actually needs HTTPS, then reuse it across HTTPS reconnects.
        self._insecure = bool(insecure)
        self._ca_file = ca_file
        self._ssl_context: ssl.SSLContext | None = None
        self._connection: http.client.HTTPConnection | None = None
        self._scheme: str | None = None
        self._requests_on_connection = 0
        self._owner_thread_id: int | None = None
        self._closed = False

    @property
    def connected_scheme(self) -> str | None:
        """Return the scheme assigned to the active connection, if any."""

        return self._scheme

    @property
    def closed(self) -> bool:
        return self._closed

    def _claim_thread(self) -> None:
        thread_id = threading.get_ident()
        if self._owner_thread_id is None:
            self._owner_thread_id = thread_id
        elif self._owner_thread_id != thread_id:
            raise RuntimeError("ElasticHttpSession cannot be shared across threads")

    def _authority(self, scheme: str) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        default_port = 443 if scheme == "https" else 80
        return host if self.port == default_port else f"{host}:{self.port}"

    def _new_connection(self, scheme: str) -> http.client.HTTPConnection:
        if scheme == "https":
            if self._ssl_context is None:
                self._ssl_context = _build_ssl_context(
                    insecure=self._insecure,
                    ca_file=self._ca_file,
                )
            return http.client.HTTPSConnection(
                self.host,
                self.port,
                timeout=self.timeout,
                context=self._ssl_context,
            )
        return http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)

    def _close_connection_unchecked(self) -> None:
        connection = self._connection
        self._connection = None
        self._scheme = None
        self._requests_on_connection = 0
        if connection is not None:
            try:
                connection.close()
            except Exception:
                # Closing is best-effort and must not hide the request result.
                pass

    def close_connection(self) -> None:
        """Close the current socket; a later request may open another one."""

        self._claim_thread()
        self._close_connection_unchecked()

    def _ensure_connection(self, scheme: str) -> tuple[http.client.HTTPConnection, bool]:
        if self._scheme != scheme:
            self._close_connection_unchecked()
        if self._connection is None:
            self._connection = self._new_connection(scheme)
            self._scheme = scheme
        return self._connection, self._requests_on_connection > 0

    @staticmethod
    def _normalize_path(path: str) -> str:
        normalized = str(path or "/")
        if "\r" in normalized or "\n" in normalized:
            raise ValueError("invalid HTTP request path")
        if not normalized.startswith("/"):
            normalized = f"/{normalized}"
        return join_http_target_path(normalized)

    def _request_once(
        self,
        scheme: str,
        method: str,
        path: str,
        headers: Mapping[str, str],
        data: bytes | None,
    ) -> tuple[HttpResponse, BaseException | None, bool]:
        connection, reused = self._ensure_connection(scheme)
        response: http.client.HTTPResponse | None = None
        try:
            connection.request(method, path, body=data, headers=dict(headers))
            response = connection.getresponse()
            payload = response.read(self.response_cap + 1)
            truncated = len(payload) > self.response_cap
            if truncated:
                payload = payload[: self.response_cap]
            normalized_headers = {str(key): str(value) for key, value in response.getheaders()}
            result = HttpResponse(
                status=int(response.status),
                body=payload,
                headers=normalized_headers,
                error=None,
                truncated=truncated,
            )
            self._requests_on_connection += 1
            if truncated or response.will_close:
                self._close_connection_unchecked()
            return result, None, reused
        except Exception as exc:
            self._close_connection_unchecked()
            return (
                HttpResponse(status=0, body=b"", headers={}, error=normalize_http_error(exc)),
                exc,
                reused,
            )
        finally:
            if response is not None:
                try:
                    response.close()
                except Exception:
                    pass

    def request(
        self,
        scheme: str,
        method: str,
        path: str,
        headers: Mapping[str, str] | None = None,
        data: bytes | str | None = None,
    ) -> HttpResponse:
        """Send one direct request and return a normalized shared response.

        A stale reused connection is reopened once for GET/HEAD and explicitly
        read-only Elastic POST endpoints.  Initial connection failures,
        non-stale failures, and mutating requests are not retried here;
        higher-level retry policy remains the caller's job.
        """

        self._claim_thread()
        if self._closed:
            raise RuntimeError("ElasticHttpSession is closed")

        normalized_scheme = str(scheme or "").strip().lower()
        if normalized_scheme not in {"http", "https"}:
            return HttpResponse(
                status=0,
                body=b"",
                headers={},
                error=f"unsupported Elastic HTTP scheme: {normalized_scheme or '-'}",
            )
        normalized_method = str(method or "GET").strip().upper()
        try:
            normalized_path = self._normalize_path(path)
            normalized_headers = {str(key): str(value) for key, value in (headers or {}).items()}
            for key, value in normalized_headers.items():
                if not key or "\r" in key or "\n" in key or "\r" in value or "\n" in value:
                    raise ValueError("invalid HTTP request header")
        except (TypeError, ValueError) as exc:
            return HttpResponse(status=0, body=b"", headers={}, error=normalize_http_error(exc))

        body = data.encode("utf-8") if isinstance(data, str) else data
        lower_header_names = {key.lower() for key in normalized_headers}
        if "host" not in lower_header_names:
            normalized_headers["Host"] = self._authority(normalized_scheme)
        if "connection" not in lower_header_names:
            normalized_headers["Connection"] = "keep-alive"
        if body is not None and "content-length" not in lower_header_names:
            normalized_headers["Content-Length"] = str(len(body))

        result, request_error, reused = self._request_once(
            normalized_scheme,
            normalized_method,
            normalized_path,
            normalized_headers,
            body,
        )
        if (
            request_error is not None
            and reused
            and _is_read_only_elastic_request(normalized_method, normalized_path)
            and _is_stale_keep_alive_error(request_error)
        ):
            result, _retry_exc, _retry_reused = self._request_once(
                normalized_scheme,
                normalized_method,
                normalized_path,
                normalized_headers,
                body,
            )
        return result

    def close(self) -> None:
        """Permanently close the session and its active connection."""

        if self._closed:
            return
        # Mark terminal before touching the socket so an owner-thread request
        # cannot start after supervisor-driven cleanup begins.  ``socket.close``
        # is safe as a best-effort cancellation mechanism for an in-flight
        # request; that request will return its normalized transport error.
        self._closed = True
        self._close_connection_unchecked()

    def __enter__(self) -> ElasticHttpSession:
        self._claim_thread()
        if self._closed:
            raise RuntimeError("ElasticHttpSession is closed")
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        self.close()


__all__ = ["ElasticHttpSession"]
