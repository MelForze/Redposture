"""HTTP client helpers for exporter scan/collect requests."""

from __future__ import annotations

import errno
import http.client
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

from .http_pool import get_active_http_pool, pool_get_compat


class HTTPResponseDetails(dict[str, Any]):
    """Mapping-compatible response details with lossless bytes out-of-band."""

    def __init__(self, values: dict[str, Any], *, raw_body: bytes) -> None:
        super().__init__(values)
        self.raw_body = raw_body


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Return redirects to the caller instead of silently following them.

    Exporter discovery treats the response body as evidence about the endpoint
    that was requested.  Following a redirect to an unrelated login page makes
    that evidence ambiguous and used to differ depending on whether the pooled
    or urllib transport happened to be active.
    """

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirectHandler())
_ACTIVE_TLS_CONTEXT = threading.local()


def build_exporter_tls_context(
    *,
    insecure: bool = False,
    ca_file: str | None = None,
    cert_file: str | None = None,
    key_file: str | None = None,
) -> ssl.SSLContext | None:
    """Build the TLS context shared by exporter urllib and pooled paths."""

    if bool(cert_file) != bool(key_file):
        raise ValueError("--tls-cert and --tls-key must be provided together")
    if not any((insecure, ca_file, cert_file, key_file)):
        return None
    context = ssl.create_default_context(cafile=ca_file or None)
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    if cert_file and key_file:
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    return context


@contextmanager
def activate_exporter_tls_context(context: ssl.SSLContext | None) -> Iterator[None]:
    sentinel = object()
    previous = getattr(_ACTIVE_TLS_CONTEXT, "value", sentinel)
    _ACTIVE_TLS_CONTEXT.value = context
    try:
        yield
    finally:
        if previous is sentinel:
            delattr(_ACTIVE_TLS_CONTEXT, "value")
        else:
            _ACTIVE_TLS_CONTEXT.value = previous


def _default_urlopen(request: Any, *, timeout: float) -> Any:
    context = getattr(_ACTIVE_TLS_CONTEXT, "value", None)
    if context is None:
        return _NO_REDIRECT_OPENER.open(request, timeout=timeout)
    opener = urllib.request.build_opener(
        _NoRedirectHandler(),
        urllib.request.HTTPSHandler(context=context),
    )
    return opener.open(request, timeout=timeout)


def format_http_host(host: str) -> str:
    """Format a DNS/IP host for use in an HTTP authority component."""

    value = str(host or "").strip()
    if value.startswith("[") and value.endswith("]"):
        return value
    if ":" in value:
        return f"[{value}]"
    return value


def build_http_url(host: str, port: int, path: str, *, scheme: str = "http") -> str:
    endpoint = str(path or "")
    if not endpoint.startswith("/"):
        raise ValueError("HTTP endpoint path must start with '/'")
    normalized_scheme = str(scheme or "http").strip().lower()
    if normalized_scheme not in {"http", "https"}:
        raise ValueError(f"unsupported exporter URL scheme: {normalized_scheme or '-'}")
    return f"{normalized_scheme}://{format_http_host(host)}:{int(port)}{endpoint}"


def retry_delay(attempt_index: int) -> float:
    # 0.20, 0.40, 0.80, ... capped to 1.50 seconds.
    return min(1.50, 0.20 * (2**attempt_index))


def unwrap_network_error(exc: BaseException) -> BaseException:
    if isinstance(exc, urllib.error.URLError):
        reason = exc.reason
        if isinstance(reason, BaseException):
            return reason
    return exc


def should_retry_http_exception(exc: BaseException) -> bool:
    root = unwrap_network_error(exc)
    if isinstance(root, (TimeoutError, socket.timeout)):
        return True
    if isinstance(root, socket.gaierror):
        # Retry only temporary DNS resolution failures.
        eai_again = getattr(socket, "EAI_AGAIN", None)
        return eai_again is not None and getattr(root, "errno", None) == eai_again
    if isinstance(root, OSError):
        return getattr(root, "errno", None) in {
            errno.ETIMEDOUT,
            errno.EAGAIN,
            errno.EWOULDBLOCK,
            errno.EINTR,
        }
    return False


def http_get_text(
    url: str,
    timeout: float,
    retries: int = 1,
    *,
    sleep_fn: Callable[[float], None] = time.sleep,
    urlopen_fn: Callable[..., Any] | None = None,
) -> tuple[int, str]:
    pool = get_active_http_pool()
    if pool is not None:
        attempts = max(1, retries + 1)
        for attempt in range(attempts):
            status, raw, _content_type, error, _truncated = pool_get_compat(pool, url, timeout)
            if error is None:
                body = raw.decode("utf-8", errors="replace")
                return int(status or 0), body
            should_retry = should_retry_http_exception(error) or isinstance(
                unwrap_network_error(error), http.client.HTTPException
            )
            if attempt >= attempts - 1 or not should_retry:
                raise error
            sleep_fn(retry_delay(attempt))
        raise RuntimeError("unreachable")

    req = urllib.request.Request(url, headers={"User-Agent": "RedPosture/1.0"})
    opener = urlopen_fn or _default_urlopen
    attempts = max(1, retries + 1)
    for attempt in range(attempts):
        try:
            with opener(req, timeout=timeout) as response:
                status = int(response.status)
                body = response.read().decode("utf-8", errors="replace")
                return status, body
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            return exc.code, body
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            if attempt >= attempts - 1 or not should_retry_http_exception(exc):
                raise
            sleep_fn(retry_delay(attempt))
    raise RuntimeError("unreachable")


def http_get_details(
    url: str,
    timeout: float,
    retries: int = 1,
    *,
    max_bytes: int | None = None,
    monotonic_fn: Callable[[], float] = time.monotonic,
    sleep_fn: Callable[[float], None] = time.sleep,
    urlopen_fn: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    pool = get_active_http_pool()
    if pool is not None:
        attempts = max(1, retries + 1)
        for attempt in range(attempts):
            started = monotonic_fn()
            status, raw, content_type, error, truncated = pool_get_compat(
                pool,
                url,
                timeout,
                max_bytes=max_bytes,
            )
            elapsed_ms = int((monotonic_fn() - started) * 1000)
            if error is None:
                body = raw.decode("utf-8", errors="replace")
                return HTTPResponseDetails(
                    {
                        "status": status,
                        "body": body,
                        "content_type": content_type,
                        "elapsed_ms": elapsed_ms,
                        "truncated": truncated,
                        "error": None,
                    },
                    raw_body=raw,
                )
            should_retry = should_retry_http_exception(error) or isinstance(
                unwrap_network_error(error), http.client.HTTPException
            )
            if attempt < attempts - 1 and should_retry:
                sleep_fn(retry_delay(attempt))
                continue
            return HTTPResponseDetails(
                {
                    "status": None,
                    "body": "",
                    "content_type": None,
                    "elapsed_ms": elapsed_ms,
                    "truncated": False,
                    "error": str(error),
                },
                raw_body=b"",
            )
        raise RuntimeError("unreachable")

    req = urllib.request.Request(url, headers={"User-Agent": "RedPosture/1.0"})
    opener = urlopen_fn or _default_urlopen
    attempts = max(1, retries + 1)
    for attempt in range(attempts):
        started = monotonic_fn()
        try:
            with opener(req, timeout=timeout) as response:
                truncated = False
                if max_bytes is None:
                    raw = response.read()
                else:
                    raw = response.read(max_bytes + 1)
                    truncated = len(raw) > max_bytes
                    if truncated:
                        raw = raw[:max_bytes]
                elapsed_ms = int((monotonic_fn() - started) * 1000)
                body = raw.decode("utf-8", errors="replace")
                return HTTPResponseDetails(
                    {
                        "status": int(response.status),
                        "body": body,
                        "content_type": response.headers.get("Content-Type"),
                        "elapsed_ms": elapsed_ms,
                        "truncated": truncated,
                        "error": None,
                    },
                    raw_body=raw,
                )
        except urllib.error.HTTPError as exc:
            truncated = False
            if max_bytes is None:
                raw = exc.read()
            else:
                raw = exc.read(max_bytes + 1)
                truncated = len(raw) > max_bytes
                if truncated:
                    raw = raw[:max_bytes]
            elapsed_ms = int((monotonic_fn() - started) * 1000)
            body = raw.decode("utf-8", errors="replace")
            return HTTPResponseDetails(
                {
                    "status": int(exc.code),
                    "body": body,
                    "content_type": exc.headers.get("Content-Type") if exc.headers else None,
                    "elapsed_ms": elapsed_ms,
                    "truncated": truncated,
                    "error": None,
                },
                raw_body=raw,
            )
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            elapsed_ms = int((monotonic_fn() - started) * 1000)
            if attempt < attempts - 1 and should_retry_http_exception(exc):
                sleep_fn(retry_delay(attempt))
                continue
            return HTTPResponseDetails(
                {
                    "status": None,
                    "body": "",
                    "content_type": None,
                    "elapsed_ms": elapsed_ms,
                    "truncated": False,
                    "error": str(exc),
                },
                raw_body=b"",
            )
    raise RuntimeError("unreachable")


__all__ = [
    "HTTPResponseDetails",
    "activate_exporter_tls_context",
    "build_exporter_tls_context",
    "build_http_url",
    "format_http_host",
    "http_get_details",
    "http_get_text",
    "retry_delay",
    "should_retry_http_exception",
    "unwrap_network_error",
]
