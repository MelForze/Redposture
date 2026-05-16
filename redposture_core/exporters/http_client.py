"""HTTP client helpers for exporter scan/collect requests."""

from __future__ import annotations

import errno
import http.client
import socket
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

from .http_pool import get_active_http_pool, pool_get_compat


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
    urlopen_fn: Callable[..., Any] = urllib.request.urlopen,
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
    attempts = max(1, retries + 1)
    for attempt in range(attempts):
        try:
            with urlopen_fn(req, timeout=timeout) as response:
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
    urlopen_fn: Callable[..., Any] = urllib.request.urlopen,
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
                return {
                    "status": status,
                    "body": body,
                    "content_type": content_type,
                    "elapsed_ms": elapsed_ms,
                    "truncated": truncated,
                    "error": None,
                }
            should_retry = should_retry_http_exception(error) or isinstance(
                unwrap_network_error(error), http.client.HTTPException
            )
            if attempt < attempts - 1 and should_retry:
                sleep_fn(retry_delay(attempt))
                continue
            return {
                "status": None,
                "body": "",
                "content_type": None,
                "elapsed_ms": elapsed_ms,
                "truncated": False,
                "error": str(error),
            }
        raise RuntimeError("unreachable")

    req = urllib.request.Request(url, headers={"User-Agent": "RedPosture/1.0"})
    attempts = max(1, retries + 1)
    for attempt in range(attempts):
        started = monotonic_fn()
        try:
            with urlopen_fn(req, timeout=timeout) as response:
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
                return {
                    "status": int(response.status),
                    "body": body,
                    "content_type": response.headers.get("Content-Type"),
                    "elapsed_ms": elapsed_ms,
                    "truncated": truncated,
                    "error": None,
                }
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
            return {
                "status": int(exc.code),
                "body": body,
                "content_type": exc.headers.get("Content-Type") if exc.headers else None,
                "elapsed_ms": elapsed_ms,
                "truncated": truncated,
                "error": None,
            }
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            elapsed_ms = int((monotonic_fn() - started) * 1000)
            if attempt < attempts - 1 and should_retry_http_exception(exc):
                sleep_fn(retry_delay(attempt))
                continue
            return {
                "status": None,
                "body": "",
                "content_type": None,
                "elapsed_ms": elapsed_ms,
                "truncated": False,
                "error": str(exc),
            }
    raise RuntimeError("unreachable")


__all__ = [
    "http_get_details",
    "http_get_text",
    "retry_delay",
    "should_retry_http_exception",
    "unwrap_network_error",
]
