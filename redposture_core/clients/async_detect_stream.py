"""Bounded lifecycle helpers for native database detection streams."""

from __future__ import annotations

import asyncio
import ipaddress
from typing import Any

from .async_http_detect import AsyncHttpFallback


def require_numeric_host(host: str) -> None:
    """Avoid asyncio.open_connection's uncancellable executor DNS resolver."""
    try:
        ipaddress.ip_address(host)
    except ValueError as exc:
        raise AsyncHttpFallback("hostname requires synchronous resolver") from exc
    if "%" in host:
        raise AsyncHttpFallback("scoped IPv6 requires synchronous resolver")


def _abort(writer: Any) -> None:
    writer.close()
    writer.transport.abort()


async def close_stream(writer: Any, *, terminate: bytes | None = None) -> None:
    """Spend at most 250ms flushing termination and completing TLS shutdown."""
    task = asyncio.current_task()
    if task is not None and task.cancelling():
        _abort(writer)
        return

    async def shutdown() -> None:
        try:
            if terminate is not None:
                writer.write(terminate)
                await writer.drain()
        finally:
            writer.close()
        await writer.wait_closed()

    try:
        await asyncio.wait_for(shutdown(), 0.25)
    except asyncio.CancelledError:
        _abort(writer)
        raise
    except Exception:
        _abort(writer)


def reraise_fallback(error: BaseException) -> None:
    """Preserve resolver/compatibility fallback through driver error wrappers."""
    pending = [error]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, AsyncHttpFallback):
            raise current
        for nested in (current.__cause__, current.__context__):
            if isinstance(nested, BaseException):
                pending.append(nested)
