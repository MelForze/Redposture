"""Numeric-only resolver for the private detection event loop.

Some native SDKs explicitly call loop.getaddrinfo even for IP literals. The
standard implementation creates executor jobs; numeric-only resolution needs
neither DNS nor a thread. Unknown names delegate the whole target to legacy
verification. A task-local shared list survives SDK exception normalization and
is also inherited by its monitoring child tasks.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from contextvars import ContextVar
from typing import Any, cast

from .async_http_detect import AsyncHttpFallback

resolver_fallbacks: ContextVar[list[str] | None] = ContextVar("detect_resolver_fallbacks", default=None)


async def numeric_getaddrinfo(
    host: Any, port: Any, *, family: int = 0, type: int = 0, proto: int = 0, flags: int = 0
) -> list[Any]:
    text = str(host or "")
    try:
        text = host.decode("ascii") if isinstance(host, bytes) else text
        ipaddress.ip_address(text)
        if "%" in text or not str(port).isascii() or not str(port).isdigit():
            raise ValueError("scope or service requires resolution")
    except (ValueError, UnicodeError) as exc:
        failures = resolver_fallbacks.get()
        if failures is not None:
            failures.append(text)
        raise AsyncHttpFallback(f"native driver requires legacy resolver: {text}") from exc
    return socket.getaddrinfo(text, port, family, type, proto, flags | socket.AI_NUMERICHOST | socket.AI_NUMERICSERV)


def install_numeric_resolver() -> None:
    """Called only at startup of our private AsyncDetectScheduler event loop."""
    loop = asyncio.get_running_loop()
    cast(Any, loop).getaddrinfo = numeric_getaddrinfo
