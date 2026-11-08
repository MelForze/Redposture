"""Bounded ownership transfer from native HTTP detection to synchronous pools."""

from __future__ import annotations

import asyncio
import socket
import ssl
import threading
from collections.abc import Callable
from typing import Any, cast
from urllib.parse import urlsplit

from ..detect_backoff import retain_detect_slot
from .async_http_detect import AsyncDetectionHttp
from .async_retained_socket import RetainedSocketIO
from .http_session import HttpSessionPool


class HttpHandoffBudget:
    def __init__(self, limit: int) -> None:
        self.limit = max(0, int(limit))
        self._active = 0
        self._lock = threading.Lock()

    @property
    def active(self) -> int:
        with self._lock:
            return self._active

    def acquire(self) -> Callable[[], None] | None:
        with self._lock:
            if self._active >= self.limit:
                return None
            self._active += 1
        released = False

        def release() -> None:
            nonlocal released
            with self._lock:
                if not released:
                    released = True
                    self._active -= 1

        return release


class _SocketStream:
    """No asyncio transport/read-ahead buffer; TLS stays in the same SSLSocket."""

    def __init__(self, io: RetainedSocketIO, sock: socket.socket) -> None:
        self.io, self.sock = io, sock
        self.pending = b""

    @property
    def transport(self) -> _SocketStream:
        return self

    async def read(self, size: int) -> bytes:
        return await self.io.recv(self.sock, size)

    def write(self, data: bytes) -> None:
        self.pending += data

    async def drain(self) -> None:
        await self.io.sendall(self.sock, self.pending)
        self.pending = b""

    def is_closing(self) -> bool:
        return self.sock.fileno() < 0

    def close(self) -> None:
        self.io.sockets.pop(self.sock, None)
        self.sock.close()

    abort = close

    async def wait_closed(self) -> None:
        pass


class RetainedDetectionHttp(AsyncDetectionHttp):
    def __init__(self, *, budget: HttpHandoffBudget, **options: Any) -> None:
        super().__init__(**options)
        self.budget = budget
        self._io: RetainedSocketIO | None = None
        self._pool: HttpSessionPool | None = None
        self._socket_context: ssl.SSLContext | None = None
        self._anonymous = True
        self._pinned: tuple[tuple[str, str, int], HttpSessionPool] | None = None

    def pin_pool(self, pool: HttpSessionPool) -> None:
        """Preserve an already confirmed surface while checking another one."""
        if self._connection is not None and self._anonymous:
            self._pinned = (self._connection[0], pool)

    def prefer_pinned_pool(self) -> None:
        if self._pinned is not None and self._connection is not None:
            if self._connection[0] == self._pinned[0]:
                self._pool = self._pinned[1]

    async def bind_pool(self, pool: HttpSessionPool) -> None:
        if pool is not self._pool and not self._anonymous:
            await self.close()
        self._pool = pool

    async def _open_address(
        self, address: str, port: int, tls: ssl.SSLContext | None, timeout: float, *, server_hostname: str
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        if self._io is None:
            self._io = RetainedSocketIO()
            self._io.check_supported()
        sock = await self._io.open((address, port), timeout)
        if tls is not None:
            sock = await self._io.wrap(tls, sock, server_hostname=server_hostname)
        self._socket_context = tls
        self._anonymous = True
        stream = _SocketStream(self._io, sock)
        return cast(asyncio.StreamReader, stream), cast(asyncio.StreamWriter, stream)

    async def _once(self, url: str, timeout: float, headers: dict[str, str], **options: Any) -> Any:
        parsed = urlsplit(url)
        origin = (parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
        if self._connection is not None and self._pinned is not None:
            if self._connection[0] == self._pinned[0] and origin != self._connection[0]:
                if self.handoff(self._pinned[1]):
                    self._pinned = None
        if self._connection is not None and urlsplit(url).scheme == "https":
            if self.ssl_context is not self._socket_context:
                await self.close()
        if self._connection is not None:
            stream = cast(_SocketStream, self._connection[2])
            stream.io.sockets[stream.sock] = timeout
        response = await super()._once(url, timeout, headers, **options)
        lowered = {key.lower(): str(value).lower() for key, value in headers.items()}
        if any(
            key in lowered
            for key in (
                "authorization",
                "proxy-authorization",
                "cookie",
                "x-api-key",
                "private-token",
                "x-vault-token",
                "x-consul-token",
            )
        ):
            self._anonymous = False
        if any(name.lower() == "set-cookie" for name in response.headers):
            self._anonymous = False
        if "close" in lowered.get("connection", ""):
            self._anonymous = False
        return response

    def handoff(self, destination: HttpSessionPool | None = None) -> bool:
        pool, current = destination if destination is not None else self._pool, self._connection
        if pool is None or current is None or self._buffer or not self._anonymous:
            return False
        key, _, stream = current
        writer = cast(_SocketStream, stream)
        if writer.pending or writer.is_closing():
            return False
        release = self.budget.acquire()
        if release is None:
            return False
        try:
            if not pool.adopt_socket(key, writer.sock, tls_context=self._socket_context, on_claim=release):
                release()
                return False
        except OSError:
            release()
            return False
        except BaseException:
            release()
            raise
        writer.io.sockets.pop(writer.sock, None)
        retain_detect_slot()
        self._connection = None
        return True

    async def close(self) -> None:
        try:
            await super().close()
        finally:
            if self._io is not None:
                self._io.close()
