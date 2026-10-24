"""Native detection I/O with explicit ownership of transferable raw sockets.

The synchronous decision continuations use their original functions. This
interpreter alone replaces socket operations. No asyncio transport can prefetch
bytes, and TLS state remains in the very SSLSocket adopted by sync auth/data.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import time
from collections.abc import Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, replace
from typing import Any

from ..detection_io import DetectCall, DetectDelay, HttpRead, read_http
from . import transport
from .async_http_detect import AsyncHttpFallback


@asynccontextmanager
async def _socket_timeout(seconds: float | None) -> Any:
    try:
        async with asyncio.timeout(seconds):
            yield
    except TimeoutError as exc:
        # The synchronous classifiers and timeout escalation inspect this text.
        raise TimeoutError("timed out") from exc


class RetainedSocketIO:
    def __init__(self) -> None:
        self.loop = asyncio.get_running_loop()
        self.sockets: dict[socket.socket, float | None] = {}

    def check_supported(self) -> None:
        """Decline loops without readiness support before connecting a target."""
        left, right = socket.socketpair()
        try:
            self.loop.add_reader(left.fileno(), lambda: None)
            self.loop.remove_reader(left.fileno())
            self.loop.add_writer(left.fileno(), lambda: None)
            self.loop.remove_writer(left.fileno())
        except (AttributeError, NotImplementedError) as exc:
            raise AsyncHttpFallback("event loop has no raw socket readiness support") from exc
        finally:
            left.close()
            right.close()

    async def _ready(self, sock: socket.socket, *, write: bool = False) -> None:
        future = self.loop.create_future()
        descriptor = sock.fileno()
        add = self.loop.add_writer if write else self.loop.add_reader
        remove = self.loop.remove_writer if write else self.loop.remove_reader

        def ready() -> None:
            if not future.done():
                future.set_result(None)

        try:
            add(descriptor, ready)
            await future
        finally:
            remove(descriptor)

    async def _operation(self, sock: socket.socket, function: Callable[[], Any], *, write: bool = False) -> Any:
        async with _socket_timeout(self.sockets[sock]):
            while True:
                try:
                    # In particular, read buffered SSL plaintext before waiting
                    # for OS readability. Both directions can require either wait.
                    return function()
                except ssl.SSLWantReadError:
                    await self._ready(sock)
                except ssl.SSLWantWriteError:
                    await self._ready(sock, write=True)
                except (BlockingIOError, InterruptedError):
                    await self._ready(sock, write=write)

    async def open(self, address: tuple[str, int], timeout: float | None = None, **options: Any) -> socket.socket:
        if options:
            raise AsyncHttpFallback("unsupported raw socket connection options")
        host, port = address
        try:
            if "%" in str(host):
                raise ValueError("scoped IPv6 requires the legacy resolver")
            numeric = ipaddress.ip_address(str(host))
        except ValueError as exc:
            # The scheduler owns DNS. Never silently dispatch getaddrinfo to a
            # worker from this native detector when called outside that setup.
            raise AsyncHttpFallback("raw native detector requires a numeric target") from exc
        family = socket.AF_INET6 if numeric.version == 6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.setblocking(False)
        self.sockets[sock] = timeout
        try:
            async with _socket_timeout(timeout):
                await self.loop.sock_connect(sock, (host, int(port)))
            return sock
        except BaseException:
            sock.close()
            raise

    async def wrap(self, context: ssl.SSLContext, sock: socket.socket, **options: Any) -> ssl.SSLSocket:
        timeout = self.sockets.pop(sock)
        options["do_handshake_on_connect"] = False
        try:
            wrapped = context.wrap_socket(sock, **options)
        except BaseException:
            sock.close()
            raise
        wrapped.setblocking(False)
        self.sockets[wrapped] = timeout
        try:
            await self._operation(wrapped, wrapped.do_handshake)
            return wrapped
        except BaseException:
            wrapped.close()
            raise

    async def recv(self, sock: socket.socket, count: int, *options: Any) -> bytes:
        return await self._operation(sock, lambda: sock.recv(count, *options))

    async def sendall(self, sock: socket.socket, data: bytes, *options: Any) -> None:
        view = memoryview(data)
        async with _socket_timeout(self.sockets[sock]):
            while view:

                def send_current(current_view: memoryview = view) -> int:
                    return sock.send(current_view, *options)

                sent = await self._operation(sock, send_current, write=True)
                if not sent:
                    raise ConnectionError("unexpected EOF")
                view = view[sent:]

    async def recv_exact(self, sock: socket.socket, size: int) -> bytes:
        data = bytearray()
        while len(data) < size:
            chunk = await self.recv(sock, size - len(data))
            if not chunk:
                raise ConnectionError("unexpected EOF")
            data.extend(chunk)
        return bytes(data)

    def transfer(self) -> None:
        """Transfer only fully framed sockets, after every readiness wait ends."""
        for sock, timeout in self.sockets.items():
            if sock.fileno() >= 0:
                sock.settimeout(timeout)
        self.sockets.clear()

    def close(self) -> None:
        for sock in self.sockets:
            sock.close()
        self.sockets.clear()


@dataclass(frozen=True)
class FingerprintRead:
    cache: Any
    key: tuple[Any, ...]
    function: Any
    args: tuple[Any, ...]
    kwargs: dict[str, Any]


def recv_exact_steps(sock: socket.socket, size: int) -> Any:
    data = bytearray()
    while len(data) < size:
        chunk = yield DetectCall(sock.recv, (size - len(data),), {})
        if not chunk:
            raise ConnectionError("unexpected EOF")
        data.extend(chunk)
    return bytes(data)


# Bind the original primitive once: later monkeypatches remain compatibility
# boundaries, instead of accidentally bypassing a caller's custom transport.
_CREATE_CONNECTION = socket.create_connection
_SLEEP = time.sleep
_BASE_REGISTRY = {transport.recv_exact: recv_exact_steps}


async def run_native(steps: Any, http: Any, registry: dict[Any, Any], io: RetainedSocketIO) -> Any:
    """Interpret known continuations; overridden helpers decline to legacy."""

    async def execute(step: Any) -> Any:
        if isinstance(step, DetectDelay):
            return await asyncio.sleep(step.seconds)
        if isinstance(step, HttpRead):
            return await read_http(step, http)
        if isinstance(step, FingerprintRead):
            factory = registry.get(step.function)
            if factory is None:
                raise AsyncHttpFallback("fingerprint helper override")
            probe_factory: Callable[..., Any] = factory

            async def probe() -> Any:
                return await run_native(probe_factory(*step.args, **step.kwargs), http, registry, io)

            return await step.cache.get_or_probe_async(step.key, probe)
        if not isinstance(step, DetectCall):
            raise AsyncHttpFallback("unsupported retained detection operation")
        function, args, kwargs = step.function, step.args, step.kwargs
        owner = getattr(function, "__self__", None)
        factory = registry.get(function)
        if factory is None and owner is not None:
            factory = registry.get(getattr(function, "__func__", None))
            if factory is not None:
                args = (owner, *args)
        if factory is not None:
            return await run_native(factory(*args, **kwargs), http, registry, io)
        if function is _CREATE_CONNECTION:
            return await io.open(*args, **kwargs)
        if function is _SLEEP:
            return await asyncio.sleep(*args, **kwargs)
        if isinstance(owner, socket.socket) and owner in io.sockets:
            name = getattr(function, "__name__", "")
            if name == "recv":
                return await io.recv(owner, *args, **kwargs)
            if name == "sendall":
                return await io.sendall(owner, *args, **kwargs)
            if name == "settimeout":
                io.sockets[owner] = args[0]
                return None
            if name == "gettimeout":
                return io.sockets[owner]
            raise AsyncHttpFallback("unsupported native socket operation")
        if isinstance(owner, ssl.SSLContext) and getattr(function, "__name__", "") == "wrap_socket":
            return await io.wrap(owner, *args, **kwargs)
        raise AsyncHttpFallback("detector helper override or synchronous-only path")

    finished = False
    try:
        step = next(steps)
        while True:
            try:
                value = await execute(step)
            except AsyncHttpFallback:
                raise
            except Exception as exc:
                step = steps.throw(exc)
            else:
                step = steps.send(value)
    except StopIteration as result:
        finished = True
        return result.value
    finally:
        if finished:
            steps.close()
        else:
            # A finally clause may itself yield CLOSE_SESSION I/O. Drain that
            # cleanup natively, including cancellation/fallback unwinding; a
            # generator.close() alone would raise "ignored GeneratorExit".
            try:
                step = steps.throw(GeneratorExit)
                while True:
                    try:
                        value = await execute(step)
                    except Exception as exc:
                        step = steps.throw(exc)
                    else:
                        step = steps.send(value)
            except (StopIteration, GeneratorExit):
                pass
            finally:
                steps.close()


def _check_original_helpers(registry: dict[Any, Any]) -> None:
    for function in registry:
        namespace = getattr(function, "__globals__", {})
        qualified = getattr(function, "__qualname__", "")
        if not qualified or "<locals>" in qualified:
            continue
        names = qualified.split(".")
        current = namespace.get(names[0])
        for name in names[1:]:
            current = getattr(current, name, None)
        current = getattr(current, "__func__", current)
        if current is not function:
            raise AsyncHttpFallback("detector helper override")


async def detect_native(steps: Any, http: Any, registry: dict[Any, Any]) -> Any:
    io = RetainedSocketIO()
    try:
        registry = {**_BASE_REGISTRY, **registry}
        _check_original_helpers(registry)
        io.check_supported()
        result = await run_native(steps, http, registry, io)
        io.transfer()
        return result
    except BaseException:
        io.close()
        steps.close()
        raise


def with_native_detection(spec: Any, factory: Any, registry: dict[Any, Any]) -> Any:
    if spec.detect is None:
        return spec

    async def detect_async(ctx: Any, http: Any) -> Any:
        return await detect_native(factory(ctx), http, registry)

    return replace(spec, detect_async=detect_async, async_detect_sync_hook=spec.detect)
