"""Single-loop native QA peer, using the same wire programs as the thread peer.

This is controlled protocol emulation, never a real database or broker. Socket
ownership/shutdown comes from the already tested generic loopback HTTP fixture;
only its connection handler is replaced. No executor or thread per client.
"""

from __future__ import annotations

import asyncio
import math
from collections.abc import Callable
from typing import Any

from scripts.performance_http_server import AsyncHttpFixture
from scripts.performance_native_fixtures import (
    NATIVE_PRODUCTS,
    Read,
    ReadLine,
    ReadSome,
    WireProgram,
    Write,
    detection_steps,
    invalid_credential_steps,
)

_MESSAGE_NAMES = frozenset(
    {
        "hello",
        "ismaster",
        "buildinfo",
        "listdatabases",
        "saslstart",
        "saslcontinue",
        "connectionstatus",
        "ping",
        "auth",
        "info",
        "quit",
        "startup",
        "sslrequest",
        "password",
        "grpc_call",
        "kafka_api_18",
        "kafka_api_17",
        "kafka_api_36",
        "kafka_sasl_raw",
    }
)


class AsyncRequestReader:
    def __init__(self, reader: asyncio.StreamReader, initial: bytes, timeout: float):
        self.reader, self.buffer, self.timeout = reader, bytearray(initial), timeout

    async def _receive(self, size: int) -> bytes:
        # Match socket.settimeout: each successful receive renews inactivity,
        # rather than applying one wall deadline to an entire fragmented frame.
        data = await asyncio.wait_for(self.reader.read(size), self.timeout)
        if not data:
            raise EOFError
        return data

    async def exact(self, size: int) -> bytes:
        if not 0 <= size <= 65536:
            raise ValueError("out-of-fixture request length")
        while len(self.buffer) < size:
            self.buffer.extend(await self._receive(min(4096, size - len(self.buffer))))
        result = bytes(self.buffer[:size])
        del self.buffer[:size]
        return result

    async def line(self) -> bytes:
        while b"\r\n" not in self.buffer:
            if len(self.buffer) >= 65536:
                raise ValueError("oversized fixture line")
            self.buffer.extend(await self._receive(4096))
        end = self.buffer.index(b"\r\n")
        return (await self.exact(end + 2))[:-2]

    async def some(self, size: int) -> bytes:
        if not 1 <= size <= 65536:
            raise ValueError("out-of-fixture request length")
        if self.buffer:
            result = bytes(self.buffer[:size])
            del self.buffer[:size]
            return result
        return await asyncio.wait_for(self.reader.read(size), self.timeout)


async def drive_native_program(program: WireProgram, reader: AsyncRequestReader, writer: asyncio.StreamWriter) -> bool:
    value: Any = None
    try:
        while True:
            try:
                step = program.send(value)
            except StopIteration as finished:
                return bool(finished.value)
            if isinstance(step, Read):
                value = await reader.exact(step.size)
            elif isinstance(step, ReadLine):
                value = await reader.line()
            elif isinstance(step, ReadSome):
                value = await reader.some(step.size)
            elif isinstance(step, Write):
                writer.write(step.data)
                await asyncio.wait_for(writer.drain(), reader.timeout)
                value = None
            else:
                raise TypeError("unsupported native wire step")
    finally:
        program.close()


def _no_http_router(*args: Any) -> bytes:
    raise AssertionError("native peer must not use the HTTP router")


class AsyncNativeFixture(AsyncHttpFixture):
    def __init__(
        self,
        module: str,
        *,
        mode: str,
        role: Callable[[str], str],
        host: str = "127.0.0.1",
        delay: Callable[[str], float] | None = None,
        message: Callable[[str], None] | None = None,
        grpc_observer: Callable[[str, list[tuple[bytes, bytes]] | None, int], None] | None = None,
        coordination_observer: Callable[[str, str, str | None, str | None, str | None, int], None] | None = None,
        program_factory: Callable[[str, bytes, Callable[[str], None]], WireProgram] | None = None,
        inactivity_timeout: float = 1,
    ):
        if module not in NATIVE_PRODUCTS or mode not in {"detect", "run", "credentials", "defcreds", "actions"}:
            raise ValueError("unsupported native fixture program")
        if not math.isfinite(inactivity_timeout) or inactivity_timeout <= 0:
            raise ValueError("finite positive fixture timeout required")
        super().__init__(_no_http_router, host=host, keep_alive=False)
        self.module, self.mode, self.role = module, mode, role
        self.pause = delay or (lambda _: 0.0)
        self.message = message
        self.grpc_observer = grpc_observer
        self.coordination_observer = coordination_observer
        self.program_factory = program_factory
        self.inactivity_timeout = inactivity_timeout
        self.thread.name = "native-fixture-loop"

    def _message(self, name: str) -> None:
        with self.lock:
            self.stats["native_messages"] += 1
            self.stats["command." + (name if name in _MESSAGE_NAMES else "other")] += 1
        if self.message is not None:
            self.message(name)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        import struct

        from bson.errors import InvalidBSON
        from h2.exceptions import ProtocolError

        self._writers.add(writer)
        host = str(writer.get_extra_info("sockname")[0])
        source = AsyncRequestReader(reader, b"", self.inactivity_timeout)

        def observe(headers: list[tuple[bytes, bytes]] | None, status: int) -> None:
            if self.grpc_observer is not None:
                self.grpc_observer(host, headers, status)

        def observe_coordination(
            kind: str, username: str | None, password: str | None, path: str | None, error: int
        ) -> None:
            if self.coordination_observer is not None:
                self.coordination_observer(host, kind, username, password, path, error)

        try:
            pause = self.pause(host)
            if pause > 0:
                await asyncio.sleep(pause)
            initial = await source.exact(4)
            if self.role(host) != "positive":
                writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Length: 7\r\nConnection: close\r\n\r\nforeign")
                await asyncio.wait_for(writer.drain(), self.inactivity_timeout)
                return
            with self.lock:
                self.stats["native_sessions"] += 1
            if self.program_factory is not None:
                program = self.program_factory(host, initial, self._message)
            elif self.mode != "detect" and self.module in {
                "mongodb",
                "postgres",
                "redis",
                "grpc",
                "clickhouse",
                "kafka",
                "zookeeper",
                "keeper",
            }:
                source.buffer.extend(initial)
                program = invalid_credential_steps(
                    self.module,
                    self._message,
                    grpc_observer=observe if self.grpc_observer is not None else None,
                    coordination_observer=observe_coordination if self.coordination_observer is not None else None,
                )
            else:
                program = detection_steps(self.module, initial, self._message)
            await drive_native_program(program, source, writer)
        except asyncio.CancelledError:
            raise
        except (EOFError, OSError, TimeoutError, ValueError, struct.error, InvalidBSON, ProtocolError):
            pass  # Same bounded malformed/closed request policy as thread peer.
        except Exception as exc:
            with self.lock:
                if len(self.errors) < 16:
                    self.errors.append(repr(exc))
        finally:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), self.inactivity_timeout)
            except (OSError, TimeoutError):
                pass
            self._writers.discard(writer)
