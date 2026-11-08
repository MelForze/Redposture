"""Async loopback HTTP peer for resource/CLI profiles, not a real product.

One fixture loop serves every connection; large concurrency must not create a
server thread per socket and accidentally benchmark the fixture's thread cap.
"""

from __future__ import annotations

import asyncio
import socket
import threading
from collections import Counter
from collections.abc import Callable
from typing import Any

Router = Callable[[str, str, dict[bytes, bytes], bytes, str], bytes]


class AsyncHttpFixture:
    def __init__(
        self,
        router: Router,
        *,
        host: str = "127.0.0.1",
        delay: Callable[[str, str], float] | None = None,
        keep_alive: bool = True,
        non_http_response: Callable[[str], bytes] | None = None,
    ):
        self.router = router
        self.host = host
        self.delay = delay or (lambda _host, _path: 0.0)
        self.keep_alive = keep_alive
        self.non_http_response = non_http_response
        self.lock = threading.Lock()
        self.stats: Counter[str] = Counter()
        self.calls: Counter[tuple[str, str, str]] = Counter()
        self.errors: list[str] = []
        self._ready = threading.Event()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._listener: socket.socket | None = None
        self._accept_task: asyncio.Task[None] | None = None
        self._accepted: set[socket.socket] = set()
        self._clients: set[asyncio.Task[Any]] = set()
        self._writers: set[asyncio.StreamWriter] = set()
        self.port = 0
        self.thread = threading.Thread(target=self._run, name="workflow-fixture-loop", daemon=True)

    def start(self) -> None:
        self.thread.start()
        if not self._ready.wait(5):
            raise RuntimeError("HTTP fixture did not start")
        if not self.port:
            raise RuntimeError("HTTP fixture failed: " + "; ".join(self.errors))

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        try:
            self._listener = socket.socket()
            self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._listener.bind((self.host, 0))
            self._listener.listen(2048)
            self._listener.setblocking(False)
            self.port = self._listener.getsockname()[1]
            self._accept_task = loop.create_task(self._accept())
            self._ready.set()
            loop.run_forever()
        except Exception as exc:
            self.errors.append(repr(exc))
            self._ready.set()
        finally:
            pending = list(asyncio.all_tasks(loop))
            for task in pending:
                task.cancel()
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.run_until_complete(loop.shutdown_default_executor())
            if self._listener is not None:
                self._listener.close()
            for connection in self._accepted:
                connection.close()
            loop.close()

    async def _accept(self) -> None:
        assert self._loop is not None and self._listener is not None
        while True:
            connection, _address = await self._loop.sock_accept(self._listener)
            self._accepted.add(connection)
            with self.lock:
                self.stats["connections"] += 1
                self.stats["active"] += 1
                self.stats["peak_active"] = max(self.stats["peak_active"], self.stats["active"])
            task = self._loop.create_task(self._connection(connection))
            self._clients.add(task)

            def finished(done: asyncio.Task[Any], sock: socket.socket = connection) -> None:
                # Also owns sockets of tasks cancelled before their first step.
                self._clients.discard(done)
                self._accepted.discard(sock)
                sock.close()
                if not done.cancelled():
                    failure = done.exception()
                    if failure is not None and not isinstance(failure, ConnectionError):
                        with self.lock:
                            if len(self.errors) < 16:
                                self.errors.append(repr(failure))
                with self.lock:
                    self.stats["active"] -= 1

            task.add_done_callback(finished)

    async def _connection(self, connection: socket.socket) -> None:
        reader, writer = await asyncio.open_connection(sock=connection, limit=65_536)
        await self._handle(reader, writer)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._writers.add(writer)
        local = writer.get_extra_info("sockname")
        host = str(local[0])
        try:
            while True:
                prefix = await asyncio.wait_for(reader.readexactly(4), 3)
                if self.non_http_response is not None and prefix not in {
                    b"GET ",
                    b"HEAD",
                    b"POST",
                    b"PUT ",
                    b"DELE",
                    b"OPTI",
                    b"PATC",
                }:
                    pause = self.delay(host, "")
                    if pause > 0:
                        await asyncio.sleep(pause)
                    writer.write(self.non_http_response(host))
                    await writer.drain()
                    return
                head = prefix + await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 3)
                request, *lines = head[:-4].split(b"\r\n")
                method_raw, path_raw, version = request.split(b" ")
                if version not in {b"HTTP/1.0", b"HTTP/1.1"}:
                    raise ValueError("unexpected HTTP version")
                method, path = method_raw.decode("ascii"), path_raw.decode("ascii")
                fields: dict[bytes, bytes] = {}
                for line in lines:
                    name, separator, value = line.partition(b":")
                    if not separator:
                        raise ValueError("invalid header")
                    fields[name.lower().strip()] = value.strip()
                if b"transfer-encoding" in fields:
                    raise ValueError("chunked request is not defined by this fixture")
                length = int(fields.get(b"content-length", b"0"))
                if not 0 <= length <= 65_536:
                    raise ValueError("request exceeds fixture frame limit")
                body = await asyncio.wait_for(reader.readexactly(length), 3) if length else b""
                with self.lock:
                    self.stats["http_requests"] += 1
                    self.calls[(host, method, path)] += 1
                pause = self.delay(host, path)
                if pause > 0:
                    await asyncio.sleep(pause)
                response = self.router(method, path, fields, body, host)
                headers, separator, payload = response.partition(b"\r\n\r\n")
                if not separator:
                    raise ValueError("fixture router returned an invalid response")
                close = (
                    not self.keep_alive or fields.get(b"connection", b"").lower() == b"close" or version == b"HTTP/1.0"
                )
                header_lines = [line for line in headers.split(b"\r\n") if not line.lower().startswith(b"connection:")]
                header_lines.append(b"Connection: close" if close else b"Connection: keep-alive")
                writer.write(b"\r\n".join(header_lines) + b"\r\n\r\n" + (b"" if method == "HEAD" else payload))
                await writer.drain()
                if close:
                    return
        except (asyncio.IncompleteReadError, ConnectionError, TimeoutError):
            pass  # Normal client close/timeout; completed requests remain counted.
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            with self.lock:
                if len(self.errors) < 16:
                    self.errors.append(repr(exc))
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass
            self._writers.discard(writer)

    def close(self) -> None:
        loop = self._loop
        if loop is None or loop.is_closed():
            self.thread.join(1)
            return

        async def shutdown() -> None:
            assert self._listener is not None
            self._listener.close()
            if self._accept_task is not None:
                self._accept_task.cancel()
                await asyncio.gather(self._accept_task, return_exceptions=True)
            tasks = list(self._clients)
            for task in tasks:
                task.cancel()
            for writer in list(self._writers):
                writer.close()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

        try:
            asyncio.run_coroutine_threadsafe(shutdown(), loop).result(5)
        finally:
            loop.call_soon_threadsafe(loop.stop)
            self.thread.join(5)
        if self.thread.is_alive() or self.stats["active"]:
            raise RuntimeError("HTTP fixture cleanup incomplete")
