"""Bounded HTTP Native decoding through the existing authenticated client."""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any

from .native_columns import NativeReadState, read_block
from .native_stream import _StringBuffer
from .native_values import NativeValues


class _HTTPBuffer:
    def __init__(self, response: Any, deadline: float | None) -> None:
        self.response, self.deadline = response, deadline
        self.pending = b""

    def check(self) -> None:
        if self.deadline is not None and time.monotonic() >= self.deadline:
            raise TimeoutError("discover_time")

    def has_data(self) -> bool:
        self.check()
        if not self.pending:
            self.pending = self.response.read(1)
        return bool(self.pending)

    def read(self, size: int) -> bytes:
        self.check()
        parts = []
        if self.pending and size:
            parts.append(self.pending)
            size -= len(self.pending)
            self.pending = b""
        while size:
            self.check()
            part = self.response.read(min(65_536, size))
            if not part:
                raise EOFError("truncated HTTP Native block")
            parts.append(part)
            size -= len(part)
        return b"".join(parts)

    def read_one(self) -> int:
        return self.read(1)[0]

    def read_strings(self, count: int, encoding: str | None = None) -> tuple[Any, ...]:
        # Column names and type specifications use this SDK buffer operation;
        # content String/FixedString values use _StringBuffer._value instead.
        from clickhouse_driver.varint import read_varint

        result = []
        for _ in range(count):
            value = self.read(read_varint(self))
            result.append(value.decode(encoding) if encoding else value)
        return tuple(result)


def _response_socket(response: Any) -> Any:
    connection = getattr(response, "connection", None)
    sock = getattr(connection, "sock", None)
    if sock is None:
        # Connection:close can detach the urllib3 connection before EOF; the
        # stdlib response still owns its socket while the body is being read.
        raw = getattr(getattr(getattr(response, "_fp", None), "fp", None), "raw", None)
        sock = getattr(raw, "_sock", None)
    return sock


@contextmanager
def http_native_rows(
    client: Any, query: str, deadline: float | None
) -> Iterator[tuple[NativeReadState, Iterator[Any]]]:
    from clickhouse_driver import Client
    from urllib3.util import Timeout

    response: Any = None
    original_timeout = getattr(client, "timeout", None)
    timeout_changed = False
    params = getattr(client, "params", None)
    missing = object()
    original_session: Any = missing
    timer: threading.Timer | None = None
    active = True
    lock = threading.Lock()
    state = NativeReadState()

    def interrupt() -> None:
        with lock:
            if active and response is not None:
                sock = _response_socket(response)
                if sock is not None:
                    try:
                        sock.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

    try:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("discover_time")
            if isinstance(original_timeout, Timeout):
                connect = original_timeout.connect_timeout
                read = original_timeout.read_timeout
                client.timeout = Timeout(
                    total=remaining,
                    connect=min(remaining, connect) if isinstance(connect, (int, float)) else remaining,
                    read=min(remaining, read) if isinstance(read, (int, float)) else remaining,
                )
                timeout_changed = True
        # raw_stream does not apply Connect's eager Native column decoder or
        # its drain-on-context-exit behavior. Auth/TLS/proxy/headers stay on the
        # original client; raw formats are uncompressed by the SDK contract.
        # A timed-out query can outlive its socket until the next cooperative
        # cancellation point. An empty session_id is itself a named session in
        # ClickHouse 24.8: omit the parameter entirely, then restore the owned,
        # sequential client's metadata session after this read-only query.
        if isinstance(params, dict):
            original_session = params.pop("session_id", missing)
        response = client.raw_stream(query, fmt="Native")
        if deadline is not None:
            timer = threading.Timer(max(0.0, deadline - time.monotonic()), interrupt)
            timer.daemon = True
            timer.start()
        source = _HTTPBuffer(response, deadline)
        context = Client("unused").connection.context
        context.server_info = SimpleNamespace(
            used_revision=0, get_timezone=lambda: str(getattr(client, "server_tz", None) or "UTC")
        )
        stream = SimpleNamespace(fin=_StringBuffer(source, deadline), context=context)
        owner = NativeValues(deadline)

        def rows() -> Iterator[Any]:
            while source.has_data():
                block = read_block(stream, owner)
                block.read_state = state
                state.remaining = block.num_rows
                state.buffered = block.row_view()
                yield from block.get_rows()

        yield state, rows()
    finally:
        with lock:
            active = False
        if timer is not None:
            timer.cancel()
        try:
            if response is not None:
                response.close()
        finally:
            if original_session is not missing and isinstance(params, dict):
                params["session_id"] = original_session
            if timeout_changed:
                client.timeout = original_timeout
