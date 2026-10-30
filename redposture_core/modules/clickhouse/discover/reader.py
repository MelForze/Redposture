"""Streaming native/HTTP chunk reader with explicit ClickHouse budgets."""

from __future__ import annotations

import codecs
import socket
import threading
import time
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager, nullcontext
from dataclasses import dataclass
from itertools import chain, zip_longest
from typing import Any

from ....discovery_containers import DiskContainer, DiskSequence
from ....discovery_spool import SpoolingValues
from ....discovery_values import DiskBackedText
from .http_native import http_native_rows
from .inventory import quote_identifier, quote_literal
from .models import ScanChunk
from .native_stream import native_streaming_strings


@dataclass
class ReadResult:
    rows: list[list[Any]]
    bytes_read: int
    error: str | None = None


def _setting_int(value: int) -> int:
    return max(0, int(value))


def build_chunk_query(
    chunk: ScanChunk,
    *,
    max_query_time: float,
    max_query_rows: int,
    max_query_bytes: int,
    max_memory: int | None,
    max_threads: int,
) -> str:
    columns = ",".join(quote_identifier(column) for column in chunk.columns)
    table = f"{quote_identifier(chunk.database)}.{quote_identifier(chunk.table)}"
    where = f" WHERE _partition_id={quote_literal(chunk.partition_id)}" if chunk.partition_id is not None else ""
    read_row_budget = max(_setting_int(max_query_rows), chunk.offset + chunk.limit)
    settings = (
        f"max_execution_time={max(0.001, float(max_query_time))},"
        "timeout_before_checking_execution_speed=0,"
        f"max_rows_to_read={read_row_budget},"
        f"max_bytes_to_read={_setting_int(max_query_bytes)},"
        + (f"max_memory_usage={_setting_int(max_memory)}," if max_memory is not None else "")
        + f"max_threads={max(1, int(max_threads))}"
    )
    return f"SELECT {columns} FROM {table}{where} LIMIT {chunk.limit} OFFSET {chunk.offset} SETTINGS {settings}"


def _normalize_row(row: Any) -> list[Any]:
    if isinstance(row, DiskSequence):
        return row
    if isinstance(row, (list, tuple)):
        return list(row)
    return [row]


def _estimate_bytes(row: list[Any]) -> int:
    if isinstance(row, DiskContainer):
        return row.byte_length

    def size(value: Any) -> int:
        if value is None:
            return 0
        if isinstance(value, (DiskBackedText, DiskContainer)):
            return value.byte_length
        if isinstance(value, str):
            return sum(
                len(value[offset : offset + 65_536].encode("utf-8", errors="replace"))
                for offset in range(0, len(value), 65_536)
            )
        if isinstance(value, bytes):
            return len(value)
        if isinstance(value, dict):
            return sum(size(key) + size(item) for key, item in value.items())
        if isinstance(value, (list, tuple)):
            return sum(size(item) for item in value)
        return len(str(value).encode("utf-8", errors="replace"))

    return sum(size(value) for value in row)


class _JoinedRows(list[Any]):
    def __init__(self, prefix: list[Any], tail: list[Any]) -> None:
        super().__init__()
        self.prefix, self.tail = prefix, tail

    def __len__(self) -> int:
        return len(self.prefix) + len(self.tail)

    def __iter__(self) -> Iterator[Any]:
        return chain(self.prefix, self.tail)

    def __getitem__(self, index: Any) -> Any:
        if isinstance(index, slice):
            return [self[position] for position in range(*index.indices(len(self)))]
        if index < 0:
            index += len(self)
        if not 0 <= index < len(self):
            raise IndexError(index)
        return self.prefix[index] if index < len(self.prefix) else self.tail[index - len(self.prefix)]

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, (list, tuple)):
            return NotImplemented
        missing = object()
        return all(a == b for a, b in zip_longest(self, other, fillvalue=missing))

    def __ne__(self, other: object) -> bool:
        result = self.__eq__(other)
        return NotImplemented if result is NotImplemented else not result


def _spool_value(value: Any) -> Any:
    """Release driver-owned large strings after each row, outside wire decoding."""
    if isinstance(value, DiskContainer):
        return value
    if isinstance(value, (str, bytes)) and len(value) > 65_536:
        disk = DiskBackedText()
        try:
            decoder = codecs.getincrementaldecoder("utf-8")("replace")
            for offset in range(0, len(value), 65_536):
                part = value[offset : offset + 65_536]
                disk.append_text(decoder.decode(part) if isinstance(part, bytes) else part)
            if isinstance(value, bytes):
                disk.append_text(decoder.decode(b"", final=True))
            disk.finish()
            return disk
        except BaseException:
            disk.close()
            raise
    if isinstance(value, dict):
        return {key: _spool_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_spool_value(item) for item in value]
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


@contextmanager
def native_query_deadline(client: Any, deadline: float | None) -> Iterator[threading.Event]:
    expired = threading.Event()
    if deadline is None:
        yield expired
        return
    active = True
    lock = threading.Lock()

    def interrupt() -> None:
        with lock:
            if not active:
                return
            expired.set()
            connection = getattr(client, "connection", None)
            shutdown = getattr(getattr(connection, "socket", None), "shutdown", None)
            if callable(shutdown):
                try:
                    shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    timer = threading.Timer(max(0.0, deadline - time.monotonic()), interrupt)
    timer.daemon = True
    timer.start()
    try:
        yield expired
    finally:
        with lock:
            active = False
        timer.cancel()


def read_chunk(
    session: Any,
    query: str,
    *,
    max_bytes: int | None = None,
    deadline: float | None = None,
) -> ReadResult:
    rows: list[list[Any]] = SpoolingValues()
    bytes_read = 0
    stream_owner: AbstractContextManager[Any] | None = None
    iterator: Iterator[Any] | None = None
    reason: str | None = None

    def consume(source: Iterator[Any]) -> str | None:
        nonlocal bytes_read, rows

        def recover(*, include_current: bool = False) -> None:
            nonlocal bytes_read, rows
            if native_state is not None:
                ready = native_state.take_remaining(include_current=include_current)
                if ready is not None and ready:
                    bytes_read += ready.byte_length
                    rows = _JoinedRows(rows, ready) if rows else ready

        while True:
            if deadline is not None and time.monotonic() >= deadline:
                recover()
                return "discover_time"
            if max_bytes is not None and bytes_read >= max_bytes:
                return "discover_max_bytes"
            try:
                delivered = native_state.delivered if native_state is not None else 0
                raw_row = next(source)
            except StopIteration:
                return None
            if deadline is not None and time.monotonic() >= deadline:
                if native_state is not None and native_state.delivered != delivered:
                    recover(include_current=True)
                return "discover_time"
            row = _normalize_row(raw_row)
            row_bytes = _estimate_bytes(row)
            if max_bytes is not None and bytes_read + row_bytes > max_bytes and rows:
                return "discover_max_bytes"
            rows.append(row if isinstance(row, DiskContainer) else [_spool_value(value) for value in row])
            bytes_read += row_bytes

    with (
        native_query_deadline(session.client, deadline if session.protocol == "native" else None) as expired,
        (
            native_streaming_strings(session.client, deadline) if session.protocol == "native" else nullcontext()
        ) as native_state,
    ):
        try:
            if session.protocol == "native" and callable(getattr(session.client, "execute_iter", None)):
                iterator = iter(session.client.execute_iter(query))
                reason = consume(iterator)
            elif session.protocol == "http" and callable(getattr(session.client, "raw_stream", None)):
                with http_native_rows(session.client, query, deadline) as (native_state, iterator):
                    reason = consume(iterator)
            elif session.protocol == "http" and callable(getattr(session.client, "query_rows_stream", None)):
                stream_owner = session.client.query_rows_stream(query)
                with stream_owner as stream:
                    reason = consume(iter(stream))
            elif session.protocol == "native":
                reason = consume(iter(session.client.execute(query)))
            else:
                result = session.client.query(query)
                reason = consume(iter(getattr(result, "result_rows", []) or []))
        except Exception as exc:
            reason = (
                "discover_time"
                if expired.is_set() or (deadline is not None and time.monotonic() >= deadline)
                else str(exc)
            )
        if expired.is_set():
            reason = "discover_time"
    if session.protocol == "native" and reason is not None:
        for close in (getattr(iterator, "close", None), getattr(session.client, "disconnect", None)):
            if callable(close):
                try:
                    close()
                except Exception:
                    pass
    return ReadResult(rows, bytes_read, reason)


__all__ = ["ReadResult", "build_chunk_query", "native_query_deadline", "read_chunk"]
