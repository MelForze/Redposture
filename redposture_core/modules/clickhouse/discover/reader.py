"""Streaming native/HTTP chunk reader with explicit ClickHouse budgets."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Any

from .inventory import quote_identifier, quote_literal
from .models import ScanChunk


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
    max_memory: int,
    max_threads: int,
) -> str:
    columns = ",".join(quote_identifier(column) for column in chunk.columns)
    table = f"{quote_identifier(chunk.database)}.{quote_identifier(chunk.table)}"
    where = f" WHERE _partition_id={quote_literal(chunk.partition_id)}" if chunk.partition_id is not None else ""
    read_row_budget = max(_setting_int(max_query_rows), chunk.offset + chunk.limit)
    settings = (
        f"max_execution_time={max(0.1, float(max_query_time))},"
        f"max_rows_to_read={read_row_budget},"
        f"max_bytes_to_read={_setting_int(max_query_bytes)},"
        f"max_memory_usage={_setting_int(max_memory)},"
        f"max_threads={max(1, int(max_threads))}"
    )
    return f"SELECT {columns} FROM {table}{where} LIMIT {chunk.limit} OFFSET {chunk.offset} SETTINGS {settings}"


def _normalize_row(row: Any) -> list[Any]:
    if isinstance(row, (list, tuple)):
        return list(row)
    return [row]


def _estimate_bytes(row: list[Any]) -> int:
    return sum(len(str(value).encode("utf-8", errors="replace")) for value in row if value is not None)


def read_chunk(session: Any, query: str) -> ReadResult:
    rows: list[list[Any]] = []
    bytes_read = 0
    stream_owner: AbstractContextManager[Any] | None = None
    try:
        if session.protocol == "native" and callable(getattr(session.client, "execute_iter", None)):
            iterator: Iterator[Any] = iter(session.client.execute_iter(query))
            for raw_row in iterator:
                row = _normalize_row(raw_row)
                rows.append(row)
                bytes_read += _estimate_bytes(row)
        elif session.protocol == "http" and callable(getattr(session.client, "query_rows_stream", None)):
            stream_owner = session.client.query_rows_stream(query)
            with stream_owner as stream:
                for raw_row in stream:
                    row = _normalize_row(raw_row)
                    rows.append(row)
                    bytes_read += _estimate_bytes(row)
        elif session.protocol == "native":
            for raw_row in session.client.execute(query):
                row = _normalize_row(raw_row)
                rows.append(row)
                bytes_read += _estimate_bytes(row)
        else:
            result = session.client.query(query)
            for raw_row in getattr(result, "result_rows", []) or []:
                row = _normalize_row(raw_row)
                rows.append(row)
                bytes_read += _estimate_bytes(row)
    except Exception as exc:
        return ReadResult(rows, bytes_read, str(exc))
    return ReadResult(rows, bytes_read)


__all__ = ["ReadResult", "build_chunk_query", "read_chunk"]
