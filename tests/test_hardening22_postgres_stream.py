"""Real PostgreSQL frames interrupted after an independently encoded DataRow."""

from __future__ import annotations

import socket
import struct
import threading
from typing import Any

import pytest

from redposture_core.modules.postgres import actions


def frame(kind: bytes, payload: bytes) -> bytes:
    return kind + struct.pack(">i", len(payload) + 4) + payload


@pytest.mark.parametrize("reader", ["rows", "table", "sql"])
@pytest.mark.parametrize("suffix", ["eof", "truncated-frame", "server-error", "complete"])
def test_pg_stream_preserves_received_rows_with_explicit_incomplete_status(reader: str, suffix: str) -> None:
    client, server = socket.socketpair()
    client.settimeout(0.3)
    server.settimeout(1)
    errors = []

    def serve() -> None:
        try:
            with server:
                server.recv(65536)
                value = b'{"id":1,"seed":"before-cut"}'
                server.sendall(frame(b"D", struct.pack(">hi", 1, len(value)) + value))
                if suffix == "truncated-frame":
                    server.sendall(b"D\x00\x00\x00\x20\x00")
                elif suffix == "server-error":
                    server.sendall(frame(b"E", b"SERROR\0C57014\0Mquery cancelled\0\0") + frame(b"Z", b"I"))
                elif suffix == "complete":
                    server.sendall(frame(b"C", b"SELECT 1\0") + frame(b"Z", b"I"))
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        rows: Any
        if reader == "rows":
            rows, error = actions._pg_query_rows(client, "SELECT known")
            assert rows == [['{"id":1,"seed":"before-cut"}']]
        elif reader == "table":
            _name, rows, error = actions._pg_query_table_rows(client, "public.known")
            assert rows == ['{"id":1,"seed":"before-cut"}']
        else:
            rows, error = actions._pg_try_query_sql(client, "SELECT known")
            assert rows == ['{"id":1,"seed":"before-cut"}']
        assert bool(error) is (suffix != "complete")
    finally:
        client.close()
        thread.join(2)
        assert not thread.is_alive() and not errors
