"""Actual RESP disconnects must not erase already discovered data."""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator
from contextlib import contextmanager

import pytest

from redposture_core.modules.redis import actions


@contextmanager
def stream(fault: str) -> Iterator[socket.socket]:
    client, server = socket.socketpair()
    client.settimeout(0.3)
    server.settimeout(1)
    errors: list[BaseException] = []

    def serve() -> None:
        scans = 0
        try:
            with server:
                while True:
                    kind, args = actions._read_resp(server)
                    assert kind == "array" and isinstance(args, list)
                    command = args[0].upper()
                    if command == b"SCAN":
                        scans += 1
                        if scans == 2:
                            return
                        server.sendall(b"*2\r\n$1\r\n1\r\n*1\r\n$4\r\nseed\r\n")
                    elif command == b"TYPE":
                        server.sendall(b"+string\r\n")
                    elif command == b"GET":
                        if fault == "value":
                            server.sendall(b"$10\r\npart")
                            return
                        server.sendall(b"$5\r\nvalue\r\n")
                    else:
                        raise AssertionError(args)
        except (ConnectionError, OSError):
            pass
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield client
    finally:
        client.close()
        thread.join(2)
        assert not thread.is_alive()
        assert not errors


@pytest.mark.parametrize("batch", [1, 10])
@pytest.mark.parametrize("fault", ["scan", "value"])
def test_resp_eof_keeps_discovered_keys_and_completed_values(batch: int, fault: str) -> None:
    with stream(fault) as sock:
        rows, error = actions._stream_dump_redis_keys(sock, batch=batch, delay_ms=0, limit=None)
    assert error, "a broken connection must never look complete"
    assert len(rows) == 1 and rows[0]["key"] == "seed"
    if batch == 1 and fault == "scan":
        assert rows[0]["value"] == "value" and rows[0]["error"] is None
    else:
        assert rows[0]["value"] is None and rows[0]["error"]
