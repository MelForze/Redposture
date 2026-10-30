"""Actual RESP disconnects must not erase already discovered data."""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from redposture_core.modules.redis import actions
from redposture_core.modules.redis.discovery import discover_redis


def discovery_context():
    return SimpleNamespace(
        args=SimpleNamespace(discover_time=5, dump=True, format="json"),
        host="qa",
        port=6379,
        live_emit=None,
        discovery_started_at=time.monotonic(),
    )


def test_discovery_reads_scan_key_larger_than_a_small_legacy_budget() -> None:
    client, server = socket.socketpair()
    client.settimeout(1)
    seen: list[bytes] = []

    def serve() -> None:
        try:
            with server:
                while True:
                    kind, args = actions._read_resp(server)
                    assert kind == "array"
                    command = args[0].upper()
                    seen.append(command)
                    if command == b"SCAN":
                        server.sendall(b"*2\r\n$1\r\n0\r\n*1\r\n$4096\r\n" + b"k" * 4096 + b"\r\n")
                    elif command == b"TYPE":
                        server.sendall(b"+string\r\n")
                    elif command == b"GET":
                        server.sendall(b"$5\r\nvalue\r\n")
                    else:
                        raise AssertionError(command)
        except (ConnectionError, OSError):
            pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        result = discover_redis(discovery_context(), {"status": "open_no_auth"}, client)
        assert result["content_discovery"]["status"] == "complete"
        assert result["key_value_entries"][0] == {"key": "k" * 4096, "value": "value", "error": None}
        assert seen == [b"SCAN", b"TYPE", b"GET"]
    finally:
        client.close()
        thread.join(2)
        assert not thread.is_alive()


def test_discovery_reads_value_larger_than_a_small_legacy_budget() -> None:
    client, server = socket.socketpair()
    client.settimeout(1)
    seen: list[bytes] = []

    def serve() -> None:
        try:
            with server:
                while True:
                    kind, args = actions._read_resp(server)
                    assert kind == "array"
                    command = args[0].upper()
                    seen.append(command)
                    if command == b"SCAN":
                        server.sendall(b"*2\r\n$1\r\n0\r\n*2\r\n$1\r\na\r\n$1\r\nb\r\n")
                    elif command == b"TYPE":
                        server.sendall(b"+string\r\n")
                    elif command == b"GET" and args[1] == b"a":
                        server.sendall(b"$5\r\nvalue\r\n")
                    elif command == b"GET":
                        server.sendall(b"$4096\r\n" + b"x" * 4096 + b"\r\n")
                    else:
                        raise AssertionError(args)
        except (ConnectionError, OSError):
            pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        result = discover_redis(discovery_context(), {"status": "open_no_auth"}, client)
        rows = result["key_value_entries"]
        assert result["content_discovery"]["status"] == "complete"
        assert rows[0] == {"key": "a", "value": "value", "error": None}
        assert rows[1] == {"key": "b", "value": "x" * 4096, "error": None}
        assert seen.count(b"GET") == 2
    finally:
        client.close()
        thread.join(2)
        assert not thread.is_alive()


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
