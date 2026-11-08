"""Native loop owns all sockets and shares exactly the blocking wire program."""

from __future__ import annotations

import socket
import struct
import threading
import time

import pytest

from scripts.performance_native_fixtures import serve_invalid_credentials
from scripts.performance_native_server import AsyncNativeFixture
from tests.test_performance_native_fixtures import Wire, mongo_request, resp


def receive_all(client):
    result = bytearray()
    while portion := client.recv(65536):
        result.extend(portion)
    return bytes(result)


def test_many_partial_clients_use_one_fixture_thread_and_shutdown_closes_them():
    before = threading.active_count()
    fixture = AsyncNativeFixture("mongodb", mode="credentials", role=lambda _: "positive", inactivity_timeout=5)
    fixture.start()
    clients = []
    try:
        for _ in range(80):
            client = socket.create_connection(("127.0.0.1", fixture.port), timeout=2)
            clients.append(client)
            client.sendall(struct.pack("<i", 100))
        deadline = time.monotonic() + 3
        while fixture.stats["active"] < 80 and time.monotonic() < deadline:
            time.sleep(0.005)
        assert fixture.stats["active"] == 80 and threading.active_count() == before + 1
        fixture.close()
        fixture.close()
        assert fixture.stats["active"] == 0 and not fixture.errors
    finally:
        for client in clients:
            client.close()
        fixture.close()
    assert threading.active_count() == before


@pytest.mark.parametrize("module", ["mongodb", "postgres", "redis", "grpc", "clickhouse", "kafka"])
def test_async_invalid_auth_replies_match_fragmented_blocking_driver(module):
    if module == "mongodb":
        data = (
            mongo_request({"hello": 1}, 1) + mongo_request({"listDatabases": 1}, 2) + mongo_request({"saslStart": 1}, 3)
        )
    elif module == "clickhouse":
        from tests.test_performance_clickhouse_auth import hello

        data = hello()
    elif module == "redis":
        data = resp(b"PING") + resp(b"AUTH", b"default", b"wrong") + resp(b"QUIT")
    elif module == "grpc":
        from tests.test_performance_native_program_parity import requests

        data = requests("grpc")
    elif module == "kafka":
        from tests.test_performance_kafka_auth import request

        data = request()
    else:
        startup = struct.pack(">i", 196608) + b"user\0probe\0database\0postgres\0\0"
        data = (
            struct.pack(">ii", 8, 80877103)
            + struct.pack(">i", len(startup) + 4)
            + startup
            + b"p"
            + struct.pack(">i", 10)
            + b"wrong\0"
        )
    wire = Wire(data[4:])
    expected = []
    try:
        serve_invalid_credentials(module, wire, data[:4], expected.append)
    except EOFError:
        pass
    observed = []
    fixture = AsyncNativeFixture(module, mode="credentials", role=lambda _: "positive", message=observed.append)
    fixture.start()
    try:
        with socket.create_connection(("127.0.0.1", fixture.port), timeout=2) as client:
            for index in range(0, len(data), 3):
                client.sendall(data[index : index + 3])
            client.shutdown(socket.SHUT_WR)
            assert receive_all(client) == bytes(wire.replies)
    finally:
        fixture.close()
    assert observed == expected and not fixture.errors


def test_foreign_route_does_not_reply_with_native_product_or_auth_success():
    fixture = AsyncNativeFixture("mongodb", mode="credentials", role=lambda _: "foreign")
    fixture.start()
    try:
        with socket.create_connection(("127.0.0.1", fixture.port), timeout=2) as client:
            client.sendall(b"1234")
            assert receive_all(client).startswith(b"HTTP/1.1 404")
    finally:
        fixture.close()
    assert fixture.stats["native_sessions"] == 0 and not fixture.errors


def test_oversized_native_frame_closes_before_reading_an_unbounded_body():
    fixture = AsyncNativeFixture("mongodb", mode="credentials", role=lambda _: "positive")
    fixture.start()
    try:
        with socket.create_connection(("127.0.0.1", fixture.port), timeout=2) as client:
            client.sendall(struct.pack("<iiii", 999999, 1, 0, 2013))
            assert receive_all(client) == b""
    finally:
        fixture.close()
    assert not fixture.errors
