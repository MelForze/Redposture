"""The network fixture itself must frame, reuse and close sockets correctly."""

from __future__ import annotations

import asyncio
import http.client
import socket
import threading

from scripts.performance_http_fixtures import response
from scripts.performance_http_server import AsyncHttpFixture


def test_many_open_connections_use_one_fixture_thread_and_cleanup_all_sockets():
    before = threading.active_count()
    fixture = AsyncHttpFixture(lambda *args: response(200, "ok"))
    fixture.start()

    async def connect_and_hold():
        peers = await asyncio.gather(*(asyncio.open_connection("127.0.0.1", fixture.port) for _ in range(80)))
        try:
            for _reader, writer in peers:
                writer.write(b"GET / HTTP/1.1\r\nHost: qa\r\n\r\n")
                await writer.drain()
            for reader, _writer in peers:
                assert (await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)).startswith(b"HTTP/1.1 200")
                assert await reader.readexactly(2) == b"ok"
            assert fixture.stats["active"] == 80
            assert fixture.stats["http_requests"] == 80
            assert threading.active_count() == before + 1
        finally:
            for _reader, writer in peers:
                writer.close()
            await asyncio.gather(*(writer.wait_closed() for _reader, writer in peers))

    try:
        asyncio.run(connect_and_hold())
    finally:
        fixture.close()
    assert fixture.stats["active"] == 0 and not fixture.errors
    assert threading.active_count() == before


def test_module_peer_rejects_tls_promptly_and_preserves_close_response_policy():
    fixture = AsyncHttpFixture(
        lambda *args: response(200, "payload"),
        keep_alive=False,
        non_http_response=lambda host: response(400, ""),
    )
    fixture.start()
    try:
        with socket.create_connection(("127.0.0.1", fixture.port), timeout=1) as peer:
            peer.sendall(b"\x16\x03\x01\x00")
            assert peer.recv(4096).startswith(b"HTTP/1.1 400")
            assert peer.recv(4096) == b""
        client = http.client.HTTPConnection("127.0.0.1", fixture.port, timeout=1)
        try:
            client.request("GET", "/")
            reply = client.getresponse()
            assert reply.read() == b"payload"
            assert reply.will_close
        finally:
            client.close()
    finally:
        fixture.close()
    assert fixture.stats["connections"] == 2
    assert fixture.stats["http_requests"] == 1
    assert fixture.stats["active"] == 0 and not fixture.errors


def test_fixture_keeps_head_and_post_framing_and_one_connection():
    calls = []

    def router(method, path, headers, body, host):
        calls.append((method, path, body))
        return response(200, body.decode() if body else "payload")

    before = threading.active_count()
    fixture = AsyncHttpFixture(router)
    fixture.start()
    try:
        client = http.client.HTTPConnection("127.0.0.1", fixture.port, timeout=1)
        try:
            client.request("HEAD", "/head")
            reply = client.getresponse()
            assert reply.read() == b""
            client.request("POST", "/post", body="данные".encode())
            reply = client.getresponse()
            assert reply.read() == "данные".encode()
            client.request("GET", "/get")
            assert client.getresponse().read() == b"payload"
        finally:
            client.close()
    finally:
        fixture.close()
    assert fixture.stats["connections"] == 1 and fixture.stats["http_requests"] == 3
    assert fixture.stats["active"] == 0 and not fixture.errors
    assert calls == [("HEAD", "/head", b""), ("POST", "/post", "данные".encode()), ("GET", "/get", b"")]
    assert threading.active_count() == before


def test_incomplete_client_request_is_not_counted_as_completed():
    fixture = AsyncHttpFixture(lambda *args: response(200, "ok"))
    fixture.start()
    try:
        with socket.create_connection(("127.0.0.1", fixture.port), timeout=1) as client:
            client.sendall(b"POST / HTTP/1.1\r\nHost: qa\r\nContent-Length: 30\r\n\r\npartial")
    finally:
        fixture.close()
    assert fixture.stats["http_requests"] == 0 and fixture.stats["active"] == 0
    assert not fixture.errors


def test_close_interrupts_slow_clients_without_another_server_thread():
    entered = threading.Event()

    def delay(host, path):
        entered.set()
        return 30

    fixture = AsyncHttpFixture(lambda *args: response(200, "ok"), delay=delay)
    fixture.start()
    client = socket.create_connection(("127.0.0.1", fixture.port), timeout=1)
    try:
        client.sendall(b"GET / HTTP/1.1\r\nHost: qa\r\n\r\n")
        assert entered.wait(1)
        fixture.close()
        assert not fixture.thread.is_alive() and fixture.stats["active"] == 0
    finally:
        client.close()
        if fixture.thread.is_alive():
            fixture.close()
