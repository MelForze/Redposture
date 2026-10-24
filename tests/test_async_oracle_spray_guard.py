"""Oracle spray keeps the original bounded STATUS/descriptor guard and TLS policy."""

import asyncio
import ssl
import struct
import time
from types import SimpleNamespace

import pytest

from redposture_core import stage_spray
from redposture_core.clients import async_oracle_detect as native
from redposture_core.clients import oracle
from redposture_core.clients.async_oracle_detect import service_fingerprint, spray_preflight
from redposture_core.clients.async_retained_socket import RetainedSocketIO


@pytest.mark.parametrize(
    "statuses,fingerprints,port,secure,expected",
    [
        ({"tcp": True}, {}, 1521, False, True),
        ({}, {"tcp": True}, 1521, True, True),
        ({"tcps": True}, {}, 1521, True, True),
        ({}, {}, 1521, False, False),
        ({"tcps": True}, {}, 2484, True, True),
    ],
)
def test_preflight_has_same_sync_native_order_and_policy(monkeypatch, statuses, fingerprints, port, secure, expected):
    calls = []

    def status(host, port, command, **options):
        calls.append(("status", host, port, command, options))
        return {"ok": statuses.get(options["protocol"], False), "text": "TNSLSNR", "error": None}

    def fingerprint(host, port, **options):
        calls.append(("fingerprint", host, port, options))
        return fingerprints.get(options["protocol"], False)

    args = SimpleNamespace(protocol="auto", timeout=9, secure=secure, service="XE")
    with monkeypatch.context() as local:
        local.setattr(oracle, "tns_listener_command", status)
        local.setattr(oracle, "tns_service_fingerprint", fingerprint)
        assert stage_spray._oracle_spray_preflight("127.0.0.1", port, args) is expected
    expected_calls = calls[:]
    calls.clear()

    async def async_status(*args, **kwargs):
        return status(*args, **kwargs)

    async def async_fingerprint(*args, **kwargs):
        return fingerprint(*args, **kwargs)

    monkeypatch.setattr(native, "listener_command", async_status)
    monkeypatch.setattr(native, "service_fingerprint", async_fingerprint)
    assert asyncio.run(spray_preflight("127.0.0.1", port, args)) is expected
    assert calls == expected_calls
    for call in calls:
        assert call[-1]["timeout"] == 1.0
        assert call[-1]["insecure"] is (not secure)


@pytest.mark.parametrize(
    "packet_type,reserved,size,body,expected",
    [
        (2, 0, 10, b"ok", True),
        (4, 0, 10, b"no", True),
        (5, 0, 10, b"to", True),
        (6, 0, 10, b"xx", False),
        (2, 1, 10, b"xx", False),
        (2, 0, 9, b"x", False),
        (2, 0, 20000, b"", False),
        (2, 0, 10, b"x", False),
    ],
)
def test_native_descriptor_fingerprint_requires_complete_specific_frame(packet_type, reserved, size, body, expected):
    async def run():
        requests = []

        async def peer(reader, writer):
            header = await reader.readexactly(8)
            length = int.from_bytes(header[:2], "big")
            requests.append(header + await reader.readexactly(length - 8))
            reply = struct.pack(">HHBBH", size, 0, packet_type, reserved, 0) + body
            for byte in reply:
                writer.write(bytes([byte]))
                await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(peer, "127.0.0.1", 0)
        async with server:
            found = await service_fingerprint(
                "127.0.0.1", server.sockets[0].getsockname()[1], service="XE", timeout=0.5
            )
        assert found is expected
        assert b"(SERVICE_NAME=XE)" in requests[0]
        assert b"(COMMAND=status)" not in requests[0]

    asyncio.run(run())


def test_native_descriptor_fingerprint_has_total_connection_budget(monkeypatch):
    async def stalled(self, *args, **kwargs):
        await asyncio.Event().wait()

    monkeypatch.setattr(RetainedSocketIO, "open", stalled)

    async def run():
        started = time.monotonic()
        result = await asyncio.wait_for(service_fingerprint("127.0.0.1", 1521, service="XE", timeout=0.1), 0.7)
        assert result is False
        assert time.monotonic() - started < 0.7

    asyncio.run(run())


@pytest.mark.parametrize("insecure", [False, True])
def test_native_descriptor_tcps_keeps_original_tls_policy(monkeypatch, insecure):
    policies = []

    async def wrap(self, context, sock, **options):
        policies.append((context.verify_mode, context.check_hostname, options))
        return sock

    monkeypatch.setattr(RetainedSocketIO, "wrap", wrap)

    async def run():
        async def peer(reader, writer):
            header = await reader.readexactly(8)
            await reader.readexactly(int.from_bytes(header[:2], "big") - 8)
            writer.write(struct.pack(">HHBBH", 10, 0, 4, 0, 0) + b"no")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(peer, "127.0.0.1", 0)
        async with server:
            assert await service_fingerprint(
                "127.0.0.1",
                server.sockets[0].getsockname()[1],
                service="XE",
                protocol="tcps",
                insecure=insecure,
                timeout=0.5,
            )

    asyncio.run(run())
    assert policies == [
        (ssl.CERT_NONE if insecure else ssl.CERT_REQUIRED, not insecure, {"server_hostname": "127.0.0.1"})
    ]
