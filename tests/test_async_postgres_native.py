"""Native PostgreSQL detection keeps startup evidence and avoids credential IO."""

import asyncio
from types import SimpleNamespace

import pytest

from redposture_core.modules.postgres import async_detect, stage


def context(port):
    return SimpleNamespace(
        host="127.0.0.1",
        port=port,
        args=SimpleNamespace(timeout=1, retries=0),
        lifecycle_state=stage._PostgresLifecycleState(),
        debug_emit=None,
    )


@pytest.mark.parametrize(
    "payload,expected",
    [
        (b"R\x00\x00\x00\x08\x00\x00\x00\x03", ("auth_required", "cleartext")),
        (b"R\x00\x00\x00\x08\x00\x00\x00\x0a", ("auth_required", "scram-sha-256")),
        (b"R\x00\x00\x00\x08\x00\x00\x00\x05", ("auth_required", "md5")),
        (b"R\x00\x00\x00\x08\x00\x00\x00\x00Z\x00\x00\x00\x05I", ("open_no_auth", None)),
    ],
)
def test_native_startup_only(payload, expected, monkeypatch):
    monkeypatch.setattr(stage.actions, "_pg_open_socket", lambda *a, **k: pytest.fail("sync socket called"))

    async def run():
        requests = []
        done = asyncio.Event()

        async def peer(reader, writer):
            try:
                length = int.from_bytes(await reader.readexactly(4), "big")
                requests.append(await reader.readexactly(length - 4))
                for byte in payload:
                    writer.write(bytes([byte]))
                    await writer.drain()
                requests.append(await reader.readexactly(5))
            finally:
                writer.close()
                await writer.wait_closed()
                done.set()

        server = await asyncio.start_server(peer, "127.0.0.1", 0)
        async with server:
            ctx = context(server.sockets[0].getsockname()[1])
            record = await async_detect.detect(ctx, None)
            await asyncio.wait_for(done.wait(), 2)
        assert (record.status, record.extra.get("auth_method")) == expected
        assert ctx.lifecycle_state.detect_record is record
        assert b"user\x00postgres\x00" in requests[0]
        assert requests[1] == b"X\x00\x00\x00\x04"

    asyncio.run(run())


def test_spec_registers_matching_sync_hook():
    spec = stage.build_postgres_spec(SimpleNamespace())
    assert spec.detect_async is async_detect.detect
    assert spec.async_detect_sync_hook is spec.detect


@pytest.mark.parametrize(
    "reply,mode,status,error_kind",
    [
        (b"N", "require", "unknown_auth", "tls_required"),
        (b"?", "prefer", "fail", "protocol_error"),
    ],
)
def test_native_ssl_request_refusal(reply, mode, status, error_kind):
    async def run():
        requests = []

        async def peer(reader, writer):
            requests.append(await reader.readexactly(8))
            writer.write(reply)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(peer, "127.0.0.1", 0)
        async with server:
            context_for_port = context(server.sockets[0].getsockname()[1])
            context_for_port.args.sslmode = mode
            record = await async_detect.detect(context_for_port, None)
        assert record.status == status
        assert record.extra["error_kind"] == error_kind
        assert requests == [b"\x00\x00\x00\x08\x04\xd2\x16/"]

    asyncio.run(run())
