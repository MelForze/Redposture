"""Detection must retain an ordinary socket for unchanged synchronous deep IO."""

import asyncio
from types import SimpleNamespace

import pytest

from redposture_core.modules.kafka import stage as kafka_stage
from redposture_core.modules.keeper import stage as keeper_stage
from redposture_core.modules.redis import actions as redis_actions
from redposture_core.modules.redis import stage as redis_stage
from redposture_core.modules.zookeeper import stage as zookeeper_stage


@pytest.mark.parametrize(
    "builder",
    [
        redis_stage.build_redis_spec,
        kafka_stage.build_kafka_spec,
        zookeeper_stage.build_zookeeper_spec,
        keeper_stage.build_keeper_spec,
    ],
)
def test_retained_modules_register_native_detect(builder):
    spec = builder(SimpleNamespace())
    assert spec.detect_async is not None
    assert spec.async_detect_sync_hook is spec.detect


@pytest.mark.parametrize(
    "ping_reply,info_reply,status,identity",
    [
        (b"+PONG\r\n", b"$21\r\nredis_version:7.4.0\r\n\r\n", "open_no_auth", "redis"),
        (b"-NOAUTH Authentication required\r\n", None, "auth_required", None),
        (b"-ERR arbitrary service\r\n", b"+unrelated\r\n", "fail", None),
    ],
)
def test_redis_exact_proof_and_same_socket(ping_reply, info_reply, status, identity, monkeypatch):
    from redposture_core.modules.redis import async_detect

    async def run():
        monkeypatch.setattr(
            asyncio.get_running_loop(),
            "run_in_executor",
            lambda *a, **k: pytest.fail("executor used during native detect"),
        )
        requests = []
        connected = 0
        complete = asyncio.Event()

        async def command(reader):
            n = int((await reader.readline())[1:])
            parts = []
            for _ in range(n):
                length = int((await reader.readline())[1:])
                parts.append(await reader.readexactly(length))
                assert await reader.readexactly(2) == b"\r\n"
            requests.append(parts)

        async def peer(reader, writer):
            nonlocal connected
            connected += 1
            try:
                await command(reader)
                writer.write(ping_reply)
                await writer.drain()
                if info_reply is not None:
                    await command(reader)
                    writer.write(info_reply)
                    await writer.drain()
                if status != "fail":
                    await command(reader)
                    writer.write(b"+PONG\r\n")
                    await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()
                complete.set()

        server = await asyncio.start_server(peer, "127.0.0.1", 0)
        async with server:
            ctx = SimpleNamespace(
                host="127.0.0.1",
                port=server.sockets[0].getsockname()[1],
                args=SimpleNamespace(timeout=1, retries=0),
                debug_emit=None,
            )
            state = redis_actions.redis_lifecycle_state_factory(ctx)
            ctx.lifecycle_state = state
            record = await async_detect.detect(ctx, None)
            assert record.status == status
            assert state.implementation == identity
            if status != "fail":
                assert state.sock.gettimeout() == 1
                # Synchronous ownership is checked without blocking the peer's event loop.
                state.sock.sendall(redis_actions._encode_resp_array(["PING"]))
                await asyncio.wait_for(complete.wait(), 2)
                assert redis_actions._read_resp(state.sock) == ("simple", "PONG")
            else:
                assert state.sock is None
                await asyncio.wait_for(complete.wait(), 2)
            redis_actions.close_redis_lifecycle_state(state)
        assert connected == 1
        assert requests[0] == [b"PING"]
        assert [b"INFO", b"SERVER"] in requests if info_reply else len(requests) == 2

    asyncio.run(run())
