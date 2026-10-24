"""Full protocol framing, retained sync clients, TLS and cancellation."""

from __future__ import annotations

import asyncio
import ssl
import struct
from dataclasses import replace
from types import SimpleNamespace

import pytest

from redposture_core.clients import kafka, zookeeper
from redposture_core.clients.async_http_detect import AsyncHttpFallback
from redposture_core.clients.async_retained_socket import RetainedSocketIO, detect_native
from redposture_core.modules.kafka import stage as kafka_stage
from redposture_core.modules.keeper import stage as keeper_stage
from redposture_core.modules.zookeeper import stage as zookeeper_stage
from redposture_core.stage_runtime import AuditCredentialRun, AuditHookContext


def frame(payload):
    return struct.pack(">i", len(payload)) + payload


async def read_frame(reader):
    size = struct.unpack(">i", await reader.readexactly(4))[0]
    return await reader.readexactly(size)


def context(builder, port, **options):
    args = SimpleNamespace(timeout=1.0, retries=0, **options)
    spec = builder(args)
    ctx = AuditHookContext(
        args=args, logger=None, host="127.0.0.1", port=port, credential=AuditCredentialRun(), phase="detect"
    )
    return spec, replace(ctx, lifecycle_state=spec.lifecycle_state_factory(ctx))


def tls_context(material):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(material["server_cert"], material["server_key"])
    return context


@pytest.mark.parametrize("secure", [False, True])
def test_kafka_full_frames_retained_real_session(secure, mtls_material, monkeypatch):
    async def run():
        requests = []
        complete = asyncio.Event()

        async def peer(reader, writer):
            try:
                api = await read_frame(reader)
                requests.append(struct.unpack(">hhi", api[:8]))
                payload = struct.pack(">ihi", 1, 0, 1) + struct.pack(">hhh", 3, 0, 0)
                for byte in frame(payload):
                    writer.write(bytes([byte]))
                    await writer.drain()
                metadata = await read_frame(reader)
                requests.append(struct.unpack(">hhi", metadata[:8]))
                writer.write(frame(struct.pack(">iii", 2, 0, 0)))
                # A second complete frame proves no stream transport consumed
                # unread bytes before ordinary KafkaSession gets the socket.
                writer.write(frame(struct.pack(">iii", 3, 0, 0)))
                await writer.drain()
                metadata = await read_frame(reader)
                requests.append(struct.unpack(">hhi", metadata[:8]))
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except (ConnectionError, TimeoutError):
                    pass
                finally:
                    complete.set()

        server = await asyncio.start_server(peer, "127.0.0.1", 0, ssl=tls_context(mtls_material) if secure else None)
        async with server:
            monkeypatch.setattr(
                asyncio.get_running_loop(), "run_in_executor", lambda *a, **k: pytest.fail("executor called")
            )
            spec, ctx = context(kafka_stage.build_kafka_spec, server.sockets[0].getsockname()[1], tls=secure)
            record = await spec.detect_async(ctx, None)
            assert record.status == "open_no_auth"
            state = ctx.lifecycle_state
            session = state.anonymous_session
            assert type(session) is kafka.KafkaSession
            assert session.correlation_id == 3
            assert session.api_versions == {3: (0, 0)}
            assert session.identity == (None, None)
            assert session.sock.gettimeout() == 1.0
            assert isinstance(session.sock, ssl.SSLSocket) is secure
            metadata, error = session.fetch_metadata(topics=None)
            assert metadata is not None and error is None
            assert session.correlation_id == 4
            state.close()
            await asyncio.wait_for(complete.wait(), 2)
            assert state.connections_opened == 1
            assert state.protocol_requests == 2
        assert requests == [(18, 0, 1), (3, 0, 2), (3, 0, 3)]

    asyncio.run(run())


def test_kafka_sasl_first_keeps_handshake_fallback_native(monkeypatch):
    async def run():
        requests = []
        completed = asyncio.Event()

        async def peer(reader, writer):
            try:
                request = await read_frame(reader)
                api, version, correlation = struct.unpack(">hhi", request[:8])
                requests.append((api, version, correlation))
                if api == 17:
                    writer.write(frame(struct.pack(">ihi", correlation, 0, 1) + b"\x00\x05PLAIN"))
                    await writer.drain()
                    await reader.read()
                    completed.set()
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(peer, "127.0.0.1", 0)
        async with server:
            spec, ctx = context(kafka_stage.build_kafka_spec, server.sockets[0].getsockname()[1])
            record = await spec.detect_async(ctx, None)
            assert record.status == "auth_required"
            assert ctx.lifecycle_state.sasl_first is True
            assert ctx.lifecycle_state.anonymous_session is None
            await asyncio.wait_for(completed.wait(), 2)
        assert requests == [(18, 0, 1), (17, 1, 1)]

    asyncio.run(run())


@pytest.mark.parametrize(
    "builder,keeper", [(zookeeper_stage.build_zookeeper_spec, False), (keeper_stage.build_keeper_spec, True)]
)
@pytest.mark.parametrize("secure", [False, True])
def test_zookeeper_keeper_full_root_identity_and_session(builder, keeper, secure, mtls_material, monkeypatch):
    async def run():
        requests, diagnostics = [], []
        sync_ready = asyncio.Event()
        consumed = asyncio.Event()

        async def peer(reader, writer):
            try:
                prefix = await reader.readexactly(4)
                if prefix in (b"srvr", b"stat", b"mntr", b"isro"):
                    diagnostics.append(prefix)
                    writer.write(
                        (b"ClickHouse Keeper version: 25.8.1\n" if keeper else b"Zookeeper version: 3.9.2\n")
                        if prefix == b"srvr"
                        else b"zk_server_state\tleader\n"
                        if prefix == b"mntr"
                        else b"rw"
                    )
                    await writer.drain()
                    return
                length = struct.unpack(">i", prefix)[0]
                await reader.readexactly(length)
                writer.write(frame(struct.pack(">iiqi", 0, 1000, 1, 16) + bytes(16)))
                await writer.drain()
                while True:
                    request = await read_frame(reader)
                    xid, opcode = struct.unpack(">ii", request[:8])
                    if opcode == -11:
                        return
                    path, _ = zookeeper._decode_zk_string(request, 8)
                    requests.append((xid, opcode, path))
                    err = -101 if path == "/clickhouse/task_queue/ddl" else 0
                    payload = struct.pack(">i", 0) + bytes(68) if err == 0 else b""
                    writer.write(frame(struct.pack(">iqi", xid, 0, err) + payload))
                    await writer.drain()
                    if (not keeper and len(requests) == 1) or (keeper and path == "/clickhouse/task_queue/ddl"):
                        # Queue the next exact response for sync get_children2.
                        writer.write(frame(struct.pack(">iqii", xid + 1, 0, 0, 0) + bytes(68)))
                        await writer.drain()
                        sync_ready.set()
                        request = await read_frame(reader)
                        rxid, op = struct.unpack(">ii", request[:8])
                        requested_path, _ = zookeeper._decode_zk_string(request, 8)
                        requests.append((rxid, op, requested_path))
                        consumed.set()
                        # The ordinary client owns CLOSE_SESSION from here.
                        await read_frame(reader)
                        return
            except asyncio.IncompleteReadError:
                return
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(peer, "127.0.0.1", 0, ssl=tls_context(mtls_material) if secure else None)
        async with server:
            monkeypatch.setattr(
                asyncio.get_running_loop(), "run_in_executor", lambda *a, **k: pytest.fail("executor called")
            )
            spec, ctx = context(builder, server.sockets[0].getsockname()[1])
            # Match the production transport configuration without a plaintext
            # first attempt when this fixture is explicitly TLS-only.
            cfg = replace(ctx.lifecycle_state.requested_config, mode="tls" if secure else "plaintext")
            ctx.lifecycle_state.requested_config = cfg
            record = await spec.detect_async(ctx, None)
            await asyncio.wait_for(sync_ready.wait(), 2)
            assert record.extra["is_keeper"] is keeper
            assert record.status == "open_no_auth"
            client = ctx.lifecycle_state.zookeeper_state.anonymous_client
            assert type(client) is zookeeper._ZkClient
            assert client.sock.gettimeout() == 1.0
            assert isinstance(client.sock, ssl.SSLSocket) is secure
            children, error, stat = client.get_children2("/")
            assert (children, error, stat) == ([], 0, {"data_length": 0, "num_children": 0})
            await asyncio.wait_for(consumed.wait(), 2)
            ctx.lifecycle_state.close()
            if keeper:
                assert record.extra["ddl_access"] == "Absent"
        assert requests[0] == (1, 12, "/")
        assert diagnostics == ([b"srvr", b"mntr", b"isro"] if keeper else [b"srvr"])

    asyncio.run(run())


def test_socket_cancellation_closes_peer_and_does_not_leak_readiness():
    async def run():
        seen = asyncio.Event()
        closed = asyncio.Event()

        async def peer(reader, writer):
            try:
                await reader.readexactly(1)
                seen.set()
                assert await reader.read() == b""
            finally:
                writer.close()
                await writer.wait_closed()
                closed.set()

        server = await asyncio.start_server(peer, "127.0.0.1", 0)
        async with server:
            io = RetainedSocketIO()
            sock = await io.open(("127.0.0.1", server.sockets[0].getsockname()[1]), 1)
            await io.sendall(sock, b"x")
            await seen.wait()

            async def receive():
                try:
                    await io.recv(sock, 1)
                finally:
                    io.close()

            task = asyncio.create_task(receive())
            await asyncio.sleep(0)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            await asyncio.wait_for(closed.wait(), 2)
            assert not io.sockets
            assert sock.fileno() == -1

    asyncio.run(run())


@pytest.mark.parametrize("host", ["example.invalid", "fe80::1%en0"])
def test_retained_adapter_declines_dns_and_scoped_addresses_before_connect(host):
    async def run():
        io = RetainedSocketIO()
        with pytest.raises(AsyncHttpFallback):
            await io.open((host, 1), 1)
        assert not io.sockets

    asyncio.run(run())


@pytest.mark.parametrize("collision", [False, True])
def test_keeper_ddl_existing_ephemeral_create_delete_is_native(collision):
    from redposture_core.detection_io import DetectCall
    from redposture_core.modules.keeper import actions as keeper_actions

    async def run():
        requests = []
        closed = asyncio.Event()

        async def peer(reader, writer):
            try:
                await read_frame(reader)
                writer.write(frame(struct.pack(">iiqi", 0, 1000, 1, 16) + bytes(16)))
                await writer.drain()
                creates = 0
                while True:
                    request = await read_frame(reader)
                    xid, opcode = struct.unpack(">ii", request[:8])
                    if opcode == -11:
                        return
                    path, offset = zookeeper._decode_zk_string(request, 8)
                    requests.append((opcode, path))
                    err, payload = 0, b""
                    if opcode == 12:
                        payload = struct.pack(">i", 0) + bytes(68)
                    elif opcode == 1:
                        creates += 1
                        assert request[offset : offset + 4] == bytes(4)
                        assert struct.unpack(">i", request[-4:])[0] == 1
                        if collision and creates == 1:
                            err = -110
                    elif opcode == 2:
                        assert struct.unpack(">i", request[-4:])[0] == -1
                    writer.write(frame(struct.pack(">iqi", xid, 0, err) + payload))
                    await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()
                closed.set()

        server = await asyncio.start_server(peer, "127.0.0.1", 0)
        async with server:
            client = zookeeper._ZkClient(
                "127.0.0.1",
                server.sockets[0].getsockname()[1],
                1,
                transport_config=zookeeper.ZkTransportConfig(mode="plaintext"),
            )

            def steps():
                yield DetectCall(client.connect, (), {})
                return (yield DetectCall(keeper_actions.probe_ddl_access, (client,), {}))

            result = await detect_native(
                steps(), None, {**zookeeper._ASYNC_RETAINED_STEPS, **keeper_actions._ASYNC_RETAINED_STEPS}
            )
            assert result == ("Write", None)
            client.close()
            await asyncio.wait_for(closed.wait(), 2)
        assert requests[0] == (12, "/clickhouse/task_queue/ddl")
        assert [opcode for opcode, _ in requests] == ([12, 1, 1, 2] if collision else [12, 1, 2])
        assert requests[-1][1] == requests[-2][1]
        assert requests[-1][1].startswith("/clickhouse/task_queue/ddl/redposture-probe-")

    asyncio.run(run())
