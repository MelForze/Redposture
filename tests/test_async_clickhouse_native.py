"""Full native ClickHouse validation and retained synchronous driver adoption."""

import asyncio
import struct
from types import SimpleNamespace

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.modules.clickhouse import actions, async_detect, stage
from redposture_core.stage_runtime import AuditCredentialRun, AuditHookContext


def context(port, *, enum_cve=False):
    return AuditHookContext(
        args=SimpleNamespace(timeout=1, retries=0, protocol="native", enum_cve=enum_cve),
        logger=None,
        host="127.0.0.1",
        port=port,
        credential=AuditCredentialRun(source="anonymous"),
        phase="detect",
        run_deep_checks=False,
        lifecycle_state=actions.ClickHouseLifecycleState(),
    )


def varint(value):
    output = bytearray()
    while value > 127:
        output.append((value & 127) | 128)
        value >>= 7
    output.append(value)
    return bytes(output)


def string(value):
    value = value.encode()
    return varint(len(value)) + value


async def read_varint(reader):
    value, shift = 0, 0
    while True:
        byte = (await reader.readexactly(1))[0]
        value |= (byte & 127) << shift
        if byte < 128:
            return value
        shift += 7


async def read_string(reader):
    return (await reader.readexactly(await read_varint(reader))).decode()


BLOCK_INFO = b"\x01\x00\x02" + struct.pack("<i", -1) + b"\x00"
EMPTY_DATA = b"\x02\x00" + BLOCK_INFO + b"\x00\x00"


def result(value):
    column_type = "String" if isinstance(value, str) else "UInt8"
    encoded = string(value) if isinstance(value, str) else bytes([value])
    return b"\x01\x00" + BLOCK_INFO + b"\x01\x01" + string("value") + string(column_type) + encoded + b"\x05"


def exception(code):
    return b"\x02" + struct.pack("<i", code) + string("DB::Exception") + string("access denied") + string("") + b"\x00"


@pytest.mark.parametrize("enum_cve", [False, True])
def test_native_select1_then_same_driver_socket_serves_sync_query(monkeypatch, enum_cve):
    # A driver execute on the event loop would violate the native detection contract.
    from clickhouse_driver import Client

    original_execute = Client.execute

    def guarded(self, *args, **kwargs):
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return original_execute(self, *args, **kwargs)
        pytest.fail("synchronous driver execute ran on detection loop")

    monkeypatch.setattr(Client, "execute", guarded)

    async def run():
        calls, connections, failures = [], [], []
        done = asyncio.Event()

        async def peer(reader, writer):
            connections.append(1)
            try:
                assert await read_varint(reader) == 0
                client_name = await read_string(reader)
                for _ in range(3):
                    await read_varint(reader)
                credentials = [await read_string(reader) for _ in range(3)]
                calls.append(("hello", credentials))
                assert "python-driver" in client_name
                writer.write(
                    b"\x00"
                    + string("ClickHouse")
                    + varint(20)
                    + varint(8)
                    + varint(54401)
                    + string("UTC")
                    + string("server")
                    + varint(1)
                )
                await writer.drain()
                queries = [("SELECT 1", 1)]
                if enum_cve:
                    queries.append(("SELECT version()", "20.8.1"))
                queries.append(("SELECT 2", 2))
                for index, (query, value) in enumerate(queries):
                    if index:
                        assert await read_varint(reader) == 4
                        calls.append("ping")
                        writer.write(b"\x04")
                        await writer.drain()
                    request = await reader.readuntil(EMPTY_DATA)
                    assert query.encode() in request
                    calls.append(query)
                    for byte in result(value):
                        writer.write(bytes([byte]))
                        await writer.drain()
            except BaseException as exc:
                failures.append(exc)
            finally:
                writer.close()
                await writer.wait_closed()
                done.set()

        server = await asyncio.start_server(peer, "127.0.0.1", 0)
        async with server:
            ctx = context(server.sockets[0].getsockname()[1], enum_cve=enum_cve)
            options = stage._build_clickhouse_host_stage_options(ctx.args)
            record = await async_detect.detect(ctx, None, options)
            assert record.status == "open_no_auth"
            session = ctx.lifecycle_state.anonymous_session
            assert session is not None
            assert session.client.connection.connected is True
            assert session.client.connection.socket.gettimeout() == 1
            if enum_cve:
                assert record.extra["server_version"] == "20.8.1"
            # This is the existing synchronous downstream worker, not a detect facade.
            rows = await asyncio.get_running_loop().run_in_executor(None, session.client.execute, "SELECT 2")
            assert rows == [(2,)]
            await asyncio.wait_for(done.wait(), 2)
            ctx.lifecycle_state.close()
        assert not failures
        assert connections == [1]
        assert calls[0] == ("hello", ["default", "default", ""])
        assert calls[1] == "SELECT 1"
        assert calls[-2:] == ["ping", "SELECT 2"]

    asyncio.run(run())


@pytest.mark.parametrize("code,phase,status", [(516, "hello", "auth_required"), (497, "query", "anonymous_limited")])
def test_native_server_exception_evidence(code, phase, status):
    async def run():
        async def peer(reader, writer):
            assert await read_varint(reader) == 0
            await read_string(reader)
            for _ in range(3):
                await read_varint(reader)
            for _ in range(3):
                await read_string(reader)
            if phase == "query":
                writer.write(
                    b"\x00"
                    + string("ClickHouse")
                    + varint(20)
                    + varint(8)
                    + varint(54401)
                    + string("UTC")
                    + string("server")
                    + varint(1)
                )
                await writer.drain()
                await reader.readuntil(EMPTY_DATA)
            writer.write(exception(code))
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(peer, "127.0.0.1", 0)
        async with server:
            ctx = context(server.sockets[0].getsockname()[1])
            record = await async_detect.detect(ctx, None, stage._build_clickhouse_host_stage_options(ctx.args))
            assert record.status == status
            assert record.extra["is_clickhouse"] is True
            assert record.auth_required is (code == 516)
            ctx.lifecycle_state.close()

    asyncio.run(run())


def test_spec_binds_native_adapter_to_exact_sync_hook():
    spec = stage.build_clickhouse_spec(SimpleNamespace())
    assert spec.detect_async is not None
    assert spec.async_detect_sync_hook is spec.detect


@pytest.mark.parametrize("kind", ["success", "auth", "limited", "transport", "protocol_mismatch"])
def test_complete_sync_native_decision_parity(monkeypatch, kind):
    calls = []

    def probe(protocol, host, port, timeout, username, password, **kwargs):
        calls.append((protocol, host, port, timeout, username, password, kwargs))
        if kind in {"success", "limited"}:
            session = actions._ChSession(protocol, object(), username, password, kwargs["database"])
            error = (
                actions._ChProbeError(
                    "access denied", kind="access_limited", confirms_service=True, access_limited=True, code=497
                )
                if kind == "limited"
                else None
            )
            return actions._probe_result(session, error)
        return actions._probe_result(
            None,
            actions._ChProbeError(
                "probe verdict",
                kind=kind,
                confirms_service=kind == "auth",
                auth_required=True if kind == "auth" else None,
            ),
        )

    ctx = context(9000)
    options = stage._build_clickhouse_host_stage_options(ctx.args)
    with monkeypatch.context() as local:
        local.setattr(actions, "_connect_and_probe", probe)
        expected = actions.detect_clickhouse(ctx, options)
    expected_calls = calls[:]
    calls.clear()

    class FakeIO:
        async def connect_and_probe(self, *args, **kwargs):
            return probe(*args, **kwargs)

        def adopt(self):
            pass

        def close(self):
            pass

    monkeypatch.setattr(async_detect, "NativeClickHouseIO", FakeIO)
    got = asyncio.run(async_detect.detect(context(9000), None, options)).to_dict()
    expected = AuditRecord.from_mapping(expected, module="clickhouse", service="clickhouse").to_dict()
    got.pop("timestamp", None)
    expected.pop("timestamp", None)
    assert got == expected
    assert calls == expected_calls
