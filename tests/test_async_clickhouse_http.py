"""Native HTTP ClickHouse keeps original initialization, query parsing and session."""

import asyncio
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from redposture_core.clients.async_clickhouse_http_detect import NativeClickHouseHttp
from redposture_core.modules.clickhouse import actions, async_detect, stage
from redposture_core.stage_runtime import AuditCredentialRun, AuditHookContext


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


def native(columns, rows):
    output = varint(len(columns)) + varint(len(rows))
    for index, (name, column_type) in enumerate(columns):
        output += string(name) + string(column_type)
        for row in rows:
            output += string(row[index]) if column_type == "String" else bytes([row[index]])
    return output


BLOCK_INFO = b"\x01\x00\x02\xff\xff\xff\xff\x00"


@pytest.mark.parametrize("protocol,enum_cve", [("http", False), ("http", True), ("auto", False)])
def test_http_original_initializer_and_same_socket_worker_query(monkeypatch, protocol, enum_cve):
    import urllib3

    original = urllib3.PoolManager.request

    def guarded(self, *args, **kwargs):
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return original(self, *args, **kwargs)
        pytest.fail("urllib3 network request executed on native detection loop")

    monkeypatch.setattr(urllib3.PoolManager, "request", guarded)

    async def run():
        calls, connections, failures = [], [], []
        worker_done = asyncio.Event()

        async def peer(reader, writer):
            connections.append(1)
            try:
                first = await reader.readexactly(1)
                if first == b"\x00":
                    calls.append("native_mismatch")
                    writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                    await writer.drain()
                    return
                while first:
                    line = first + await reader.readline()
                    method, path, _ = line.decode().split()
                    headers = {}
                    while True:
                        header = await reader.readline()
                        if header == b"\r\n":
                            break
                        key, value = header.decode().split(":", 1)
                        headers[key.lower()] = value.strip()
                    body = await reader.readexactly(int(headers.get("content-length", "0")))
                    sql = body.decode()
                    params = parse_qs(urlsplit(path).query)
                    calls.append(sql)
                    assert method == "POST"
                    assert headers.get("authorization") == "Basic ZGVmYXVsdDo="
                    if sql == "SELECT version(), timezone()":
                        response = b"24.10.1\tUTC\n"
                    elif "FROM system.settings LIMIT 10000" in sql:
                        response = native([("name", "String"), ("value", "String"), ("readonly", "UInt8")], [])
                    elif "SELECT 1 AS check" in sql:
                        response = BLOCK_INFO + native([("check", "UInt8")], [[1]])
                    else:
                        value = "24.10.1" if "version()" in sql else 2 if "SELECT 2" in sql else 1
                        response = native([("value", "String" if isinstance(value, str) else "UInt8")], [[value]])
                        if "client_protocol_version" in params:
                            response = BLOCK_INFO + response
                    writer.write(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: "
                        + str(len(response)).encode()
                        + b"\r\n\r\n"
                        + response
                    )
                    await writer.drain()
                    if "SELECT 2" in sql:
                        worker_done.set()
                        return
                    first = await reader.read(1)
            except BaseException as exc:
                failures.append(exc)
                worker_done.set()
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(peer, "127.0.0.1", 0)
        async with server:
            args = SimpleNamespace(protocol=protocol, timeout=1, retries=0, enum_cve=enum_cve)
            ctx = AuditHookContext(
                args=args,
                logger=None,
                host="127.0.0.1",
                port=server.sockets[0].getsockname()[1],
                credential=AuditCredentialRun(source="anonymous"),
                phase="detect",
                run_deep_checks=False,
                lifecycle_state=actions.ClickHouseLifecycleState(),
            )
            record = await async_detect.detect(ctx, None, stage._build_clickhouse_host_stage_options(args))
            assert record.status == "open_no_auth"
            assert record.extra["protocol"] == "http"
            if enum_cve:
                assert record.extra["server_version"] == "24.10.1"
            session = ctx.lifecycle_state.anonymous_session
            rows = await asyncio.get_running_loop().run_in_executor(
                None, lambda: session.client.query("SELECT 2").result_rows
            )
            assert rows == [(2,)] or rows == [[2]]
            await asyncio.wait_for(worker_done.wait(), 2)
            ctx.lifecycle_state.close()
        assert not failures
        assert len(connections) == (2 if protocol == "auto" else 1)
        sql_calls = calls[1:] if protocol == "auto" else calls
        assert sql_calls[0] == "SELECT version(), timezone()"
        assert "FROM system.settings LIMIT 10000" in sql_calls[1]
        assert "SELECT 1 AS check" in sql_calls[2]
        assert "SELECT 1" in sql_calls[3]
        assert "SELECT 2" in sql_calls[-1]

    asyncio.run(run())


@pytest.mark.parametrize(
    "error_code,phase,status",
    [
        (516, "init", "auth_required"),
        (497, "init", "detected"),
        (81, "init", "detected"),
        (497, "query", "anonymous_limited"),
        (None, "init", "not_clickhouse"),
    ],
)
def test_http_original_exception_evidence(error_code, phase, status):
    async def run():
        requests = []

        async def peer(reader, writer):
            try:
                while True:
                    line = await reader.readline()
                    if not line:
                        return
                    headers = {}
                    while True:
                        header = await reader.readline()
                        if header == b"\r\n":
                            break
                        key, value = header.decode().split(":", 1)
                        headers[key.lower()] = value.strip()
                    body = (await reader.readexactly(int(headers.get("content-length", "0")))).decode()
                    requests.append(body)
                    should_error = phase == "init" or body.startswith("SELECT 1\n")
                    if should_error:
                        payload = (
                            b"foreign endpoint"
                            if error_code is None
                            else f"Code: {error_code}. DB::Exception: access denied".encode()
                        )
                        code_header = (
                            b"" if error_code is None else f"X-ClickHouse-Exception-Code: {error_code}\r\n".encode()
                        )
                        writer.write(
                            b"HTTP/1.1 500 Error\r\n"
                            + code_header
                            + b"Content-Length: "
                            + str(len(payload)).encode()
                            + b"\r\nConnection: close\r\n\r\n"
                            + payload
                        )
                        await writer.drain()
                        return
                    if body == "SELECT version(), timezone()":
                        payload = b"20.8.1\tUTC\n"
                    else:
                        payload = native([("name", "String"), ("value", "String"), ("readonly", "UInt8")], [])
                    writer.write(
                        b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(payload)).encode() + b"\r\n\r\n" + payload
                    )
                    await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(peer, "127.0.0.1", 0)
        async with server:
            args = SimpleNamespace(protocol="http", timeout=1, retries=0)
            ctx = AuditHookContext(
                args=args,
                logger=None,
                host="127.0.0.1",
                port=server.sockets[0].getsockname()[1],
                credential=AuditCredentialRun(source="anonymous"),
                phase="detect",
                run_deep_checks=False,
                lifecycle_state=actions.ClickHouseLifecycleState(),
            )
            record = await async_detect.detect(ctx, None, stage._build_clickhouse_host_stage_options(args))
            assert record.status == status
            assert record.extra["is_clickhouse"] is (error_code is not None)
            assert record.auth_required is (True if error_code == 516 else False if phase == "query" else None)
            assert requests[0] == "SELECT version(), timezone()"
            if phase == "query":
                assert requests[1] in {
                    "SELECT name, value, readonly FROM system.settings LIMIT 10000\n FORMAT Native",
                    "SELECT name, value, readonly as readonly FROM system.settings LIMIT 10000\n FORMAT Native",
                }
                assert requests[2:-1] in ([], ["SELECT 1 AS check\n FORMAT Native"])
                assert requests[-1] == "SELECT 1\n FORMAT Native"
            else:
                assert len(requests) == 1
            ctx.lifecycle_state.close()

    asyncio.run(run())


def test_transport_failure_requests_original_retry_policy(monkeypatch):
    from redposture_core.clients.async_http_detect import AsyncHttpFallback
    from redposture_core.clients.async_retained_socket import RetainedSocketIO

    async def run():
        transport = NativeClickHouseHttp(RetainedSocketIO(), "127.0.0.1", 8123, 1, "default", "", None, None, None)

        async def exchange(request):
            raise ConnectionRefusedError("first connect refused")

        monkeypatch.setattr(transport, "_exchange", exchange)

        def initializer():
            return transport.pool.request(
                "POST", "http://127.0.0.1:8123/", body=b"SELECT version(), timezone()", retries=1
            )

        with pytest.raises(AsyncHttpFallback):
            await transport._drive(initializer)

    asyncio.run(run())
