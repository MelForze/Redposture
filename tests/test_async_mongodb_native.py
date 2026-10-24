"""MongoDB native detection retains the exact hello and anonymous-list evidence."""

import asyncio
from types import SimpleNamespace

import pytest

from redposture_core.clients.async_http_detect import AsyncHttpFallback
from redposture_core.modules.mongodb import async_detect, stage

HELLO = {"ok": 1, "minWireVersion": 0, "maxWireVersion": 17, "isWritablePrimary": True}


def ctx():
    return SimpleNamespace(
        host="127.0.0.1", port=27017, args=SimpleNamespace(timeout=1, retries=0), lifecycle_state=None, debug_emit=None
    )


@pytest.mark.parametrize(
    "listing,status,required",
    [
        (["admin", "app"], "open_no_auth", False),
        (RuntimeError("not authorized"), "auth_required", True),
        (RuntimeError("connection reset"), "fail", False),
    ],
)
def test_native_anonymous_evidence(monkeypatch, listing, status, required):
    calls = []

    class Client:
        async def hello(self):
            calls.append("hello")
            return HELLO

        async def server_info(self):
            calls.append("buildInfo")
            return {"version": "7.0.1"}

        async def list_database_names(self):
            calls.append("listDatabases")
            if isinstance(listing, Exception):
                raise listing
            return listing

        async def close(self):
            calls.append("close")

    monkeypatch.setattr(async_detect, "open_client", lambda *a, **k: Client())
    record = asyncio.run(async_detect.detect(ctx(), None))
    assert record.status == status
    assert record.auth_required is required
    assert record.extra["is_mongodb"] is True
    assert record.extra["hello"] == HELLO
    assert calls == ["hello", "buildInfo", "listDatabases", "close"]


def test_missing_async_driver_requests_legacy(monkeypatch):
    monkeypatch.setattr(async_detect.client_helpers, "_load_pymongo", lambda: SimpleNamespace())
    with pytest.raises(AsyncHttpFallback):
        async_detect.open_client("127.0.0.1", 27017, timeout=1, auth_db="admin")


def test_spec_registers_matching_sync_hook():
    spec = stage.build_mongodb_spec(SimpleNamespace())
    assert spec.detect_async is async_detect.detect
    assert spec.async_detect_sync_hook is spec.detect


def test_native_client_hello_fallback_is_only_code_59():
    from pymongo.errors import OperationFailure

    from redposture_core.clients.async_mongodb_detect import AsyncMongoDetectClient

    commands = []

    class Driver:
        def __getitem__(self, name):
            return self

        async def command(self, command):
            commands.append(command)
            if command == "hello":
                raise OperationFailure("no such command", code=59)
            return HELLO

    assert asyncio.run(AsyncMongoDetectClient(Driver()).hello()) == HELLO
    assert commands == ["hello", "isMaster"]


def test_generic_hello_ack_is_not_mongodb():
    from redposture_core.clients.async_mongodb_detect import AsyncMongoDetectClient
    from redposture_core.clients.mongodb import MongoNotMongoError

    class Driver:
        def __getitem__(self, name):
            return self

        async def command(self, command):
            return {"ok": 1}

    with pytest.raises(MongoNotMongoError):
        asyncio.run(AsyncMongoDetectClient(Driver()).hello())


@pytest.mark.parametrize("response_to,opcode,detected", [(1, 1, True), (2, 1, False), (1, 2013, False)])
def test_native_legacy_framer(response_to, opcode, detected):
    import struct

    from bson import BSON

    from redposture_core.clients.async_mongodb_detect import probe_legacy_hello

    async def run():
        requests = []

        async def peer(reader, writer):
            header = await reader.readexactly(16)
            size, request_id, _response_to, operation = struct.unpack("<iiii", header)
            requests.append((request_id, operation, await reader.readexactly(size - 16)))
            document = BSON.encode(HELLO)
            body = struct.pack("<iqii", 0, 0, 0, 1) + document
            reply = struct.pack("<iiii", 16 + len(body), 7, response_to, opcode) + body
            for byte in reply:
                writer.write(bytes([byte]))
                await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(peer, "127.0.0.1", 0)
        async with server:
            hello = await probe_legacy_hello("127.0.0.1", server.sockets[0].getsockname()[1], timeout=1)
        assert (hello == HELLO) is detected
        assert requests[0][:2] == (1, 2004)
        assert BSON.encode({"isMaster": 1}) in requests[0][2]

    asyncio.run(run())


def test_explicit_database_keeps_native_collection_count_evidence(monkeypatch):
    calls = []

    class Client:
        async def hello(self):
            return HELLO

        async def server_info(self):
            return {}

        async def list_database_names(self):
            return ["app"]

        async def list_collection_names(self, db):
            calls.append(("list", db))
            return ["a", "b"]

        async def count_documents(self, db, collection):
            calls.append(("count", db, collection))
            if collection == "b":
                raise RuntimeError("not authorized")
            return 2

        async def close(self):
            pass

    monkeypatch.setattr(async_detect, "open_client", lambda *a, **k: Client())
    context = ctx()
    context.args.database = "app"
    record = asyncio.run(async_detect.detect(context, None))
    assert calls == [("list", "app"), ("count", "app", "a"), ("count", "app", "b")]
    assert record.extra["partial"] is True
    assert record.extra["collections"] == []
    assert record.extra["capability_coverage"]["can_read_documents"] == {
        "state": "partial",
        "successes": 1,
        "failures": 1,
    }
