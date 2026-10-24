"""Complete native records and request sequences against original sync detectors."""

import asyncio
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from redposture_core.stage_runtime import AuditCredentialRun, AuditHookContext


def context(module, **options):
    args = dict(timeout=1, retries=0, debug=False, auth_db="admin", database=None, protocol="tcp", service="XE")
    args.update(options)
    return AuditHookContext(
        args=SimpleNamespace(**args),
        logger=None,
        host="127.0.0.1",
        port={"postgres": 5432, "mongodb": 27017, "oracle": 1521}[module],
        credential=AuditCredentialRun(source="anonymous"),
        phase="detect",
        run_deep_checks=False,
        lifecycle_state={} if module == "oracle" else None,
    )


def stable(record):
    payload = record.to_dict()
    for key in ("timestamp", "elapsed_ms", "stage_timing_total_ms"):
        payload.pop(key, None)
    return payload


def frame(kind, body):
    return kind + (len(body) + 4).to_bytes(4, "big") + body


@pytest.mark.parametrize(
    "response",
    [
        frame(b"R", (3).to_bytes(4, "big")),
        frame(b"R", (5).to_bytes(4, "big")),
        frame(b"R", (5).to_bytes(4, "big") + b"salt"),
        frame(b"R", (10).to_bytes(4, "big")),
        frame(b"R", (11).to_bytes(4, "big")),
        frame(b"R", (12).to_bytes(4, "big")),
        frame(b"R", (7).to_bytes(4, "big")),
        frame(b"E", b"SERROR\0C28000\0Mpassword authentication failed\0\0"),
        frame(b"E", b"SERROR\0CXX000\0Mno authentication method is found\0\0"),
        frame(b"E", b"SERROR\0C3D000\0Mdatabase does not exist\0\0"),
        frame(b"R", bytes(4)) + frame(b"S", b"server_version\x0016.4\0") + frame(b"Z", b"I"),
        frame(b"Y", b""),
        b"R\x00\x00\x00\x03",
        b"",
    ],
)
def test_postgres_complete_record_and_startup_bytes(monkeypatch, response):
    from redposture_core.modules.postgres import actions, async_detect, stage

    class Socket:
        def __init__(self):
            self.data = response
            self.sent = []

        def recv(self, size):
            result, self.data = self.data[:size], self.data[size:]
            return result

        def sendall(self, data):
            self.sent.append(data)

    sock = Socket()

    @contextmanager
    def opened(*args, **kwargs):
        yield sock

    monkeypatch.setattr(actions, "_pg_open_socket", opened)
    expected = stage._postgres_detect(context("postgres"))

    class Reader:
        def __init__(self):
            self.data = response

        async def read(self, size):
            result, self.data = self.data[:size], self.data[size:]
            return result

    class Writer:
        def __init__(self):
            self.sent = []
            self.transport = SimpleNamespace(abort=lambda: None)

        def write(self, data):
            self.sent.append(data)

        async def drain(self):
            pass

        def close(self):
            pass

        async def wait_closed(self):
            pass

    writer = Writer()

    async def connect(*args, **kwargs):
        return Reader(), writer

    monkeypatch.setattr(asyncio, "open_connection", connect)
    got = asyncio.run(async_detect.detect(context("postgres"), None))
    assert stable(got) == stable(expected)
    assert writer.sent == sock.sent


@pytest.mark.parametrize(
    "listing,database",
    [
        (["admin", "app"], None),
        (RuntimeError("not authorized"), None),
        (RuntimeError("connection reset"), None),
        (["app"], "app"),
    ],
)
def test_mongodb_complete_record_and_requests(monkeypatch, listing, database):
    from redposture_core.modules.mongodb import actions, async_detect

    calls = []
    hello = {"ok": 1, "minWireVersion": 0, "maxWireVersion": 17, "isWritablePrimary": True}

    class Sync:
        def hello(self):
            calls.append("hello")
            return hello

        def server_info(self):
            calls.append("buildInfo")
            return {"version": "7.0.1"}

        def list_database_names(self):
            calls.append("listDatabases")
            if isinstance(listing, Exception):
                raise listing
            return listing

        def list_collection_names(self, db):
            calls.append(("listCollections", db))
            return ["a", "b"]

        def count_documents(self, db, collection):
            calls.append(("count", db, collection))
            if collection == "b":
                raise RuntimeError("not authorized")
            return 2

        def close(self):
            calls.append("close")

    context_value = context("mongodb", database=database)
    with monkeypatch.context() as local:
        local.setattr(actions, "_open_client", lambda *a, **kw: Sync())
        expected = async_detect.detect_sync(context_value)
    expected_calls = calls[:]
    calls.clear()

    class Native(Sync):
        async def hello(self):
            return super().hello()

        async def server_info(self):
            return super().server_info()

        async def list_database_names(self):
            return super().list_database_names()

        async def list_collection_names(self, db):
            return super().list_collection_names(db)

        async def count_documents(self, db, collection):
            return super().count_documents(db, collection)

        async def close(self):
            return super().close()

    monkeypatch.setattr(async_detect, "open_client", lambda *a, **kw: Native())
    got = asyncio.run(async_detect.detect(context_value, None))
    assert stable(got) == stable(expected)
    assert calls == expected_calls


@pytest.mark.parametrize(
    "status,restricted,service",
    [
        ("available", False, "XE"),
        ("unknown", False, "XE"),
        ("fail", False, "XE"),
        ("available", True, None),
    ],
)
def test_oracle_complete_record_cache_and_requests(monkeypatch, status, restricted, service):
    from redposture_core.modules.oracle import actions, async_detect

    calls = []

    def listener(*args, **kwargs):
        calls.append((args, kwargs))
        return {
            "ok": True,
            "text": "TNSLSNR (SERVICE_NAME=XE)",
            "protocol": "tcp",
            "listener_password_protected": False,
            "listener_restricted": restricted,
        }

    def targets(*args, **kwargs):
        calls.append((args, kwargs))
        return [
            {
                "protocol": "tcp",
                "service": "XE",
                "sid": None,
                "status": status,
                "exists": True if status == "available" else False if status == "unknown" else None,
                "auth_required": True if status == "available" else None,
                "error": "probe verdict",
            }
        ]

    expected_context = context("oracle", service=service)
    with monkeypatch.context() as local:
        local.setattr(actions, "tns_listener_command", listener)
        local.setattr(actions, "_probe_listener_targets", targets)
        expected = async_detect.detect_sync(expected_context)
    expected_calls = calls[:]
    calls.clear()

    async def native_listener(*args, **kwargs):
        return listener(*args, **kwargs)

    async def native_targets(*args, **kwargs):
        return targets(*args, **kwargs)

    monkeypatch.setattr(async_detect, "listener_command", native_listener)
    monkeypatch.setattr(async_detect, "probe_targets", native_targets)
    got_context = context("oracle", service=service)
    got = asyncio.run(async_detect.detect(got_context, None))
    assert stable(got) == stable(expected)
    assert got_context.lifecycle_state == expected_context.lifecycle_state
    assert calls == expected_calls
