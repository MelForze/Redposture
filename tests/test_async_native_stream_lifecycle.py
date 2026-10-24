"""Native detection must keep DNS and cancellation from escaping its lifetime."""

import asyncio
import time
from types import SimpleNamespace

import pytest

from redposture_core.clients import async_mongodb_detect, async_oracle_detect
from redposture_core.clients.async_detect_stream import close_stream, require_numeric_host
from redposture_core.clients.async_http_detect import AsyncHttpFallback
from redposture_core.modules.postgres import async_detect as postgres


@pytest.mark.parametrize("host", ["localhost", "example.invalid", "fe80::1%lo0"])
def test_hostname_or_scoped_ipv6_requires_legacy_before_connector(monkeypatch, host):
    async def forbidden(*args, **kwargs):
        pytest.fail("native connector must not start an executor DNS lookup")

    monkeypatch.setattr(asyncio, "open_connection", forbidden)

    async def run():
        with pytest.raises(AsyncHttpFallback):
            await postgres._probe(host, 5432, 60, postgres.actions._PgTlsConfig(), "postgres")
        with pytest.raises(AsyncHttpFallback):
            await async_mongodb_detect.probe_legacy_hello(host, 27017, timeout=60)
        with pytest.raises(AsyncHttpFallback):
            await async_oracle_detect.listener_command(host, 1521, "status", timeout=60)

    asyncio.run(run())


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "2001:db8::1"])
def test_numeric_hosts_need_no_resolver(host):
    assert require_numeric_host(host) is None


class StalledWriter:
    def __init__(self):
        self.closed = False
        self.aborted = False
        self.writes = []
        self.transport = SimpleNamespace(abort=self.abort)

    def write(self, data):
        self.writes.append(data)

    async def drain(self):
        await asyncio.Event().wait()

    def close(self):
        self.closed = True

    async def wait_closed(self):
        await asyncio.Event().wait()

    def abort(self):
        self.aborted = True


def test_close_has_one_quarter_second_budget_for_terminate_and_shutdown():
    async def run():
        writer = StalledWriter()
        started = time.monotonic()
        await asyncio.wait_for(close_stream(writer, terminate=b"X\x00\x00\x00\x04"), 0.6)
        assert time.monotonic() - started < 0.6
        assert writer.closed and writer.aborted

    asyncio.run(run())


def test_cancelled_close_aborts_and_propagates_cancellation():
    async def run():
        writer = StalledWriter()
        task = asyncio.create_task(close_stream(writer, terminate=b"X\x00\x00\x00\x04"))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 0.6)
        assert writer.closed and writer.aborted

    asyncio.run(run())


def test_oracle_driver_and_modern_mongo_also_guard_dns(monkeypatch):
    monkeypatch.setattr(
        async_mongodb_detect.helpers,
        "_load_pymongo",
        lambda: pytest.fail("must guard hostname before constructing driver"),
    )
    monkeypatch.setattr(
        async_oracle_detect.helpers,
        "_load_oracledb",
        lambda: pytest.fail("must guard hostname before constructing driver"),
    )
    with pytest.raises(AsyncHttpFallback):
        async_mongodb_detect.open_client("example.invalid", 27017, timeout=1, auth_db="admin")
    with pytest.raises(AsyncHttpFallback):
        asyncio.run(
            async_oracle_detect.connect_probe(
                "example.invalid",
                1521,
                timeout=1,
                protocol="tcp",
                service="XE",
                sid=None,
                wallet=None,
                ssl_server_dn=None,
                insecure=True,
            )
        )


@pytest.mark.parametrize("wrapped", [False, True])
def test_oracle_preserves_resolver_fallback_even_in_exception_chain(monkeypatch, wrapped):
    fallback = AsyncHttpFallback("hostname redirect requires legacy resolver")

    async def connect(**kwargs):
        if wrapped:
            raise RuntimeError("driver connection failed") from fallback
        raise fallback

    monkeypatch.setattr(
        async_oracle_detect.helpers,
        "_load_oracledb",
        lambda: SimpleNamespace(is_thin_mode=lambda: True, connect_async=connect),
    )
    with pytest.raises(AsyncHttpFallback, match="hostname redirect"):
        asyncio.run(
            async_oracle_detect.connect_probe(
                "127.0.0.1",
                1521,
                timeout=1,
                protocol="tcp",
                service="XE",
                sid=None,
                wallet=None,
                ssl_server_dn=None,
                insecure=True,
            )
        )


def test_mongodb_topology_fallback_never_becomes_negative_selection_timeout():
    from pymongo.errors import ServerSelectionTimeoutError

    fallback = AsyncHttpFallback("hostname discovery requires legacy resolver")

    class Driver:
        topology_description = SimpleNamespace(
            server_descriptions=lambda: {("127.0.0.1", 27017): SimpleNamespace(error=fallback)}
        )

        def __getitem__(self, name):
            return self

        async def command(self, command):
            raise ServerSelectionTimeoutError("selection timed out")

    with pytest.raises(AsyncHttpFallback, match="hostname discovery"):
        asyncio.run(async_mongodb_detect.AsyncMongoDetectClient(Driver()).hello())
