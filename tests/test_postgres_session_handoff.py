"""Same identity keeps its session; different credentials always authenticate."""

from __future__ import annotations

import asyncio
import socket
import ssl
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.clients.http_handoff import HttpHandoffBudget
from redposture_core.clients.session_handoff import SessionHandoff
from redposture_core.modules.postgres import actions, async_detect, stage
from redposture_core.modules.postgres.session import session_scope
from redposture_core.stage_runtime import AuditCredentialRun, AuditHookContext


@pytest.mark.parametrize("retained", [False, True])
@pytest.mark.parametrize("capability_error", [None, "timed out"])
def test_auth_data_keep_all_capability_checks_but_avoid_second_startup(retained, capability_error, monkeypatch):
    opened, startup, checks, peers = [], [], [], []

    @contextmanager
    def connect(*args, **kwargs):
        client, peer = socket.socketpair()
        opened.append(client)
        peers.append(peer)
        try:
            yield client
        finally:
            client.close()

    def auth(sock, username, password, database):
        startup.append((username, password, database))
        return actions._PgSession(True, "cleartext", "17.2", True, True, username, database)

    def privileges(sock, **kw):
        checks.append("privileges")
        return False, False, True, [], capability_error

    def databases(sock):
        checks.append("databases")
        return ["postgres"], None

    monkeypatch.setattr(actions, "_pg_open_socket", connect)
    monkeypatch.setattr(actions, "_pg_startup_and_auth", auth)
    monkeypatch.setattr(actions, "_collect_postgres_privileges", privileges)
    monkeypatch.setattr(actions, "_pg_query_databases", databases)
    monkeypatch.setattr(actions, "_pg_collect_database_artifacts", lambda *a, **k: (None, [], [], [], 0, None))
    args = SimpleNamespace(timeout=1, retries=0)
    state = stage._PostgresLifecycleState(sessions=SessionHandoff(None if retained else HttpHandoffBudget(0)))
    ctx = AuditHookContext(
        args, None, "127.0.0.1", 5432, AuditCredentialRun("reader", "pass", source="provided"), lifecycle_state=state
    )
    try:
        verified = stage._postgres_auth(
            ctx, AuditRecord("127.0.0.1", 5432, "postgres", "auth_required", True, "postgres")
        )
        assert verified.extra["credential_verified"] is True
        record = stage._postgres_data(ctx, verified)
        assert record.status == "valid_credentials"
        assert record.extra["database_count"] == 1
        assert checks == ["privileges", "databases", "privileges", "databases"]
        assert len(opened) == len(startup) == (1 if retained and capability_error is None else 2)
    finally:
        if state.sessions is not None:
            state.sessions.close()
        for peer in peers:
            peer.close()
    assert all(sock.fileno() == -1 for sock in opened)


@pytest.mark.parametrize("changed", ["user", "password", "database", "tls"])
def test_session_key_never_crosses_identity_database_or_tls(changed, monkeypatch):
    peers, opened = [], []

    @contextmanager
    def connect(*args, **kwargs):
        sock, peer = socket.socketpair()
        opened.append(sock)
        peers.append(peer)
        try:
            yield sock
        finally:
            sock.close()

    monkeypatch.setattr(actions, "_pg_open_socket", connect)
    monkeypatch.setattr(actions, "_pg_startup_and_auth", lambda *a, **k: actions._PgSession(True, "md5", "17"))
    config = dict(username="reader", password="pass", database="postgres", tls_config=actions._PgTlsConfig())
    cache = SessionHandoff()
    try:
        with session_scope("127.0.0.1", 5432, 1, cache=cache, retain=True, **config):
            pass
        second = dict(config)
        second[{"user": "username", "tls": "tls_config"}.get(changed, changed)] = (
            actions._PgTlsConfig(sslmode="require") if changed == "tls" else "different"
        )
        with session_scope("127.0.0.1", 5432, 1, cache=cache, reuse=True, **second):
            pass
        assert len(opened) == 2
    finally:
        cache.close()
        for peer in peers:
            peer.close()


@pytest.mark.parametrize("mode", ["plain", "tls", "mtls"])
def test_native_anonymous_startup_can_be_used_by_sync_reader_without_reconnect(mode, mtls_material):
    budget = HttpHandoffBudget(1)
    cache = SessionHandoff(budget)
    config = actions._PgTlsConfig(sslmode="require" if mode == "tls" else "disable")
    server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_tls.load_cert_chain(mtls_material["server_cert"], mtls_material["server_key"])
    if mode == "mtls":
        server_tls.verify_mode = ssl.CERT_REQUIRED
        server_tls.load_verify_locations(str(mtls_material["ca_cert"]))
        config = actions._PgTlsConfig(
            sslmode="verify-ca",
            ca_file=str(mtls_material["ca_cert"]),
            cert_file=str(mtls_material["client_cert"]),
            key_file=str(mtls_material["client_key"]),
        )

    async def run():
        connections = []
        done = asyncio.Event()

        async def serve(reader, writer):
            connections.append(1)
            try:
                if mode != "plain":
                    assert await reader.readexactly(8) == b"\x00\x00\x00\x08\x04\xd2\x16\x2f"
                    writer.write(b"S")
                    await writer.drain()
                    await writer.start_tls(server_tls)
                length = int.from_bytes(await reader.readexactly(4), "big")
                await reader.readexactly(length - 4)
                writer.write(b"R\x00\x00\x00\x08\x00\x00\x00\x00Z\x00\x00\x00\x05I")
                await writer.drain()
                assert await reader.readexactly(5) == b"X\x00\x00\x00\x04"
            finally:
                writer.close()
                await writer.wait_closed()
                done.set()

        server = await asyncio.start_server(serve, "127.0.0.1", 0)
        async with server:
            port = server.sockets[0].getsockname()[1]
            result = await async_detect._probe_retained("127.0.0.1", port, 1, config, "postgres", cache)
            assert result.auth_required is False and budget.active == 1
            with session_scope(
                "127.0.0.1",
                port,
                1,
                username="postgres",
                password=None,
                database="postgres",
                tls_config=config,
                cache=cache,
                reuse=True,
            ) as (sock, session):
                assert session is result
                assert isinstance(sock, ssl.SSLSocket) is (mode != "plain")
            await asyncio.wait_for(done.wait(), 2)
            assert len(connections) == 1 and budget.active == 0

    try:
        asyncio.run(run())
    finally:
        cache.close()
