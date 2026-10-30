"""Startup protocol evidence and password proof are independent observations."""

from __future__ import annotations

import asyncio
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from redposture_core.modules.postgres import actions, async_detect, stage
from tests.test_async_native_record_parity import context, stable


def frame(kind: bytes, body: bytes) -> bytes:
    return kind + (len(body) + 4).to_bytes(4, "big") + body


def error(code: str, message: str) -> bytes:
    return frame(b"E", b"SFATAL\0C" + code.encode() + b"\0M" + message.encode() + b"\0\0")


class Socket:
    def __init__(self, response: bytes):
        self.response = response
        self.sent: list[bytes] = []

    def recv(self, size: int) -> bytes:
        part, self.response = self.response[:size], self.response[size:]
        return part

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)


@pytest.mark.parametrize(
    "response",
    [
        frame(b"E", b""),
        frame(b"E", b"not a PostgreSQL error\0"),
        frame(b"E", b"SFATAL\0Mno such user\0\0"),
        frame(b"E", b"SFATAL\0CINVALID\0Mno such user\0\0"),
        frame(b"E", b"SFATAL\0C28000\0Munterminated"),
        frame(b"R", (3).to_bytes(4, "big") + b"extra"),
        frame(b"R", (5).to_bytes(4, "big") + b"bad"),
        frame(b"S", b"server_version\0missing-terminator"),
        frame(b"K", b"bad"),
        frame(b"Z", b"garbage"),
        frame(b"Z", b"I"),
    ],
)
def test_invalid_startup_frames_do_not_confirm_an_unrelated_listener(response):
    with pytest.raises(actions._PgAuditError) as caught:
        actions._pg_startup_and_auth(Socket(response), "alice", "candidate", "app")
    assert caught.value.detected is False
    assert getattr(caught.value, "credential_verified", None) is None


@pytest.mark.parametrize(
    ("code", "message", "kind"),
    [
        ("28000", "no such user", "unknown_user"),
        ("08P01", "no such user", "unknown_user"),
        ("3D000", 'database "app" does not exist', "database_unavailable"),
        ("28000", 'no pg_hba.conf entry for host "127.0.0.1", user "alice"', "auth_policy_denied"),
        ("XX000", "no authentication method is found", "auth_configuration_error"),
    ],
)
def test_pre_password_startup_rejection_is_not_a_password_verdict(code, message, kind):
    sock = Socket(error(code, message))
    with pytest.raises(actions._PgAuditError) as caught:
        actions._pg_startup_and_auth(sock, "alice", "candidate", "app")
    exc = caught.value
    assert exc.detected is True
    assert exc.error_kind == kind
    assert getattr(exc, "credential_verified", None) is None
    assert getattr(exc, "password_sent", False) is False
    assert not any(packet.startswith(b"p") for packet in sock.sent)


def test_later_database_error_preserves_auth_challenge_and_observed_version():
    response = frame(b"R", (3).to_bytes(4, "big"))
    response += frame(b"S", b"server_version\x0016.4\0") + error("3D000", 'database "app" does not exist')
    with pytest.raises(actions._PgAuditError) as caught:
        actions._pg_startup_and_auth(Socket(response), "alice", "candidate", "app")
    exc = caught.value
    assert exc.detected is True and exc.auth_required is True
    assert getattr(exc, "server_version", None) == "16.4"
    assert getattr(exc, "password_sent", False) is True
    assert getattr(exc, "credential_verified", None) is None


def test_eof_after_a_valid_challenge_keeps_service_and_auth_evidence():
    with pytest.raises(actions._PgAuditError) as caught:
        actions._pg_startup_and_auth(Socket(frame(b"R", (3).to_bytes(4, "big"))), "alice", "candidate", "app")
    assert caught.value.detected is True
    assert caught.value.auth_required is True
    assert getattr(caught.value, "credential_verified", None) is None
    assert caught.value.error_kind == "transport_error"


@pytest.mark.parametrize("supported", [True, False])
def test_only_an_explicit_password_failure_after_exchange_is_rejected(monkeypatch, supported):
    response = frame(b"R", (3 if supported else 7).to_bytes(4, "big"))
    if supported:
        response += error("28P01", 'password authentication failed for user "alice"')
    sock = Socket(response)
    monkeypatch.setattr(actions, "_pg_open_socket", lambda *_args, **_kwargs: _opened(sock))
    ctx = SimpleNamespace(
        host="127.0.0.1",
        port=6432,
        credential=SimpleNamespace(username="alice", password="candidate", source="provided"),
        args=SimpleNamespace(
            timeout=1,
            retries=0,
            database="app",
            sslmode="disable",
            ssl_ca=None,
            ssl_cert=None,
            ssl_key=None,
            ssl_server_name=None,
        ),
    )
    record = stage._postgres_probe_credential(ctx).to_dict()
    assert record["credential_verified"] is (False if supported else None)
    assert record["credential_verification"] == ("rejected" if supported else "unavailable")


@contextmanager
def _opened(sock):
    yield sock


@pytest.mark.parametrize("response", [error("08P01", "no such user"), frame(b"E", b"noise\0"), frame(b"Z", b"I")])
def test_async_startup_evidence_matches_sync(monkeypatch, response):
    sock = Socket(response)
    monkeypatch.setattr(actions, "_pg_open_socket", lambda *_args, **_kwargs: _opened(sock))
    expected = stage._postgres_detect(context("postgres"))

    class Reader:
        def __init__(self):
            self.data = response

        async def read(self, size):
            part, self.data = self.data[:size], self.data[size:]
            return part

    class Writer:
        transport = SimpleNamespace(abort=lambda: None)

        def write(self, data):
            pass

        async def drain(self):
            pass

        def close(self):
            pass

        async def wait_closed(self):
            pass

    async def connect(*_args, **_kwargs):
        return Reader(), Writer()

    monkeypatch.setattr(asyncio, "open_connection", connect)
    result = asyncio.run(async_detect.detect(context("postgres"), None))
    assert stable(result) == stable(expected)
