from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.modules.redis import actions
from redposture_core.stage_runtime import AuditCredentialRun
from tests.test_authenticated_implementations import VALKEY


class Socket:
    def __init__(self):
        self.user = None
        self.closed = False
        self.timeout = 1

    def settimeout(self, value):
        self.timeout = value

    def gettimeout(self):
        return self.timeout

    def close(self):
        self.closed = True


def setup(monkeypatch, mode):
    state = actions.RedisAuditLifecycleState(
        "qa", 6379, 1, 0, False, None, time.monotonic(), is_redis=True, auth_required=True, status="auth_required"
    )
    args = SimpleNamespace(defcreds=True, enum_cve=False)
    auths = []
    probes = []

    def open_socket(state):
        state.sock = Socket()

    def authenticate(sock, user, password, **options):
        auths.append(user)
        if user == "bad":
            return False, "WRONGPASS"
        sock.user = user
        return True, None

    def command(sock, *parts):
        assert parts == ("INFO", "SERVER")
        probes.append(sock.user)
        if sock.user == "first" and mode == "disconnected":
            raise ConnectionError("incomplete INFO")
        if sock.user == "second":
            return "error", "NOPERM INFO denied"
        return "bulk", VALKEY.encode()

    monkeypatch.setattr(actions, "_open_redis_lifecycle_socket", open_socket)
    monkeypatch.setattr(actions, "_check_provided_credentials", authenticate)
    monkeypatch.setattr(actions, "_count_redis_keys", lambda sock: (4, None))
    monkeypatch.setattr(actions, "_send_cmd", command)

    def ctx(user):
        return SimpleNamespace(
            lifecycle_state=state,
            args=args,
            credential=AuditCredentialRun(username=user, password="qa-password", source="provided"),
        )

    detect = AuditRecord(
        host="qa",
        port=6379,
        module="redis",
        service="redis",
        status="auth_required",
        auth_required=True,
        extra={"is_redis": True},
    )
    return state, ctx, detect, auths, probes


def test_each_verified_pair_owns_its_info_evidence_and_denial_is_not_bad_credentials(monkeypatch):
    state, ctx, detect, auths, probes = setup(monkeypatch, "normal")
    first = actions.redis_auth_hook(ctx("first"), detect)
    second = actions.redis_auth_hook(ctx("second"), detect)
    rejected = actions.redis_auth_hook(ctx("bad"), detect)
    assert first.extra["server_implementation"]["product"] == "Valkey"
    assert second.status == "valid_credentials" and second.extra.get("server_implementation") is None
    assert second.extra["implementation_probe_error"] == "NOPERM INFO denied"
    assert rejected.extra.get("server_implementation") is None
    assert probes == ["first", "second"] and auths == ["first", "second", "bad"]
    actions.close_redis_lifecycle_state(state)


def test_optional_info_disconnect_cannot_select_a_later_or_rejected_identity_for_data(monkeypatch):
    state, ctx, detect, auths, probes = setup(monkeypatch, "disconnected")
    first = actions.redis_auth_hook(ctx("first"), detect)
    assert first.status == "valid_credentials" and first.extra.get("server_implementation") is None
    assert first.extra["implementation_probe_error"] == "incomplete INFO"
    actions.redis_auth_hook(ctx("bad"), detect)
    owners = []
    monkeypatch.setattr(
        actions, "_redis_collect_lifecycle_data_once", lambda state, **kw: owners.append(state.sock.user)
    )
    try:
        actions.redis_data_hook(ctx("first"), first)
    finally:
        actions.close_redis_lifecycle_state(state)
    assert owners == ["first"]
    assert auths == ["first", "bad", "first"]


def test_anonymous_detect_does_not_gain_authenticated_probe(monkeypatch):
    state, ctx, detect, auths, probes = setup(monkeypatch, "normal")
    anonymous = ctx("first")
    anonymous.credential = AuditCredentialRun(source="anonymous")
    record = actions.redis_auth_hook(anonymous, detect)
    assert record.extra.get("server_implementation") is None
    assert not auths and not probes
    actions.close_redis_lifecycle_state(state)


@pytest.mark.parametrize("mode", ["oversized", "eof"])
def test_optional_info_wire_limit_keeps_verified_auth_and_discards_partial_socket(mode):
    class Wire(Socket):
        def __init__(self):
            super().__init__()
            self.data = bytearray(b"$1000000000\r\n" + b"x" * 80000 if mode == "oversized" else b"$20\r\nshort")
            self.max_requested = 0
            self.sent = []

        def recv(self, count):
            self.max_requested = max(self.max_requested, count)
            data = bytes(self.data[:count])
            del self.data[:count]
            return data

        def sendall(self, data):
            self.sent.append(data)

    sock = Wire()
    state = actions.RedisAuditLifecycleState(
        "qa", 6379, 1, 0, False, None, time.monotonic(), sock=sock, is_redis=True, status="valid_credentials"
    )
    actions._capture_authenticated_redis_identity(state, SimpleNamespace())
    assert state.status == "valid_credentials" and state.server_implementation is None
    assert state.sock is None and sock.closed
    assert sock.max_requested <= 65536 + 128
    assert ("64 KiB" if mode == "oversized" else "EOF") in state.implementation_probe_error
    assert sock.sent == [actions._encode_resp_array(["INFO", "SERVER"])]
