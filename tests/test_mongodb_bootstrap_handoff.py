"""Only current complete protected-backend proof may skip anonymous bootstrap."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from pymongo.errors import OperationFailure

from redposture_core.modules.mongodb import actions
from tests.test_async_retained_parity import normalize
from tests.test_stage_mongodb import _FakeRaw


def hello():
    return {"ok": 1, "isWritablePrimary": True, "minWireVersion": 0, "maxWireVersion": 21, "version": "7.0.5"}


def proof(**changes):
    return {
        "is_mongodb": True,
        "status": "auth_required",
        "auth_required": True,
        "hello": hello(),
        "server_version": "7.0.5",
        "database": None,
        "error": "authentication required",
        **changes,
    }


def key(**changes):
    fields = dict(
        host="127.0.0.1",
        port=27017,
        timeout=1,
        username=None,
        password=None,
        auth_db="admin",
        tls=False,
        tls_ca=None,
        tls_cert_key=None,
        tls_insecure=False,
    )
    fields.update(changes)
    return actions._mongo_session_key(**fields)


@pytest.mark.parametrize(
    "field,value",
    [
        ("host", "127.0.0.2"),
        ("port", 27018),
        ("timeout", 2),
        ("auth_db", "other"),
        ("tls", True),
        ("tls_ca", "/other-ca"),
        ("tls_cert_key", "/other-cert"),
        ("tls_insecure", True),
    ],
)
def test_bootstrap_is_not_reused_for_a_changed_connection_and_mismatch_consumes_it(field, value):
    state = actions.MongoLifecycleState(SimpleNamespace())
    try:
        state.remember_bootstrap(key(), proof())
        assert state.take_bootstrap(key(**{field: value})) is None
        assert state.take_bootstrap(key()) is None
    finally:
        state.close()


@pytest.mark.parametrize(
    "change",
    [
        {"is_mongodb": False},
        {"status": "open_no_auth"},
        {"auth_required": None},
        {"database": "selected"},
        {"error": "connection timeout"},
        {"hello": {"ok": 1}},
        {"status": "legacy_wire_unsupported"},
    ],
)
def test_incomplete_foreign_or_anonymous_refresh_cannot_leave_stale_proof(change):
    state = actions.MongoLifecycleState(SimpleNamespace())
    try:
        state.remember_bootstrap(key(), proof())
        state.remember_bootstrap(key(), proof(**change))
        assert state.take_bootstrap(key()) is None
    finally:
        state.close()


def test_bootstrap_is_one_shot_and_close_prevents_late_publication():
    state = actions.MongoLifecycleState(SimpleNamespace())
    state.remember_bootstrap(key(), proof())
    cached = state.take_bootstrap(key())
    assert cached and cached["server_version"] == "7.0.5"
    assert state.take_bootstrap(key()) is None
    state.close()
    state.remember_bootstrap(key(), proof())
    assert state.take_bootstrap(key()) is None


@pytest.mark.parametrize(
    "tls,ca,cert,insecure", [(False, None, None, False), (True, "/qa-ca", "/qa-cert", False), (True, None, None, True)]
)
def test_native_finish_publishes_the_same_transport_key_as_sync_consumer(tls, ca, cert, insecure):
    import time

    from redposture_core.audit_config import AuditConfig
    from redposture_core.modules.mongodb.async_detect import _finish

    args = SimpleNamespace(timeout=1, retries=0, debug=False, auth_db="admin", tls=tls, tls_ca=ca, tls_cert_key=cert)
    state = actions.MongoLifecycleState(SimpleNamespace())
    ctx = SimpleNamespace(args=args, host="127.0.0.1", port=27017, debug_emit=None, lifecycle_state=state)
    try:
        _finish(ctx, proof(), AuditConfig.from_namespace(args), time.monotonic())
        assert state.take_bootstrap(key(tls=tls, tls_ca=ca, tls_cert_key=cert, tls_insecure=insecure))
    finally:
        state.close()


def audit(bootstrap=None, *, database=None, retries=0):
    return actions._audit_mongodb_host(
        "127.0.0.1",
        27017,
        1,
        retries,
        [{"username": "root", "password": "root", "default": False}],
        "admin",
        database,
        True,
        True,
        False,
        [],
        {},
        False,
        None,
        None,
        None,
        anonymous_bootstrap=bootstrap,
    )


@pytest.mark.parametrize("limited", [False, True])
def test_correct_identity_and_full_data_stay_identical_with_protected_bootstrap(monkeypatch, limited):
    opened = []

    class Raw(_FakeRaw):
        def __init__(self, username, password):
            super().__init__(auth_required=True, username=username, password=password)
            self.closed = 0

        def close(self):
            self.closed += 1

        def list_database_names(self):
            if limited:
                raise OperationFailure("not authorized", code=13)
            return super().list_database_names()

    def create(*args, username=None, password=None, **kwargs):
        raw = Raw(username, password)
        opened.append(raw)
        return raw

    monkeypatch.setattr(actions, "open_mongodb_client", create)
    before = audit()
    baseline = opened[:]
    opened.clear()
    after = audit(proof())
    assert normalize(after) == normalize(before)
    assert after["provided_credentials_ok"] is True
    assert [raw.username for raw in baseline] == [None, "root"]
    assert [raw.username for raw in opened] == ["root"]
    assert all(raw.closed == 1 for raw in baseline + opened)


def test_explicit_database_keeps_full_bootstrap(monkeypatch):
    users = []

    def create(*args, username=None, password=None, **kwargs):
        users.append(username)
        return _FakeRaw(auth_required=True, username=username, password=password)

    monkeypatch.setattr(actions, "open_mongodb_client", create)
    result = audit(proof(), database="redposture")
    assert result["provided_credentials_ok"] is True and users[0] is None


def test_retry_does_not_reuse_old_bootstrap_or_skip_credentials(monkeypatch):
    users, attempts = [], []
    original = actions._try_credentials

    def create(*args, username=None, password=None, **kwargs):
        users.append(username)
        return _FakeRaw(auth_required=True, username=username, password=password)

    def try_credentials(*args, **kwargs):
        attempts.append(1)
        if len(attempts) == 1:
            raise ConnectionError("connection reset")
        return original(*args, **kwargs)

    monkeypatch.setattr(actions, "open_mongodb_client", create)
    monkeypatch.setattr(actions, "_try_credentials", try_credentials)
    monkeypatch.setattr(actions.time, "sleep", lambda _delay: None)
    result = audit(proof(), retries=1)
    assert result["provided_credentials_ok"] is True
    assert len(attempts) == 2 and users == [None, "root", "root"]
