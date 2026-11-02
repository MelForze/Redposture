"""Selected MongoClient survives verification and its own data phase only."""

from __future__ import annotations

import pytest

from redposture_core.clients.session_handoff import SessionHandoff
from redposture_core.modules.mongodb import actions
from tests.test_async_retained_parity import normalize
from tests.test_stage_mongodb import _FakeRaw


def audit(cache, **options):
    return actions._audit_mongodb_host(
        "127.0.0.1",
        27017,
        1,
        0,
        [{"username": "root", "password": "root", "default": False}],
        options.pop("auth_db", "admin"),
        None,
        True,
        False,
        False,
        [],
        {},
        False,
        None,
        None,
        None,
        session_cache=cache,
        **options,
    )


@pytest.mark.parametrize("optimized,expected", [(False, 6), (True, 3)])
def test_identity_is_rechecked_but_selected_pool_is_not_recreated(optimized, expected, monkeypatch):
    opened, checks = [], []

    class Raw(_FakeRaw):
        def __init__(self, username, password):
            super().__init__(auth_required=True, username=username, password=password)
            self.closed = 0

        def close(self):
            self.closed += 1

        def list_database_names(self):
            checks.append(self.username)
            return super().list_database_names()

    def create(*args, username=None, password=None, **kwargs):
        raw = Raw(username, password)
        opened.append(raw)
        return raw

    monkeypatch.setattr(actions, "open_mongodb_client", create)
    original = actions._try_credentials
    if not optimized:
        # Retain the former embedding contract: selected credentials only,
        # no ownership transfer of the verified MongoClient.
        monkeypatch.setattr(actions, "_try_credentials", lambda *a, **kw: original(*a, **kw))
    cache = SessionHandoff()
    try:
        first = audit(cache)
        first_checks = checks[:]
        checks.clear()
        second = audit(cache)
        assert normalize(first) == normalize(second)
        assert checks == first_checks
        assert first["provided_credentials_ok"] is True
        assert first["credential_capabilities"]["database_count"] == 2
        assert len(opened) == expected
        if optimized:
            assert sum(raw.closed == 0 for raw in opened) == 1
    finally:
        cache.close()
    assert all(raw.closed == 1 for raw in opened)


@pytest.mark.parametrize("change", ["password", "auth_db", "tls", "timeout"])
def test_cached_client_requires_the_exact_connection_identity(change, monkeypatch):
    created = []

    def create(*args, username=None, password=None, **kwargs):
        created.append((args, username, password, kwargs))
        return _FakeRaw(auth_required=True, username=username, password=password)

    monkeypatch.setattr(actions, "open_mongodb_client", create)
    cache = SessionHandoff()
    try:
        audit(cache)
        kwargs = dict(
            host="127.0.0.1",
            port=27017,
            timeout=1,
            auth_db="admin",
            credential_candidates=[{"username": "root", "password": "root"}],
            selected_clients=[],
            session_cache=cache,
        )
        if change == "password":
            kwargs["credential_candidates"] = [{"username": "root", "password": "different"}]
        else:
            kwargs[change] = True if change == "tls" else "different" if change == "auth_db" else 2
        before = len(created)
        actions._try_credentials(**kwargs)
        assert len(created) == before + 1
        for client, lease in kwargs["selected_clients"]:
            if lease is not None:
                cache.finish(lease)
            else:
                client.close()
    finally:
        cache.close()
