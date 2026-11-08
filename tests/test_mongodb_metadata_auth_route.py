"""Mass credentials preserve full per-pair proof while avoiding SDK monitors."""

from __future__ import annotations

from typing import Any

import pytest
from pymongo.errors import OperationFailure

from redposture_core.modules.mongodb import actions

HELLO = {"ok": 1, "minWireVersion": 0, "maxWireVersion": 21, "isWritablePrimary": True}


def run(**options):
    args: dict[str, Any] = dict(
        host="127.0.0.1",
        port=27017,
        timeout=0.5,
        retries=0,
        credential_candidates=[
            {"username": "reader", "password": "correct", "default": True},
            {"username": "other", "password": "wrong", "default": True},
        ],
        auth_db="admin",
        database=None,
        show_databases=False,
        show_collections=False,
        show_indexes=False,
        collection_targets=[],
        collection_targets_by_database={},
        dump_documents=False,
        dump_limit=None,
        query_filter=None,
        projection=None,
        anonymous_bootstrap={
            "status": "auth_required",
            "auth_required": True,
            "hello": HELLO,
            "server_version": "7.0.43",
        },
    )
    args.update(options)
    return actions._audit_mongodb_host(**args)


def test_metadata_auth_uses_one_verified_native_client_per_pair_and_keeps_every_verdict(monkeypatch):
    sdk_calls = []
    native_calls = []
    closed = []

    def forbidden_sdk(*args, **kwargs):
        sdk_calls.append((args, kwargs))
        raise OperationFailure("Authentication failed", 18)

    class Client:
        client: Any

        def __init__(self, user):
            self.client = self
            self.user = user

        def hello(self):
            return dict(HELLO)

        def run_command(self, db, command):
            return {"authInfo": {"authenticatedUsers": [{"user": self.user, "db": "admin"}]}}

        def server_info(self):
            return {"version": "7.0.43"}

        def list_database_names(self):
            return ["admin", "analytics"]

        def list_collection_names(self, db):
            return ["system.users"] if db == "admin" else ["events", "archive"]

        def close(self):
            closed.append(self.user)

    def native(*args, **kwargs):
        user = kwargs["username"]
        native_calls.append(user)
        if user == "other":
            raise OperationFailure("Authentication failed", 18)
        return Client(user)

    monkeypatch.setattr(actions, "open_mongodb_client", forbidden_sdk)
    monkeypatch.setattr(actions, "_open_metadata_client", native, raising=False)
    result = run()
    assert sdk_calls == []
    assert native_calls == ["reader", "other"] and closed == ["reader"]
    assert result["is_mongodb"] and result["status"] == "weak_default_creds"
    assert [(r["username"], r["credential_state"]) for r in result["credential_attempts"]] == [
        ("reader", "valid"),
        ("other", "invalid"),
    ]
    assert result["credential_attempts"][0]["credential_capabilities"]["database_count"] == 2
    assert result["credential_attempts"][0]["credential_capabilities"]["collection_count"] == 3


def test_metadata_factory_replays_only_an_explicit_pre_auth_fallback(monkeypatch):
    from redposture_core.clients import mongodb_metadata as wire

    sdk = []
    native = []
    raw = object()
    monkeypatch.setattr(actions, "open_mongodb_client", lambda *a, **k: sdk.append(k) or raw)

    def unsupported(*a, **k):
        native.append(k)
        raise wire.MongoMetadataFallback("old wire")

    monkeypatch.setattr(actions, "_OPEN_MONGODB_CLIENT_ORIGINAL", actions.open_mongodb_client)
    monkeypatch.setattr(wire, "MongoMetadataClient", unsupported)
    result = actions._open_metadata_client(
        "127.0.0.1", 27017, 0.5, username="reader", password="correct", auth_db="admin"
    )
    assert result.client is raw and len(sdk) == len(native) == 1


def test_metadata_factory_never_replays_auth_or_a_network_failure(monkeypatch):

    from redposture_core.clients import mongodb_metadata as wire
    from redposture_core.clients.mongodb import MongoClientError

    sdk = []
    monkeypatch.setattr(actions, "open_mongodb_client", lambda *a, **k: sdk.append(k))
    monkeypatch.setattr(actions, "_OPEN_MONGODB_CLIENT_ORIGINAL", actions.open_mongodb_client)
    for error in [
        OperationFailure("Authentication failed", 18),
        MongoClientError("invalid server signature"),
        TimeoutError("timed out"),
    ]:

        def fail(*a, _error=error, **k):
            raise _error

        monkeypatch.setattr(wire, "MongoMetadataClient", fail)
        with pytest.raises(type(error)):
            actions._open_metadata_client(
                "127.0.0.1", 27017, 0.5, username="reader", password="correct", auth_db="admin"
            )
    assert not sdk


def test_tls_options_stay_on_sdk_without_native_auth(monkeypatch):
    from redposture_core.clients import mongodb_metadata as wire

    def forbidden(*a, **k):
        raise AssertionError("TLS/OCSP route must stay on SDK")

    monkeypatch.setattr(wire, "MongoMetadataClient", forbidden)
    for options in [dict(tls=True), dict(tls_ca="ca.pem"), dict(tls_cert_key="client.pem"), dict(tls_insecure=True)]:
        calls = []
        raw = object()

        def sdk(*a, _calls=calls, _raw=raw, **k):
            _calls.append(k)
            return _raw

        monkeypatch.setattr(actions, "open_mongodb_client", sdk)
        monkeypatch.setattr(actions, "_OPEN_MONGODB_CLIENT_ORIGINAL", sdk)
        result = actions._open_metadata_client(
            "127.0.0.1", 27017, 0.5, username="reader", password="correct", auth_db="admin", **options
        )
        assert result.client is raw and len(calls) == 1


def test_embedded_client_factory_is_preserved(monkeypatch):
    calls = []
    expected = object()
    monkeypatch.setattr(actions, "_open_client", lambda *a, **k: calls.append(k) or expected)
    assert (
        actions._open_metadata_client("127.0.0.1", 27017, 0.5, username="reader", password="correct", auth_db="admin")
        is expected
    )
    assert len(calls) == 1


@pytest.mark.parametrize(
    "options",
    [
        {"database": "analytics"},
        {"show_databases": True},
        {"show_collections": True},
        {"show_indexes": True},
        {"collection_targets": ["events"]},
        {"collection_targets_by_database": {"analytics": ["events"]}},
        {"dump_documents": True},
        {"query_filter": {}},
        {"projection": {}},
        {"document_selector": {}},
        {"index_filter": "events"},
        {"nosql_command": {"ping": 1}},
        {"discover": True},
    ],
)
def test_every_selector_data_and_discover_route_keeps_the_sdk_before_auth(monkeypatch, options):
    sdk = []

    class Client:
        def __init__(self, user):
            self.client = self
            self.user = user

        def hello(self):
            return dict(HELLO)

        def run_command(self, db, command):
            if "connectionStatus" in command:
                return {"authInfo": {"authenticatedUsers": [{"user": self.user, "db": "admin"}]}}
            return {"ok": 1}

        def server_info(self):
            return {"version": "7.0.43"}

        def list_database_names(self):
            if not self.user:
                raise OperationFailure("not authorized", 13)
            return ["admin", "analytics"]

        def list_collection_names(self, db):
            return []

        def list_indexes(self, *a):
            return []

        def count_documents(self, *a):
            return 0

        def find_documents(self, *a, **k):
            return []

        def close(self):
            pass

    def old(*a, **k):
        sdk.append(k["username"])
        if k["username"] == "other":
            raise OperationFailure("Authentication failed", 18)
        return Client(k["username"])

    def unexpected(*a, **k):
        raise AssertionError("data route must not use native metadata auth")

    monkeypatch.setattr(actions, "_open_client", old)
    monkeypatch.setattr(actions, "_open_metadata_client", unexpected)
    record = run(**options)
    assert "reader" in sdk and "other" in sdk and record["is_mongodb"] is True


def test_dns_route_preserves_sdk_resolution_without_native_auth(monkeypatch):
    from redposture_core.clients import mongodb_metadata as wire

    calls = []
    raw = object()

    def sdk(*args, **kwargs):
        calls.append((args, kwargs))
        return raw

    def native(*args, **kwargs):
        raise AssertionError("DNS must stay on existing SDK selection")

    monkeypatch.setattr(actions, "open_mongodb_client", sdk)
    monkeypatch.setattr(actions, "_OPEN_MONGODB_CLIENT_ORIGINAL", sdk)
    monkeypatch.setattr(wire, "MongoMetadataClient", native)
    result = actions._open_metadata_client(
        "cluster.qa.invalid", 27017, 0.5, username="reader", password="pencil", auth_db="admin"
    )
    assert result.client is raw and len(calls) == 1 and calls[0][0] == ("cluster.qa.invalid", 27017)
