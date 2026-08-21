from __future__ import annotations

import pytest

from redposture_core.clients.mongodb import (
    MongoAuditClient,
    MongoDependencyError,
    MongoNotMongoError,
    _load_bson_json_util,
    _load_pymongo,
    build_mongodb_uri,
    close_quietly,
    is_auth_error,
    json_safe,
    non_system_databases,
    normalize_mongodb_error,
    open_mongodb_client,
)


class _Cursor(list):
    def limit(self, value: int):
        return _Cursor(self[:value])


class _Collection:
    def __init__(self) -> None:
        self.docs = [{"_id": 1, "role": "admin"}, {"_id": 2, "role": "viewer"}]

    def estimated_document_count(self) -> int:
        return len(self.docs)

    def count_documents(self, query):
        return len(self.docs)

    def list_indexes(self):
        return [{"name": "_id_"}, {"name": "role_1"}]

    def find(self, query, projection=None):
        if query:
            key, value = next(iter(query.items()))
            return _Cursor([doc for doc in self.docs if doc.get(key) == value])
        return _Cursor(list(self.docs))


class _Db:
    def __init__(self, name: str) -> None:
        self.name = name

    def command(self, command):
        assert self.name == "admin"
        if isinstance(command, dict):
            return {"ok": 1, "stats": command}
        assert command in {"hello", "isMaster"}
        return {"ok": 1, "isWritablePrimary": True}

    def list_collection_names(self):
        return ["demo_accounts"]

    def __getitem__(self, name: str):
        assert name == "demo_accounts"
        return _Collection()


class _RawClient:
    def __getitem__(self, name: str):
        return _Db(name)

    def server_info(self):
        return {"version": "7.0.0"}

    def list_database_names(self):
        return ["admin", "local", "redposture"]

    def close(self):
        self.closed = True


def test_build_mongodb_uri_escapes_auth_and_auth_source() -> None:
    uri = build_mongodb_uri("127.0.0.1", 27017, username="root@x", password="p:a/s", auth_db="admin")
    assert uri == "mongodb://root%40x:p%3Aa%2Fs@127.0.0.1:27017/?authSource=admin&directConnection=true"

    empty_password_uri = build_mongodb_uri("mongo.local", 27017, username="root", password="", auth_db="")
    assert empty_password_uri == "mongodb://root:@mongo.local:27017/?authSource=admin&directConnection=true"

    password_only_uri = build_mongodb_uri("mongo.local", 27017, username=None, password="", auth_db="auth/db")
    assert password_only_uri == "mongodb://:@mongo.local:27017/?authSource=auth%2Fdb&directConnection=true"
    assert build_mongodb_uri("2001:db8::1", 27017) == (
        "mongodb://[2001:db8::1]:27017/?authSource=admin&directConnection=true"
    )
    assert build_mongodb_uri("[::1]", 27017) == "mongodb://[::1]:27017/?authSource=admin&directConnection=true"


def test_mongo_audit_client_wraps_database_collection_helpers() -> None:
    client = MongoAuditClient(_RawClient())
    assert client.hello()["ok"] == 1
    assert client.server_info()["version"] == "7.0.0"
    assert client.list_database_names() == ["admin", "local", "redposture"]
    assert client.list_collection_names("redposture") == ["demo_accounts"]
    assert client.run_command("admin", {"dbStats": 1}) == {"ok": 1, "stats": {"dbStats": 1}}
    assert client.count_documents("redposture", "demo_accounts") == 2
    assert [idx["name"] for idx in client.list_indexes("redposture", "demo_accounts")] == ["_id_", "role_1"]
    assert client.find_documents("redposture", "demo_accounts", query={"role": "admin"}, limit=1) == [
        {"_id": 1, "role": "admin"}
    ]


def test_json_safe_and_database_filter_helpers() -> None:
    class Weird:
        def __str__(self) -> str:
            return "weird-value"

    assert json_safe({"x": Weird()}) == {"x": "weird-value"}
    assert non_system_databases(["admin", "redposture", "local", "billing", "redposture"]) == [
        "redposture",
        "billing",
    ]
    assert json_safe((Weird(), {"nested": Weird()})) == ["weird-value", {"nested": "weird-value"}]
    assert non_system_databases(["", None, "config", "local", "admin"]) == []


def test_mongo_audit_client_hello_normalizes_non_json_values() -> None:
    class ProcessId:
        def __str__(self) -> str:
            return "object-id-like"

    class Raw:
        def __getitem__(self, name: str):
            class Db:
                def command(self, command: str):
                    return {"ok": 1, "isWritablePrimary": True, "topologyVersion": {"processId": ProcessId()}}

            return Db()

    hello = MongoAuditClient(Raw()).hello()
    assert hello["topologyVersion"]["processId"] == "object-id-like"


def test_normalize_mongodb_error_and_auth_detection() -> None:
    assert normalize_mongodb_error(RuntimeError("")) == "mongodb operation failed"
    assert normalize_mongodb_error(RuntimeError("ServerSelectionTimeoutError: timed out")) == "connection timeout"
    assert normalize_mongodb_error(RuntimeError("[Errno 111] Connection refused")) == (
        "connection refused (service is not listening on target port)"
    )
    assert normalize_mongodb_error(RuntimeError("[Errno -2] Name or service not known")) == "dns lookup failed"
    assert normalize_mongodb_error(RuntimeError("[Errno 60] Operation timed out")) == "connection timeout"
    assert normalize_mongodb_error(RuntimeError("[Errno 13] Permission denied")) == "Permission denied"
    assert normalize_mongodb_error(RuntimeError("Authentication failed.")) == "authentication failed"
    assert normalize_mongodb_error(RuntimeError("not authorized on admin")) == "authentication failed"
    assert normalize_mongodb_error(RuntimeError("temporary failure in name resolution")) == "dns lookup failed"
    assert is_auth_error("Command requires authentication code 13") is True
    assert is_auth_error("Auth error code 18") is True
    assert is_auth_error("plain network error") is False


def test_open_mongodb_client_uses_fake_client_without_pymongo_import() -> None:
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    class FakeMongoClient:
        def __init__(self, *args: object, **kwargs: object) -> None:
            calls.append((args, kwargs))

    client = open_mongodb_client(
        "127.0.0.1",
        27017,
        username="root",
        password="root",
        auth_db="admin",
        timeout=2.5,
        mongo_client_cls=FakeMongoClient,
    )
    assert isinstance(client, FakeMongoClient)
    args, kwargs = calls[0]
    assert args[0] == "mongodb://root:root@127.0.0.1:27017/?authSource=admin&directConnection=true"
    assert kwargs["serverSelectionTimeoutMS"] == 2500
    assert kwargs["connectTimeoutMS"] == 2500
    assert kwargs["socketTimeoutMS"] == 2500
    assert kwargs["appname"] == "redposture"


def test_open_mongodb_client_passes_tls_and_mtls_options() -> None:
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    class FakeMongoClient:
        def __init__(self, *args: object, **kwargs: object) -> None:
            calls.append((args, kwargs))

    open_mongodb_client(
        "mongo.local",
        27017,
        tls=True,
        tls_ca_file="/tmp/ca.pem",
        tls_certificate_key_file="/tmp/client.pem",
        tls_insecure=True,
        mongo_client_cls=FakeMongoClient,
    )
    _args, kwargs = calls[0]
    assert kwargs["tls"] is True
    assert kwargs["tlsCAFile"] == "/tmp/ca.pem"
    assert kwargs["tlsCertificateKeyFile"] == "/tmp/client.pem"
    assert kwargs["tlsAllowInvalidCertificates"] is True
    assert kwargs["tlsAllowInvalidHostnames"] is True


def test_mongodb_optional_dependency_loaders(monkeypatch: pytest.MonkeyPatch) -> None:
    real_import = __import__

    def fake_import(name: str, *args: object, **kwargs: object):
        if name in {"pymongo", "bson"} or name.startswith("bson."):
            raise ModuleNotFoundError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", fake_import)
    with pytest.raises(MongoDependencyError, match="pymongo is required"):
        _load_pymongo()
    assert _load_bson_json_util() is None


def test_mongo_audit_client_fallbacks_and_close_quietly() -> None:
    class BadCountCollection(_Collection):
        def estimated_document_count(self) -> int:
            raise RuntimeError("estimated failed")

    class WorseCountCollection(_Collection):
        def estimated_document_count(self) -> int:
            raise RuntimeError("estimated failed")

        def count_documents(self, query):
            raise RuntimeError("count failed")

    class FallbackDb(_Db):
        def __init__(self, collection_cls):
            self.collection_cls = collection_cls

        def command(self, command):
            if command == "hello":
                raise RuntimeError("no hello")
            return {"ok": 1, "ismaster": True}

        def __getitem__(self, name: str):
            return self.collection_cls()

    class FallbackRaw:
        def __init__(self, collection_cls) -> None:
            self.collection_cls = collection_cls
            self.closed = False

        def __getitem__(self, name: str):
            return FallbackDb(self.collection_cls)

        def close(self):
            self.closed = True

    raw = FallbackRaw(BadCountCollection)
    client = MongoAuditClient(raw)
    assert client.hello()["ismaster"] is True
    assert client.count_documents("redposture", "demo_accounts") == 2
    client.close()
    assert raw.closed is True

    with pytest.raises(RuntimeError, match="count failed"):
        MongoAuditClient(FallbackRaw(WorseCountCollection)).count_documents("redposture", "demo_accounts")

    class BrokenClose:
        def close(self):
            raise RuntimeError("close failed")

    close_quietly(BrokenClose())


def test_mongo_audit_client_rejects_non_mongo_hello() -> None:
    class Raw:
        def __getitem__(self, name: str):
            class Db:
                def command(self, command: str):
                    return {"ok": 0}

            return Db()

    with pytest.raises(MongoNotMongoError):
        MongoAuditClient(Raw()).hello()


def test_mongo_audit_client_rejects_non_document_hello_and_wraps_non_dict_results() -> None:
    class Raw:
        def __getitem__(self, name: str):
            class Db:
                def command(self, command):
                    if command == "hello":
                        return "not-a-document"
                    return ["ok"]

            return Db()

        def server_info(self):
            return "not-a-dict"

    client = MongoAuditClient(Raw())
    with pytest.raises(MongoNotMongoError, match="hello did not return"):
        client.hello()
    assert client.server_info() == {}
    assert client.run_command("admin", {"ping": 1}) == {"result": ["ok"]}


def test_mongo_audit_client_close_quietly_without_close_method() -> None:
    close_quietly(object())
