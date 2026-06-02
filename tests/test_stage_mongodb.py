from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import pytest

from redposture_core import stage_mongodb as mongodb
from tests.stage_runtime_helpers import run_module_targets_for_test


class _Cursor(list):
    def limit(self, value: int):
        return _Cursor(self[:value])


class _FakeCollection:
    def __init__(self, docs: list[dict[str, Any]]) -> None:
        self.docs = docs

    def estimated_document_count(self) -> int:
        return len(self.docs)

    def count_documents(self, _query: dict[str, Any]) -> int:
        return len(self.docs)

    def list_indexes(self):
        return [{"name": "_id_"}, {"name": "role_1"}]

    def find(self, query: dict[str, Any], projection: dict[str, Any] | None = None):
        rows = self.docs
        if query:
            key, value = next(iter(query.items()))
            rows = [doc for doc in rows if doc.get(key) == value]
        if projection:
            include = {key for key, value in projection.items() if value}
            rows = [{key: value for key, value in doc.items() if key in include or key == "_id"} for doc in rows]
        return _Cursor(rows)


class _FakeDb:
    def __init__(self, raw: _FakeRaw, name: str) -> None:
        self.raw = raw
        self.name = name

    def command(self, command: str):
        if isinstance(command, dict):
            return {"ok": 1, "database": self.name, "command": command}
        assert command in {"hello", "isMaster"}
        return {"ok": 1, "isWritablePrimary": True, "version": "7.0.5"}

    def list_collection_names(self):
        self.raw._check_auth()
        return list(self.raw.data.get(self.name, {}))

    def __getitem__(self, collection: str):
        self.raw._check_auth()
        docs = self.raw.data.get(self.name, {}).get(collection, [])
        return _FakeCollection(docs)


class _FakeRaw:
    def __init__(self, *, auth_required: bool, username: str | None, password: str | None) -> None:
        self.auth_required = auth_required
        self.username = username
        self.password = password
        self.data = {
            "admin": {},
            "redposture": {
                "demo_accounts": [
                    {"_id": 1, "username": "admin", "role": "admin"},
                    {"_id": 2, "username": "readonly", "role": "viewer"},
                ],
                "audit_events": [{"_id": 1, "event_type": "login_success"}],
            },
        }

    def _check_auth(self) -> None:
        if self.auth_required and (self.username, self.password) != ("root", "root"):
            raise RuntimeError("not authorized code 13")

    def __getitem__(self, name: str):
        return _FakeDb(self, name)

    def server_info(self):
        return {"version": "7.0.5"}

    def list_database_names(self):
        self._check_auth()
        return list(self.data)

    def close(self) -> None:
        pass


def _patch_open(monkeypatch: pytest.MonkeyPatch, *, auth_required: bool = False) -> None:
    def fake_open(host, port, *, username=None, password=None, auth_db="admin", timeout=1.0, mongo_client_cls=None):
        return _FakeRaw(auth_required=auth_required, username=username, password=password)

    monkeypatch.setattr(mongodb, "open_mongodb_client", fake_open)


def _args(**overrides: object) -> argparse.Namespace:
    base = {
        "targets": "127.0.0.1",
        "hosts": None,
        "port": 27017,
        "ports": None,
        "timeout": 1.0,
        "workers": 2,
        "retries": 0,
        "username": None,
        "password": None,
        "auth_db": "admin",
        "defcreds": False,
        "show_databases": False,
        "database": None,
        "show_collections": False,
        "collections": None,
        "show_indexes": False,
        "dump": None,
        "query": None,
        "projection": None,
        "document": None,
        "index": None,
        "nosql_cmd": None,
        "nosql_shell": False,
        "output": None,
        "output_format": "txt",
        "debug": False,
        "log": None,
    }
    base.update(overrides)
    return argparse.Namespace(**base)


def test_audit_mongodb_open_no_auth_with_dump(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_open(monkeypatch, auth_required=False)
    record = mongodb._audit_mongodb_host(
        "127.0.0.1",
        27017,
        1.0,
        0,
        [],
        "admin",
        "redposture",
        True,
        True,
        True,
        ["demo_accounts"],
        {"redposture": ["demo_accounts"]},
        True,
        1,
        None,
        None,
    )
    assert record["status"] == "open_no_auth"
    assert record["auth_required"] is False
    assert record["database_names"] == ["admin", "redposture"]
    assert record["collections"][0]["collection"] == "demo_accounts"
    assert record["indexes"][0]["index"]["name"] == "_id_"
    assert len(record["documents"]) == 1


def test_audit_mongodb_auth_required_and_valid_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_open(monkeypatch, auth_required=True)
    denied = mongodb._audit_mongodb_host(
        "127.0.0.1", 27018, 1.0, 0, [], "admin", None, False, False, False, [], {}, False, None, None, None
    )
    assert denied["status"] == "auth_required"

    valid = mongodb._audit_mongodb_host(
        "127.0.0.1",
        27018,
        1.0,
        0,
        [{"username": "root", "password": "root", "default": True}],
        "admin",
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
    )
    assert valid["status"] == "weak_default_creds"
    assert valid["credential_attempts"][0]["ok"] is True


def test_audit_mongodb_targets_two_pass_debug_and_output(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_open(monkeypatch, auth_required=False)
    lines: list[str] = []
    debug: list[str] = []
    result = run_module_targets_for_test(
        "mongodb",
        hosts=["127.0.0.1"],
        port=27017,
        timeout=1.0,
        retries=0,
        workers=1,
        credential_candidates=[],
        auth_db="admin",
        database="redposture",
        show_databases=True,
        show_collections=True,
        show_indexes=False,
        collection_targets=["demo_accounts"],
        collection_targets_by_database={"redposture": ["demo_accounts"]},
        dump_documents=False,
        dump_limit=None,
        query_filter=None,
        projection=None,
        output_path=None,
        output_format="txt",
        emit_line=lines.append,
        debug_emit=debug.append,
    )
    assert result == (1, 1, 0, 0, 0, 0)
    assert lines[0].startswith("MONGODB") and "MongoDB Service" in lines[0]
    assert any("anonymous access" in line for line in lines)
    assert any("Collections" in line for line in lines)
    assert any("pass=1 detect start" in item for item in debug)
    assert any("stage2_gate=run" in item for item in debug)
    assert any("stage_timing_summary" in item for item in debug)


def test_run_mongodb_stage_validation_and_query(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _patch_open(monkeypatch, auth_required=False)
    out = tmp_path / "mongo.jsonl"
    rc = mongodb.run_mongodb_stage(
        _args(
            output=str(out),
            output_format="json",
            database="redposture",
            collections=["demo_accounts"],
            query='{"role":"admin"}',
            dump=1,
        ),
        logger=object(),  # type: ignore[arg-type]
    )
    assert rc == 0
    payload = out.read_text(encoding="utf-8")
    assert '"service": "mongodb"' in payload
    assert '"query_documents"' in payload

    rc = mongodb.run_mongodb_stage(_args(query='{"role":"admin"}'), logger=object())  # type: ignore[arg-type]
    assert rc == 2


def test_mongodb_small_helpers_and_collection_validation() -> None:
    assert mongodb._clip("abcdef", 3) == "abc"
    assert mongodb._retry_delay(10) == 1.5
    assert mongodb._is_suppressed_fail_record({"status": "fail", "error": "connection timeout"}) is True
    assert mongodb._credential_runs("root", "root", defcreds=True)[:2] == [
        {"username": "root", "password": "root", "default": False},
        {"username": "admin", "password": "admin", "default": True},
    ]
    assert mongodb._parse_json_object("", field_name="--query") == ({}, None)
    assert mongodb._parse_json_object("[1]", field_name="--query")[1] == "--query must be a JSON object"
    assert mongodb._split_csv_values(["a,b", "b", " c "]) == ["a", "b", "c"]

    normalized, grouped, error = mongodb._group_collection_targets(["db.users", "events"], "redposture")
    assert error is None
    assert normalized == ["db.users", "events"]
    assert grouped == {"redposture": ["db.users", "events"]}

    normalized, grouped, error = mongodb._group_collection_targets(["db.users", "events"], None)
    assert error is None
    assert normalized == ["db.users", "events"]
    assert grouped == {"db": ["users"], None: ["events"]}
    assert mongodb._group_collection_targets(["broken."], None)[2] == "invalid --collection target: broken."

    value, safe, error = mongodb._parse_document_selector("1")
    assert error is None and value == 1 and safe == 1
    value, safe, error = mongodb._parse_document_selector("plain-id")
    assert error is None and value == "plain-id" and safe == "plain-id"
    assert mongodb._parse_document_selector("{}")[2] == "--document must be a scalar _id value"


def test_run_mongodb_stage_document_index_and_nosql_command(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _patch_open(monkeypatch, auth_required=False)
    out = tmp_path / "mongo.txt"
    rc = mongodb.run_mongodb_stage(
        _args(
            output=str(out),
            database="redposture",
            collections=["demo_accounts"],
            document="1",
            projection='{"username":1}',
            index="role_1",
            nosql_cmd='{"dbStats":1}',
        ),
        logger=object(),  # type: ignore[arg-type]
    )
    assert rc == 0
    payload = out.read_text(encoding="utf-8")
    assert "Query" in payload
    assert '"username":"admin"' in payload
    assert "index=role_1" in payload
    assert "index=_id_" not in payload
    assert 'Mongo Command database=redposture command={"dbStats":1}' in payload
    assert '"database":"redposture"' in payload


def test_run_mongodb_stage_document_and_nosql_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_open(monkeypatch, auth_required=False)
    assert mongodb.run_mongodb_stage(_args(document="1"), logger=object()) == 2  # type: ignore[arg-type]
    assert (
        mongodb.run_mongodb_stage(
            _args(collections=["demo_accounts"], document="1", query='{"role":"admin"}'), logger=object()
        )
        == 2
    )
    assert mongodb.run_mongodb_stage(_args(nosql_cmd="[1]"), logger=object()) == 2  # type: ignore[arg-type]
    assert mongodb.run_mongodb_stage(_args(nosql_cmd='{"ping":1}', nosql_shell=True), logger=object()) == 2  # type: ignore[arg-type]


def test_mongodb_nosql_shell_session() -> None:
    class ShellClient:
        def __init__(self) -> None:
            self.calls: list[tuple[str, dict[str, Any]]] = []

        def run_command(self, database: str, command: dict[str, Any]) -> dict[str, Any]:
            self.calls.append((database, command))
            return {"ok": 1, "db": database, "command": command}

    client = ShellClient()
    inputs = iter(["use redposture", '{"dbStats":1}', "bad-json", "quit"])
    lines: list[str] = []
    rc = mongodb._run_mongodb_nosql_shell_session(
        client,  # type: ignore[arg-type]
        initial_database="admin",
        input_func=lambda _prompt: next(inputs),
        emit_line=lines.append,
    )
    assert rc == 0
    assert client.calls == [("redposture", {"dbStats": 1})]
    assert "[*] switched to db redposture" in lines
    assert any('"db":"redposture"' in line for line in lines)
    assert any("must be valid JSON object" in line for line in lines)


def test_audit_mongodb_invalid_credentials_anonymous_and_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    def anonymous_with_invalid_creds(host, port, *, username=None, password=None, auth_db="admin", timeout=1.0):
        if username is None:
            return _FakeRaw(auth_required=False, username=username, password=password)
        return _FakeRaw(auth_required=True, username=username, password=password)

    monkeypatch.setattr(mongodb, "open_mongodb_client", anonymous_with_invalid_creds)
    invalid = mongodb._audit_mongodb_host(
        "127.0.0.1",
        27017,
        1.0,
        0,
        [{"username": "bad", "password": "bad", "default": False}],
        "admin",
        "redposture",
        True,
        True,
        True,
        ["demo_accounts"],
        {"redposture": ["demo_accounts"]},
        True,
        None,
        None,
        None,
    )
    assert invalid["status"] == "invalid_credentials_anonymous"
    assert invalid["auth_required"] is False
    assert invalid["credential_attempts"][0]["ok"] is False
    assert invalid["database_count"] == 2
    assert invalid["database_names"] is None
    assert invalid["collections"] == []
    status_line = mongodb._format_record(invalid, "txt")
    assert "invalid credentials bad:bad; anonymous access still available (DBs:2) (collections:0)" in status_line
    assert "read:" not in status_line
    assert "list_collections:" not in status_line

    def broken_open(*args: object, **kwargs: object) -> object:
        raise RuntimeError("connection refused")

    monkeypatch.setattr(mongodb, "open_mongodb_client", broken_open)
    failed = mongodb._audit_mongodb_host(
        "127.0.0.1", 27017, 1.0, 1, [], "admin", None, False, False, False, [], {}, False, None, None, None
    )
    assert failed["status"] == "fail"
    assert failed["is_mongodb"] is False
    assert "connection refused" in failed["error"]


def test_audit_mongodb_invalid_credentials_do_not_run_anonymous_deep(monkeypatch: pytest.MonkeyPatch) -> None:
    def anonymous_with_invalid_creds(host, port, *, username=None, password=None, auth_db="admin", timeout=1.0):
        if username is None:
            return _FakeRaw(auth_required=False, username=username, password=password)
        return _FakeRaw(auth_required=True, username=username, password=password)

    monkeypatch.setattr(mongodb, "open_mongodb_client", anonymous_with_invalid_creds)
    lines: list[str] = []
    result = run_module_targets_for_test(
        "mongodb",
        hosts=["127.0.0.1"],
        port=27017,
        timeout=1.0,
        retries=0,
        workers=1,
        credential_candidates=[{"username": "bad", "password": "bad", "default": False}],
        auth_db="admin",
        database="redposture",
        show_databases=True,
        show_collections=True,
        show_indexes=True,
        collection_targets=["demo_accounts"],
        collection_targets_by_database={"redposture": ["demo_accounts"]},
        dump_documents=True,
        dump_limit=5,
        query_filter=None,
        projection=None,
        output_path=None,
        output_format="txt",
        emit_line=lines.append,
    )
    assert result == (1, 0, 0, 0, 0, 0)
    assert any("invalid credentials bad:bad; anonymous access still available" in line for line in lines)
    assert not any("[*] Databases" in line for line in lines)
    assert not any("[*] Collections" in line for line in lines)
    assert not any("[*] Dump Documents" in line for line in lines)


def test_collect_mongodb_data_handles_collection_and_query_errors() -> None:
    class BrokenClient:
        def list_collection_names(self, database: str):
            raise RuntimeError("not authorized")

    data = mongodb._collect_mongodb_data(
        BrokenClient(),  # type: ignore[arg-type]
        database_names=["redposture"],
        selected_database=None,
        collection_targets=[],
        collection_targets_by_database={},
        show_databases=True,
        show_collections=True,
        show_indexes=True,
        dump_documents=True,
        dump_limit=None,
        query_filter=None,
        projection=None,
    )
    assert data["database_names"] == ["redposture"]
    assert data["collections"] == []
    assert data["capabilities"]["can_list_collections"] is False
    assert data["query_error"] == "authentication failed"


def test_mongodb_formatters_cover_txt_and_json_branches() -> None:
    record = {
        "timestamp": "now",
        "host": "127.0.0.1",
        "port": 27017,
        "is_mongodb": True,
        "status": "valid_credentials",
        "auth_required": True,
        "effective_username": "root",
        "provided_username": "root",
        "provided_password": "",
        "capabilities": {"can_read_documents": False, "can_list_collections": True},
        "database_count": 1,
        "server_version": "7.0",
        "database_names": ["redposture"],
        "collections": [{"database": "redposture", "collection": "users", "documents": 2}],
        "indexes": [{"database": "redposture", "collection": "users", "index": {"name": "_id_"}}],
        "documents": [{"database": "redposture", "collection": "users", "document": {"_id": 1}}],
        "query_documents": [{"database": "redposture", "collection": "users", "document": {"_id": 2}}],
        "query_error": None,
        "query_filter": {"role": "admin"},
    }
    assert "MongoDB Service" in mongodb._format_detect_record(record, "txt")
    assert '"type": "detect"' in mongodb._format_detect_record(record, "json")
    assert "root:<empty>" in mongodb._format_record(record, "txt")
    assert '"status": "valid_credentials"' in mongodb._format_record(record, "json")
    assert "Databases" in mongodb._format_databases_detail_records(record, "txt")[0]
    assert '"type": "databases"' in mongodb._format_databases_detail_records(record, "json")[0]
    assert "Collections" in mongodb._format_collections_detail_records(record, "txt")[0]
    assert '"type": "collections"' in mongodb._format_collections_detail_records(record, "json")[0]
    assert "Indexes" in mongodb._format_indexes_detail_records(record, "txt")[0]
    assert '"type": "indexes"' in mongodb._format_indexes_detail_records(record, "json")[0]
    assert "Dump Documents" in mongodb._format_documents_detail_records(record, "txt")[0]
    assert '"type": "documents_dump"' in mongodb._format_documents_detail_records(record, "json")[0]
    assert "Query" in mongodb._format_query_detail_records(record, "txt")[0]
    assert '"type": "query"' in mongodb._format_query_detail_records(record, "json")[0]


def test_run_mongodb_stage_credential_file_prefilter(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _patch_open(monkeypatch, auth_required=True)
    creds = tmp_path / "creds.txt"
    creds.write_text("bad:bad\nroot:root\n", encoding="utf-8")
    calls: list[tuple[list[str], int]] = []

    def fake_prefilter(hosts: list[str], port: int, **kwargs: object) -> list[str]:
        calls.append((list(hosts), port))
        return ["127.0.0.1"]

    monkeypatch.setattr(mongodb, "filter_open_tcp_hosts_for_credential_file", fake_prefilter)
    out = tmp_path / "mongo.txt"
    rc = mongodb.run_mongodb_stage(
        _args(targets="127.0.0.1,127.0.0.2", username=str(creds), ports="27017,27018", output=str(out)),
        logger=object(),  # type: ignore[arg-type]
    )
    assert rc == 0
    assert calls == [(["127.0.0.1", "127.0.0.2"], 27017), (["127.0.0.1", "127.0.0.2"], 27018)]
    assert "root:root" in out.read_text(encoding="utf-8")
