"""Regression coverage for native data correctness and connection ownership."""

import inspect
import json
import re
import sqlite3
import struct
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from redposture_core.clients import kafka
from redposture_core.clients.oracle import OracleAuditClient
from redposture_core.modules.clickhouse import actions as clickhouse
from redposture_core.modules.clickhouse.discover import engine
from redposture_core.modules.clickhouse.discover.models import ColumnInventory, TableInventory
from redposture_core.modules.clickhouse.discover.reader import ReadResult
from redposture_core.modules.etcd import actions as etcd
from redposture_core.modules.kafka import actions as kafka_actions
from redposture_core.modules.kafka.actions import _build_dump_coverage
from redposture_core.modules.oracle import actions as oracle
from redposture_core.modules.postgres import actions as postgres
from redposture_core.modules.redis import actions as redis

OUT = Path()


@pytest.fixture(autouse=True)
def audit_output_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(__import__(__name__, fromlist=["OUT"]), "OUT", tmp_path)


def test_n03_redis_duplicate_scan():
    responses = iter([("array", [b"1", [b"a", b"b"]]), ("array", [b"0", [b"a", b"c"]])])
    reads = []

    def value(sock, key):
        reads.append(key.decode())
        return "value", None

    with (
        patch.object(redis, "_send_cmd", side_effect=lambda *args: next(responses)),
        patch.object(redis, "_dump_redis_key_value", side_effect=value),
    ):
        entries, error = redis._stream_dump_redis_keys(None, batch=2, delay_ms=0, limit=3)
    assert [x["key"] for x in entries] == ["a", "b", "c"]
    assert reads == ["a", "b", "c"]


def test_n01_unknown_total_resume():
    path = OUT / "unknown-total-checkpoint.json"
    path.unlink(missing_ok=True)
    table = TableInventory("app", "events", columns=[ColumnInventory("app", "events", "payload", "String", 1)])
    calls = []

    def read(session, query):
        calls.append(int(re.search(r"OFFSET (\d+)", query)[1]))
        return ReadResult([["abc"], ["def"]], 6) if calls[-1] < 4 else ReadResult([], 0)

    with (
        patch.object(engine, "collect_inventory", return_value=([table], [])),
        patch.object(engine, "read_chunk", side_effect=read),
    ):
        first = engine.run_discovery(
            None,
            host="audit",
            port=9000,
            config=engine.DiscoverConfig(checkpoint=path, chunk_rows=2, max_total_bytes=6),
            query_rows=None,
        )
        assert calls == [0]
        calls.clear()
        resumed = engine.run_discovery(
            None,
            host="audit",
            port=9000,
            config=engine.DiscoverConfig(checkpoint=path, resume=True, chunk_rows=2),
            query_rows=None,
        )
    assert first["status"] == "partial" and calls == [2, 4] and resumed["status"] == "complete"
    assert resumed["coverage_percent"] == 100


def test_n02_split_resume():
    path = OUT / "split-checkpoint.json"
    path.unlink(missing_ok=True)
    table = TableInventory(
        "app", "events", total_rows=2, columns=[ColumnInventory("app", "events", "payload", "String", 1)]
    )
    calls = []

    def read(session, query):
        limit, offset = map(int, re.search(r"LIMIT (\d+) OFFSET (\d+)", query).groups())
        calls.append([offset, limit])
        return ReadResult([], 0, "memory limit") if limit > 1 else ReadResult([['{"password":"S3cretValue123"}']], 29)

    with (
        patch.object(engine, "collect_inventory", return_value=([table], [])),
        patch.object(engine, "read_chunk", side_effect=read),
    ):
        first = engine.run_discovery(
            None, host="audit", port=9000, config=engine.DiscoverConfig(checkpoint=path, chunk_rows=2), query_rows=None
        )
        calls.clear()
        resumed = engine.run_discovery(
            None,
            host="audit",
            port=9000,
            config=engine.DiscoverConfig(checkpoint=path, resume=True, chunk_rows=2),
            query_rows=None,
        )
    assert first["occurrence_count"] == resumed["occurrence_count"] == 2
    assert calls == [] and resumed["coverage_percent"] == 100


def test_n04_oracle_users_fallback():
    # ALL_USERS columns mirror Oracle's published dictionary view. SQLite is
    # only the local SELECT-column validator; this does not emulate Oracle auth.
    conn = sqlite3.connect(":memory:")
    conn.execute(
        "create table all_users (username text, user_id integer, created text, common text, oracle_maintained text, inherited text, default_collation text, implicit text, all_shard text)"
    )
    conn.executemany("insert into all_users (username) values (?)", [("ALICE",), ("BOB",), ("AUDITOR",)])
    conn.execute("create table dual (user text)")
    conn.execute("insert into dual values ('AUDITOR')")
    result = OracleAuditClient(conn).list_users()
    visible = [row[0] for row in conn.execute("select username from all_users order by username")]
    assert [x["username"] for x in result] == visible
    conn.close()


def test_n05_oracle_deep_error_leak():
    opened = []

    class Client:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    def open_client(*args, **kwargs):
        client = Client()
        opened.append(client)
        return client

    params: dict[str, Any] = {
        name: None
        for name, p in inspect.signature(oracle._audit_oracle_host).parameters.items()
        if p.default is inspect.Parameter.empty
    }
    params.update(
        host="audit",
        port=1521,
        timeout=1,
        retries=1,
        protocol="tcp",
        service="APP",
        credential_candidates=[{"username": "u", "password": "p"}],
    )
    probe = {
        "listener_targets": [{"protocol": "tcp", "service": "APP", "status": "accepted"}],
        "listener_reachable": True,
        "protocol": "tcp",
        "service": "APP",
        "sid": None,
        "auth_target": True,
        "auth_probes": [{"protocol": "tcp", "service": "APP", "sid": None}],
    }
    params["probe_state"] = {"oracle_detection": probe}
    with (
        patch.object(oracle, "_try_credentials", return_value=({"username": "u", "password": "p"}, [], None)),
        patch.object(oracle, "_open_client", side_effect=open_client),
        patch.object(oracle, "_collect_oracle_data", side_effect=ValueError("ORA-00942: table or view does not exist")),
        patch.object(oracle.time, "sleep"),
    ):
        record = oracle._audit_oracle_host(**params)
    assert len(opened) == 1 and all(c.closed for c in opened) and record["is_oracle"] is True
    assert record["status"] == "valid_credentials" and "ORA-00942" in record["error"]


def test_n06_kafka_one_fetch():
    requests = []

    def send(sock, **kwargs):
        requests.append(kwargs["api_key"])
        correlation = kwargs["correlation_id"]
        topic = kafka._encode_kafka_string("events")
        if kwargs["api_key"] == kafka.KAFKA_LIST_OFFSETS:
            return struct.pack(">ii", correlation, 1) + topic + struct.pack(">iihiq", 1, 0, 0, 1, 0)
        page = requests.count(kafka.KAFKA_FETCH)
        records = kafka._build_produce_probe_batch(b"first-message" if page == 1 else b"second-message")
        if page > 1:
            records = struct.pack(">q", 1) + records[8:]
        # A valid Fetch v10 page contains one record; high watermark=2 proves
        # another record remains. A normal broker may split at a batch or byte limit.
        return (
            struct.pack(">iihii", correlation, 0, 0, 0, 1)
            + topic
            + struct.pack(">iihqqqii", 1, 0, 0, 2, 2, 0, -1, len(records))
            + records
        )

    with patch.object(kafka, "_send_kafka_request", side_effect=send):
        messages, correlation, error = kafka._read_partition_messages_on_leader(None, 1, "events", 0, 2)
    coverage = _build_dump_coverage(["events"], {"events": messages}, {}, error)
    assert messages == ["p0@0 first-message", "p0@1 second-message"]
    assert requests == [2, 1, 1] and error is None and coverage["complete"]


def test_n07_clickhouse_case_sensitive_selectors():
    columns, error = clickhouse._normalize_column_names(["userName,UserName"])
    tables = clickhouse._normalize_table_targets(["app.events,app.Events"])
    with patch.object(clickhouse, "_query_rows", return_value=([["userName"], ["UserName"]], None)):
        filtered, _ = clickhouse._query_table_columns(None, "app", "events", only_columns=["userName"])
    assert columns == ["userName", "UserName"] and tables == ["app.events", "app.Events"] and filtered == ["userName"]


def test_n08_kafka_sasl_order_lost():
    class Sock:
        def __init__(self):
            reply = struct.pack(">ihi", 1, 0, 1) + kafka._encode_kafka_string("PLAIN")
            self.incoming = struct.pack(">i", len(reply)) + reply

        def sendall(self, data):
            pass

        def recv(self, size):
            chunk, self.incoming = self.incoming[:size], self.incoming[size:]
            return chunk

    observed = []

    class Session:
        transport_mode = "plaintext"
        correlation_id = 1

        def __init__(self):
            self.sock = Sock()

        def detect(self):
            raise ConnectionError("unexpected EOF")

        def close(self):
            pass

        def bootstrap(self, **kwargs):
            observed.append(kwargs["sasl_first"])
            return (True, None) if kwargs["sasl_first"] else (None, "ApiVersions rejected before SASL")

        def fetch_metadata(self, **kwargs):
            return {"topic_map": {"events": 1}}, None

    state = kafka_actions.KafkaLifecycleState()
    ctx = SimpleNamespace(
        host="audit",
        port=9092,
        args=SimpleNamespace(timeout=1, retries=0),
        lifecycle_state=state,
        credential=SimpleNamespace(username="u", password="p", source="provided"),
        debug_emit=None,
    )
    with patch.object(kafka_actions.KafkaSession, "open", side_effect=lambda *a, **kw: Session()):
        detected = kafka_actions.detect_kafka(ctx, {"max_messages": 10})
        authenticated = kafka_actions.authenticate_kafka(ctx, detected, {})
    assert (
        detected["status"] == "auth_required"
        and observed == [True]
        and authenticated["provided_credentials_ok"] is True
    )


def test_n09_sql_catalog_identifiers():
    pg_queries = []

    def pg_query(sock, query):
        pg_queries.append(query)
        return ([["public", "order.items"]] if "information_schema.tables" in query else [["value"]]), None

    with patch.object(postgres, "_pg_query_rows", side_effect=pg_query):
        names, _ = postgres._pg_query_readable_tables(None)
        name, rows, error = postgres._pg_query_table_rows(None, names[0], max_rows=1)
    assert names == ['public."order.items"'] and rows is not None and error is None
    assert 'FROM "public"."order.items"' in pg_queries[-1]
    assert postgres._pg_display_identifier_path(["Mixed", "Table"]) == '"Mixed"."Table"'
    session = SimpleNamespace(database="app", check_grant_supported=None)

    def ch_query(session, query):
        return ([["app", "order.items"]] if "FROM system.tables" in query else [[1]]), None

    with patch.object(clickhouse, "_query_rows", side_effect=ch_query):
        readable, access, truncated, errors = clickhouse._query_readable_tables_result(session)
    assert readable == ["app.`order.items`"] and not errors


def test_n11_oracle_scheduler_download_repeats():
    import subprocess

    source = OUT / "source.txt"
    source.write_text("ABCDEFGH")

    class Client(OracleAuditClient):
        def __init__(self):
            pass

        def _data_pump_directory(self):
            return {"directory_path": str(OUT)}

        def _resolve_scheduler_path(self, path):
            return str(source)

        def scheduler_exec(self, command, *, capture_output=False):
            result = subprocess.run(command, shell=True, capture_output=True, check=False)
            return {"ok": result.returncode == 0}

        def _read_directory_file_chunk(self, path, *, offset=0, amount=32767):
            return {"ok": True, "data": (OUT / path).read_text()[offset : offset + amount], "error": None}

        def os_delete(self, path, **kwargs):
            (OUT / path).unlink()
            return {"ok": True}

    target = OUT / "download.txt"
    target.write_text("ABCD")
    result = oracle._download_oracle_file(
        Client(), "input", str(target), fs_mode="scheduler", chunk_size=4, max_chunks=3
    )
    assert target.read_text() == "ABCDEFGH" and result["ok"]


def test_n12_oracle_table_selector_ignored():
    selected = []

    class Client:
        def current_context(self):
            return {"current_schema": "APP"}

        def server_banner(self):
            return {}

        def list_tables(self, schema):
            return [{"owner": "APP", "table_name": "ACCOUNTS"}, {"owner": "APP", "table_name": "ORDERS"}]

        def dump_table(self, schema, table, *, limit):
            selected.append([schema, table])
            return [{"id": 1}]

    params: dict[str, Any] = {
        name: None
        for name, p in inspect.signature(oracle._collect_oracle_data).parameters.items()
        if p.default is inspect.Parameter.empty
    }
    params.update(
        client=Client(), host="audit", port=1521, protocol="tcp", table="ORDERS", dump_rows=True, dump_limit=1
    )
    result = oracle._collect_oracle_data(**params)
    assert selected == [["APP", "ORDERS"]] and result["error"] is None


def test_n10_etcd_v2_auth_status():
    def request(host, port, method, path, timeout, **kwargs):
        if path == "/version":
            return 200, json.dumps({"etcdserver": "2.3.8", "etcdcluster": "2.3.0"})
        if path.startswith("/v2/keys"):
            if kwargs.get("basic_auth") == ("root", "secret"):
                return 200, json.dumps(
                    {"action": "get", "node": {"key": "/", "dir": True, "nodes": [{"key": "/a", "value": "data"}]}}
                )
            return 401, json.dumps({"errorCode": 110, "message": "requires user authentication"})
        raise AssertionError(path)

    with patch.object(etcd, "_http_json_request", side_effect=request):
        record = etcd._audit_etcd_host("audit", 2379, 1, 0, False, False, None, username="root", password="secret")
    assert (
        record["provided_credentials_ok"] is True
        and record["status"] == "valid_credentials"
        and record["api_has_access"]["v2"] is True
    )


def test_n01_long_unknown_frontier_does_not_recurse(monkeypatch, tmp_path):
    table = TableInventory("app", "events", columns=[ColumnInventory("app", "events", "payload", "String", 1)])
    checkpoint = tmp_path / "long-frontier.json"
    reads = []

    def read(_session, query):
        reads.append(int(re.search(r"OFFSET (\d+)", query)[1]))
        return ReadResult([], 0)

    monkeypatch.setattr(engine, "collect_inventory", lambda _: ([table], []))
    monkeypatch.setattr(engine, "read_chunk", read)
    # Produce the current compatibility metadata through the real scan/store,
    # then seed a long completed frontier without changing its scan scope.
    engine.run_discovery(
        None,
        host="audit",
        port=9000,
        config=engine.DiscoverConfig(checkpoint=checkpoint, chunk_rows=1),
        query_rows=None,
    )
    chunks = {f"app.events|<all>|{offset}|1": {"status": "complete", "rows_scanned": 1} for offset in range(1100)}
    coverage = {
        "app.events.payload": {
            "status": "pending",
            "rows_scanned": 1100,
            "bytes_scanned": 1100,
            "total_chunks": 1101,
            "completed_chunks": 1100,
            "failed_chunks": 0,
        }
    }

    engine.CheckpointStore(checkpoint, "audit:9000", resume=True).update(chunks=chunks, coverage=coverage)
    reads.clear()
    result = engine.run_discovery(
        None,
        host="audit",
        port=9000,
        config=engine.DiscoverConfig(checkpoint=checkpoint, resume=True, chunk_rows=1),
        query_rows=None,
    )
    assert result["status"] == "complete" and result["coverage_percent"] == 100
    assert reads == [1100]


@pytest.mark.parametrize("failure", ["budget", "read_error"])
def test_n11_download_stops_are_partial(failure):
    class Client:
        def __init__(self):
            self.reads = 0

        def scheduler_read_file(self, path, *, max_bytes, offset):
            self.reads += 1
            if failure == "read_error" and self.reads == 2:
                return {"ok": False, "error": "read denied"}
            return {"ok": True, "data": "ABCD"}

    target = OUT / "partial.txt"
    result = oracle._download_oracle_file(
        Client(), "input", str(target), fs_mode="scheduler", chunk_size=4, max_chunks=2
    )
    assert result["ok"] is False and result["partial"] is True and result["error"]
    assert target.read_text() == ("ABCD" if failure == "read_error" else "ABCDABCD")


def test_n01_failed_unknown_frontier_can_finish_after_retry(monkeypatch):
    table = TableInventory("app", "events", columns=[ColumnInventory("app", "events", "payload", "String", 1)])
    path = OUT / "failed-frontier.json"
    attempts = []

    def read(session, query):
        offset = int(re.search(r"OFFSET (\d+)", query)[1])
        attempts.append(offset)
        if offset == 0:
            return ReadResult([["x"], ["y"]], 2)
        return ReadResult([], 0, "temporarily unavailable")

    monkeypatch.setattr(engine, "collect_inventory", lambda _: ([table], []))
    monkeypatch.setattr(engine, "read_chunk", read)
    first = engine.run_discovery(
        None, host="audit", port=9000, config=engine.DiscoverConfig(checkpoint=path, chunk_rows=2), query_rows=None
    )
    assert first["status"] == "partial"
    attempts.clear()

    def recovered(session, query):
        attempts.append(int(re.search(r"OFFSET (\d+)", query)[1]))
        return ReadResult([], 0)

    monkeypatch.setattr(engine, "read_chunk", recovered)
    resumed = engine.run_discovery(
        None,
        host="audit",
        port=9000,
        config=engine.DiscoverConfig(checkpoint=path, resume=True, chunk_rows=2),
        query_rows=None,
    )
    assert attempts == [2] and resumed["status"] == "complete"
    assert resumed["coverage_percent"] == 100


def test_n06_topic_keeps_pages_read_before_partition_error(monkeypatch):
    session = SimpleNamespace(
        closed=False, sock=object(), transport_mode="plaintext", correlation_id=1, api_versions={}
    )
    monkeypatch.setattr(
        kafka,
        "_read_partition_messages_on_leader",
        lambda *args, **kwargs: (["p0@0 first-message"], 3, "page2 timeout"),
    )
    items, error, _ = kafka._read_topic_messages(
        "audit", 9092, 1, "events", 10, existing_session=session, bootstrap_metadata={"topic_map": {"events": 1}}
    )
    assert items == ["p0@0 first-message"] and "page2 timeout" in error


def test_n06_fetch_transport_error_keeps_previous_page(monkeypatch):
    count = 0

    def send(sock, **kwargs):
        nonlocal count
        correlation = kwargs["correlation_id"]
        topic = kafka._encode_kafka_string("events")
        if kwargs["api_key"] == kafka.KAFKA_LIST_OFFSETS:
            return struct.pack(">ii", correlation, 1) + topic + struct.pack(">iihiq", 1, 0, 0, 1, 0)
        count += 1
        if count == 2:
            raise TimeoutError("page two timeout")
        records = kafka._build_produce_probe_batch(b"first-message")
        return (
            struct.pack(">iihii", correlation, 0, 0, 0, 1)
            + topic
            + struct.pack(">iihqqqii", 1, 0, 0, 2, 2, 0, -1, len(records))
            + records
        )

    monkeypatch.setattr(kafka, "_send_kafka_request", send)
    items, _, error = kafka._read_partition_messages_on_leader(None, 1, "events", 0, 2)
    assert items == ["p0@0 first-message"] and "timeout" in error
