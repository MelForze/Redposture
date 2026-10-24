"""Native audit regressions: actual parsers/collectors with finite transport fixtures."""

from __future__ import annotations

import gzip
import json
import struct
from dataclasses import replace
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from redposture_core.clients import kafka
from redposture_core.clients.http_api import HttpResponse
from redposture_core.clients.mongodb import MongoAuditClient
from redposture_core.modules.clickhouse.discover import engine
from redposture_core.modules.clickhouse.discover.models import ColumnInventory, TableInventory
from redposture_core.modules.clickhouse.discover.reader import ReadResult
from redposture_core.modules.kafka import http_surfaces, stage, ui
from redposture_core.modules.mongodb import actions as mongo
from redposture_core.modules.postgres import actions as pg


@pytest.mark.parametrize("database", ["Mixed DB", "DB.with.dot", 'a"b'])
@pytest.mark.parametrize("explicit", [False, True])
def test_nat01_quoted_database_is_raw_connection_identity(database, explicit):
    quoted = '"' + database.replace('"', '""') + '"'
    normalized, grouped, error = pg._pg_group_table_targets([f"{quoted}.public.events"], database if explicit else None)
    assert error is None
    assert grouped == {database: ["public.events"]}
    assert normalized == [f"{quoted}.public.events"]
    packets = []
    pg._pg_send_startup(SimpleNamespace(sendall=packets.append), "audit", next(iter(grouped)))
    fields = packets[0][8:].split(b"\0")
    assert fields[fields.index(b"database") + 1].decode() == database


@pytest.mark.parametrize(
    "vendor,port,path,content_type,root",
    [
        ("kafka_rest_proxy", 8082, "/topics", "application/vnd.kafka.v2+json", {}),
        (
            "kafka_connect",
            8083,
            "/connectors",
            "application/json",
            {"version": "3.0", "commit": "abc", "kafka_cluster_id": "id"},
        ),
        ("schema_registry", 8081, "/subjects", "application/vnd.schemaregistry.v1+json", {}),
        ("redpanda_console", 8080, "/api/topics", "application/json", None),
    ],
)
def test_nat02_http_inventory_retains_all_received_items(vendor, port, path, content_type, root):
    names = [f"item-{i}" for i in range(201)]

    class Pool:
        def request(self, method, url, **kwargs):
            request_path = urlsplit(url).path
            if request_path == path:
                value = [{"name": name} for name in names] if vendor == "redpanda_console" else names
                return HttpResponse(200, json.dumps(value).encode(), {"Content-Type": content_type})
            values = {"/v3/clusters": {"kind": "KafkaClusterList", "data": []}, "/admin/startup": {}}
            if request_path in values:
                return HttpResponse(200, json.dumps(values[request_path]).encode(), {})
            if request_path == "/":
                body = b"<title>Redpanda Console</title>" if root is None else json.dumps(root).encode()
                return HttpResponse(200, body, {})
            return HttpResponse(404, b"", {})

    ctx = SimpleNamespace(host="audit", port=port, args=SimpleNamespace(port=port), target=None)
    record = http_surfaces.detect(Pool(), f"http://audit:{port}", ctx)
    assert record["ui_vendor"] == vendor
    assert record["http_inventory"] == names
    if vendor in {"redpanda_console", "kafka_rest_proxy"}:
        assert [item["name"] for item in http_surfaces.collect(record, {"show_topics": True})["ui_topics"]] == names


@pytest.mark.parametrize("host", ["::1", "2001:db8::42"])
def test_nat03_ui_base_brackets_ipv6(host):
    ctx = SimpleNamespace(host=host, port=8080, target=SimpleNamespace(path="/prefix/api/info"))
    result = ui._base(ctx, "http")
    assert result == f"http://[{host}]:8080/prefix"
    assert urlsplit(result).hostname == host
    assert urlsplit(result).port == 8080


def _clickhouse_fixture(monkeypatch):
    table = TableInventory(
        "app",
        "events",
        total_rows=2,
        columns=[
            ColumnInventory("app", "events", "public", "String", 1),
            ColumnInventory("app", "events", "password", "String", 2),
        ],
    )
    monkeypatch.setattr(engine, "collect_inventory", lambda _: ([table], []))
    reads = []

    def read(session, query):
        reads.append(query)
        return ReadResult([["ordinary", "secret-value-123"]], 24)

    monkeypatch.setattr(engine, "read_chunk", read)
    return table, reads


@pytest.mark.parametrize(
    "change",
    [
        {"exclusions": ()},
        {"chunk_rows": 1},
        {"detectors": ("password",)},
        {"redact": False},
    ],
)
def test_nat04_resume_rejects_changed_scope_before_reads(tmp_path, monkeypatch, change):
    _, reads = _clickhouse_fixture(monkeypatch)
    path = tmp_path / "checkpoint.json"
    config = engine.DiscoverConfig(checkpoint=path, chunk_rows=2, exclusions=("app.events.password",))
    engine.run_discovery(None, host="audit", port=9000, config=config, query_rows=None)
    before = path.read_bytes()
    reads.clear()
    with pytest.raises(ValueError, match="incompatible.*checkpoint|checkpoint.*incompatible"):
        engine.run_discovery(
            None, host="audit", port=9000, config=replace(config, resume=True, **change), query_rows=None
        )
    assert reads == []
    assert path.read_bytes() == before


def test_nat04_resume_rejects_legacy_checkpoint_with_unverifiable_scope(tmp_path, monkeypatch):
    _, reads = _clickhouse_fixture(monkeypatch)
    path = tmp_path / "checkpoint.json"
    config = engine.DiscoverConfig(checkpoint=path, chunk_rows=2)
    engine.run_discovery(None, host="audit", port=9000, config=config, query_rows=None)
    document = json.loads(path.read_text())
    document["targets"]["audit:9000"].pop("scan_signature", None)
    path.write_text(json.dumps(document))
    before = path.read_bytes()
    reads.clear()
    with pytest.raises(ValueError, match="incompatible.*checkpoint|checkpoint.*incompatible"):
        engine.run_discovery(None, host="audit", port=9000, config=replace(config, resume=True), query_rows=None)
    assert reads == []
    assert path.read_bytes() == before


def test_nat04_same_scope_resume_preserves_occurrences_and_allows_budget_change(tmp_path, monkeypatch):
    _, reads = _clickhouse_fixture(monkeypatch)
    config = engine.DiscoverConfig(checkpoint=tmp_path / "checkpoint.json", chunk_rows=2)
    first = engine.run_discovery(None, host="audit", port=9000, config=config, query_rows=None)
    reads.clear()
    resumed = engine.run_discovery(
        None, host="audit", port=9000, config=replace(config, resume=True, max_seconds=60), query_rows=None
    )
    assert reads == []
    assert resumed["occurrence_count"] == first["occurrence_count"]
    assert resumed["coverage_percent"] <= 100


@pytest.mark.parametrize("count_error", [False, True])
def test_nat05_mongodb_preserves_partial_documents_and_closes_cursor(count_error):
    closed = []

    class Cursor:
        def limit(self, limit):
            return self

        def close(self):
            closed.append(True)

        def __iter__(self):
            yield {"_id": 1, "password": "secret-value-123"}
            raise TimeoutError("getMore timed out after first batch")

    def count():
        if count_error:
            raise TimeoutError("count timed out")
        return 2

    collection = SimpleNamespace(
        estimated_document_count=count, count_documents=lambda query: count(), find=lambda *args: Cursor()
    )

    class Database:
        def __getitem__(self, key):
            return collection

    class Raw:
        def __getitem__(self, key):
            return Database()

    report = mongo._collect_mongodb_data(
        MongoAuditClient(Raw()),
        database_names=["app"],
        selected_database="app",
        collection_targets=["items"],
        collection_targets_by_database={"app": ["items"]},
        show_databases=False,
        show_collections=False,
        show_indexes=False,
        dump_documents=True,
        dump_limit=2,
        query_filter=None,
        projection=None,
    )
    assert report["documents"] == [
        {"database": "app", "collection": "items", "document": {"_id": 1, "password": "secret-value-123"}}
    ]
    assert report["partial"] is True
    assert report["capabilities"]["can_read_documents"] is True
    assert report["query_error"] == "connection timeout"
    assert closed == [True]


def _varint(value):
    value = (value << 1) ^ (value >> 63)
    out = bytearray()
    while value > 127:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)


def _batch(offset, values, *, control=False, compressed=False):
    records = []
    for delta, value in enumerate(values):
        raw_value = _varint(-1) if value is None else _varint(len(value)) + value
        body = b"\0" + _varint(0) + _varint(delta) + _varint(-1) + raw_value + _varint(0)
        records.append(_varint(len(body)) + body)
    encoded = b"".join(records)
    attributes = (0x30 if control else 0) | (1 if compressed else 0)
    suffix = struct.pack(">hiqqqhii", attributes, max(0, len(values) - 1), 0, 0, -1, -1, -1, len(values))
    suffix += gzip.compress(encoded) if compressed else encoded
    batch = struct.pack(">ibI", 0, 2, kafka._crc32c(suffix)) + suffix
    return struct.pack(">qi", offset, len(batch)) + batch


def _partition_read(monkeypatch, batches, *, start, end, count):
    fetch_offsets = []

    def send(sock, **kwargs):
        correlation = kwargs["correlation_id"]
        topic = kafka._encode_kafka_string("events")
        if kwargs["api_key"] == kafka.KAFKA_LIST_OFFSETS:
            return struct.pack(">ii", correlation, 1) + topic + struct.pack(">iihiq", 1, 0, 0, 1, start)
        # Fetch v10 body ends in partition offset, max_bytes; parse through known fields.
        reader = kafka._KafkaReader(kwargs["body"])
        reader._read(4 + 4 + 4 + 4 + 1 + 4 + 4 + 4)  # replica/max-wait/min/max/isolation/session/session-epoch/topics
        reader.read_string(nullable=False)
        reader.read_i32()
        reader.read_i32()
        reader.read_i32()  # partition count/id/leader epoch
        offset = reader.read_i64()
        fetch_offsets.append(offset)
        records = batches(offset)
        return (
            struct.pack(">iihii", correlation, 0, 0, 0, 1)
            + topic
            + struct.pack(">iihqqqii", 1, 0, 0, end, end, start, -1, len(records))
            + records
        )

    monkeypatch.setattr(kafka, "_send_kafka_request", send)
    messages, _, error = kafka._read_partition_messages_on_leader(None, 1, "events", 0, count)
    return messages, error, fetch_offsets


def test_nat06_compressed_batch_prefix_does_not_consume_requested_count(monkeypatch):
    records = _batch(0, [b"before-start", b"available-one", b"available-two"], compressed=True)
    messages, error, _ = _partition_read(monkeypatch, lambda _: records, start=1, end=3, count=2)
    assert messages == ["p0@1 available-one", "p0@2 available-two"]
    assert error is None


def test_nat07_control_batch_does_not_consume_application_count(monkeypatch):
    records = _batch(0, [struct.pack(">hi", 0, 1)], control=True) + _batch(1, [b"application-one", b"application-two"])
    messages, error, _ = _partition_read(monkeypatch, lambda _: records, start=0, end=3, count=2)
    assert messages == ["p0@1 application-one", "p0@2 application-two"]
    assert error is None


@pytest.mark.parametrize(
    "first",
    [_batch(0, [b"marker"], control=True), _batch(0, [None]), _batch(0, []), _batch(0, [], compressed=True)],
    ids=["control", "tombstone", "empty", "compressed-empty"],
)
def test_nat07_control_or_tombstone_only_fetch_advances_to_next_batch(monkeypatch, first):
    messages, error, offsets = _partition_read(
        monkeypatch, lambda offset: first if offset == 0 else _batch(1, [b"application"]), start=0, end=2, count=1
    )
    assert messages == ["p0@1 application"]
    assert error is None
    assert offsets == [0, 1]


@pytest.mark.parametrize("status", ["auth_required", "invalid_credentials"])
@pytest.mark.parametrize("dump", [False, True])
def test_live21_01_ui_request_fields_exist_before_auth_gate(monkeypatch, status, dump):
    monkeypatch.setattr(
        ui,
        "detect_ui",
        lambda *args: {"host": "audit", "port": 8080, "is_kafka": True, "is_kafka_ui": True, "status": status},
    )
    args = SimpleNamespace(show_topics=True, dump=dump, max_messages=17)
    spec = stage.build_kafka_spec(args)
    ctx = SimpleNamespace(
        host="audit", port=8080, target=SimpleNamespace(scheme="http"), lifecycle_state=SimpleNamespace()
    )
    assert spec.detect is not None
    record = spec.detect(ctx).to_dict()
    assert record["show_topics"] is True
    assert record["dump"] is dump
    assert record["max_messages"] == (17 if dump else None)


def test_native_unlimited_dump_reads_all_pages_to_snapshot_high_watermark(monkeypatch):
    messages, error, offsets = _partition_read(
        monkeypatch,
        lambda offset: _batch(offset, [f"seed-{i}".encode() for i in range(offset, offset + 100)]),
        start=0,
        end=1205,
        count=None,
    )
    assert messages == [f"p0@{i} seed-{i}" for i in range(1205)]
    assert error is None
    assert offsets == list(range(0, 1205, 100))


def test_native_unlimited_dump_preserves_received_pages_on_fetch_failure(monkeypatch):
    def batches(offset):
        if offset == 200:
            raise TimeoutError("next fetch timed out")
        return _batch(offset, [f"seed-{i}".encode() for i in range(offset, offset + 100)])

    messages, error, offsets = _partition_read(monkeypatch, batches, start=0, end=1205, count=None)
    assert messages == [f"p0@{i} seed-{i}" for i in range(200)]
    assert error and "timeout" in error.lower()
    assert offsets == [0, 100, 200]
