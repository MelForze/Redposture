"""Object catalogs preserve complete JSON without retaining wide trees."""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import time
import tracemalloc
import urllib.error
import weakref
from collections.abc import Mapping
from types import SimpleNamespace

import pytest

from redposture_core.clients.oracle import OracleReadBudgetError, json_safe
from redposture_core.discovery_containers import DiskContainer
from redposture_core.discovery_json import DiskJSONDocument
from redposture_core.discovery_mapping import DiskObjectStore
from redposture_core.discovery_spool import SpoolingRecords, SpoolingValues
from redposture_core.discovery_values import DiskBackedText, iter_json_chunks


def _decode(payload):
    document = DiskJSONDocument()
    try:
        for offset in range(0, len(payload), 127):
            document.feed(payload[offset : offset + 127])
        return document.finish()
    finally:
        document.close()


def _plain(value):
    return json.loads("".join(iter_json_chunks(value)))


def test_object_is_real_mapping_and_small_json_operations_keep_all_members():
    value = _decode(b'{"number":1,"nested":{"boolean":true},"array":[null,"text"]}')
    assert isinstance(value, Mapping) and isinstance(value, DiskContainer)
    assert not isinstance(value, dict)
    assert list(value) == ["number", "nested", "array"]
    assert list(value.items())[0] == ("number", 1)
    assert value.get("missing", "default") == "default"
    assert value.get(10, "default") == "default"
    assert dict(value)["nested"]["boolean"] is True
    assert value == {"number": 1, "nested": {"boolean": True}, "array": [None, "text"]}
    with pytest.raises(TypeError):
        json.dumps(value)
    assert _plain(value) == {"number": 1, "nested": {"boolean": True}, "array": [None, "text"]}


@pytest.mark.parametrize(
    "payload,expected", [(b"{}", {}), (b"[]", []), (b"null", None), (b"false", False), (b"42", 42)]
)
def test_empty_containers_and_primitive_roots(payload, expected):
    assert _plain(_decode(payload)) == expected


def test_duplicate_keys_replace_value_without_moving_ordinal_even_for_long_unicode_keys():
    key = "ключ😀/" * 2000
    encoded_key = json.dumps(key, ensure_ascii=False)
    payload = '{"first":1,' + encoded_key + ':"old","last":3,' + encoded_key + ':"new","first":2}'
    value = _decode(payload.encode())
    assert len(value) == 3
    assert value["first"] == 2
    assert value[key] == "new"
    assert list(_plain(value)) == ["first", key, "last"]
    assert value == {"first": 2, key: "new", "last": 3}
    disk_key = next(key for key in value if isinstance(key, DiskBackedText))
    assert value[disk_key] == "new"
    assert "".join(disk_key.iter_text_chunks()) == key


def test_shared_owner_covers_nested_objects_arrays_and_independent_child_lifetime():
    document = DiskJSONDocument()
    document.feed(b'{"parent":{"items":[{"password":"secret"},[],{}]},"other":{}}')
    value = document.finish()
    child = value["parent"]["items"][0]
    array = value["parent"]["items"]
    assert isinstance(array, SpoolingValues)
    assert value.reference_owner is child.reference_owner is array.reference_owner
    owner = weakref.ref(value.reference_owner)
    document.close()
    del document, value, array
    assert owner() is not None
    assert child["password"] == "secret"
    del child
    assert owner() is None


def test_array_index_slice_reverse_and_prefix_keep_existing_spooling_api():
    value = _decode(b'[0,{"number":1},[2],3]')
    assert isinstance(value, SpoolingValues)
    assert value[-1] == 3
    assert _plain(value[::-1]) == [3, [2], {"number": 1}, 0]
    assert _plain(list(reversed(value))) == [3, [2], {"number": 1}, 0]
    assert _plain(value[1:3]) == [{"number": 1}, [2]]
    with pytest.raises(IndexError):
        _ = value[4]


def test_all_tree_nodes_and_counts_live_on_one_store_not_an_owner_per_item():
    document = DiskJSONDocument()
    tracemalloc.start()
    try:
        document.feed(b"[")
        for index in range(6000):
            if index:
                document.feed(b",")
            document.feed(b'{"object":{},"array":[]}')
        document.feed(b"]")
        value = document.finish()
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
        document.close()
    assert len(value) == 6000
    owner = value.reference_owner
    assert owner._db.execute("SELECT count(*) FROM containers").fetchone()[0] == 18001
    assert len(owner._spool_refs) == 0
    assert _plain(value[5999]) == {"object": {}, "array": []}
    assert peak < 8_000_000


def test_failed_root_array_exposes_only_closed_items_and_preserves_exact_long_leaf():
    document = DiskJSONDocument()
    block = b"v" * 100_000
    document.feed(b'[{"value":"' + block + b'"},{"password":"unfinished')
    with pytest.raises(ValueError):
        document.finish()
    value = document.completed_array()
    document.close()
    assert len(value) == 1
    leaf = value[0]["value"]
    assert isinstance(leaf, DiskBackedText)
    assert leaf.byte_length == len(block)
    assert leaf.digest == hashlib.sha256(block).hexdigest()


def test_expired_deadline_recovers_nested_completed_prefix_after_close():
    document = DiskJSONDocument(deadline=time.monotonic() + 900)
    document.feed(b'{"known":1,"nested":{"password":"complete","array":[{"password":"nested"},')
    document.parser.deadline = time.monotonic() - 1
    with pytest.raises(TimeoutError, match="discover_time"):
        document.feed(b'{"password":"not-read"}')
    value = document.partial_value()
    document.close()
    assert _plain(value) == {"known": 1, "nested": {"password": "complete", "array": [{"password": "nested"}]}}


class _FailingConnection:
    def __init__(self, connection, statement):
        self.connection = connection
        self.statement = statement

    def execute(self, sql, *args):
        if sql.startswith(self.statement):
            raise sqlite3.OperationalError("database or disk is full")
        return self.connection.execute(sql, *args)

    def close(self):
        self.connection.close()


def test_storage_failure_recovers_nested_prefix_without_any_new_disk_writes(monkeypatch):
    document = DiskJSONDocument()
    document.feed(b'{"known":1,"nested":{"password":"complete","array":[{"password":"nested"}')
    owner = document._store
    monkeypatch.setattr(owner, "_db", _FailingConnection(owner._db, "INSERT INTO entries"))
    with pytest.raises(OSError, match="storage failure"):
        document.feed(b"]}")
    value = document.partial_value()
    assert document.partial_value() is value
    document.close()
    assert _plain(value) == {"known": 1, "nested": {"password": "complete", "array": [{"password": "nested"}]}}


def test_metadata_update_failure_rolls_back_member_and_arena_import(monkeypatch):
    owner = DiskObjectStore()
    value = owner.mapping()
    value["kept"] = 1
    before = value.byte_length
    monkeypatch.setattr(owner, "_db", _FailingConnection(owner._db, "UPDATE containers"))
    with pytest.raises(OSError, match="storage failure"):
        value["failed"] = "q" * 100_000
    assert len(value) == 1
    assert value.byte_length == before
    assert _plain(value) == {"kept": 1}
    assert not owner._spool_refs


def test_validated_scalar_survives_its_storage_failure_and_document_close(monkeypatch):
    document = DiskJSONDocument()
    document.feed(b'{"kept":1,"password":"' + b"q" * 100_000)
    owner = document._store
    monkeypatch.setattr(owner, "_db", _FailingConnection(owner._db, "INSERT INTO entries"))
    with pytest.raises(OSError, match="storage failure"):
        document.feed(b'"}')
    value = document.partial_value()
    document.close()
    assert len(value) == 2
    assert value["kept"] == 1
    assert value["password"].byte_length == 100_000
    assert value["password"].digest == hashlib.sha256(b"q" * 100_000).hexdigest()


def test_top_level_and_nested_mapping_spool_codec_preserve_lifetime_and_json():
    value = _decode(b'{"nested":{"password":"complete"},"array":[{"n":1}]}')
    records = SpoolingRecords()
    records.append(value)
    records.append({"wrapped": value})
    assert _plain(next(records.iter_appended(0))) == {"nested": {"password": "complete"}, "array": [{"n": 1}]}
    del value
    records.finish()
    first, second = list(records)
    assert isinstance(first, Mapping) and isinstance(first, DiskContainer)
    assert _plain(first) == {"nested": {"password": "complete"}, "array": [{"n": 1}]}
    assert _plain(records[0]) == _plain(first)
    assert _plain(records[-1]["wrapped"]) == _plain(first)
    assert _plain(second["wrapped"]) == _plain(first)
    assert _plain(list(reversed(records))[1]) == _plain(first)
    del records, first
    assert second["wrapped"]["nested"]["password"] == "complete"


def test_json_safe_imports_native_objects_without_dumping_or_copying_whole_trees(monkeypatch):
    class Weird:
        def __str__(self):
            return "native-value"

    native = {"object": {"weird": Weird(), "array": [1, None, True]}, "long": "v" * 100_000}
    original = json.dumps

    def reject_native(value, *args, **kwargs):
        assert value is not native
        assert value is not native["object"]
        return original(value, *args, **kwargs)

    monkeypatch.setattr(json, "dumps", reject_native)
    converted = json_safe(native, bounded=True)
    assert isinstance(converted, Mapping) and isinstance(converted, DiskContainer)
    assert _plain(converted) == {"object": {"weird": "native-value", "array": [1, None, True]}, "long": "v" * 100_000}
    assert converted.byte_length == len("".join(iter_json_chunks(converted)).encode())
    assert json_safe(converted) is converted
    assert json_safe(converted["object"]["array"]) is not None


def test_json_safe_native_import_checks_deadline():
    with pytest.raises(OracleReadBudgetError, match="discover_time"):
        json_safe({"password": "complete"}, bounded=True, deadline=time.monotonic() - 1)


@pytest.mark.parametrize(
    "native", [{"nested": ["first", {"number": 2}]}, ["first", {"number": 2}], (1, "text"), {1: "integer-key"}]
)
def test_json_safe_ordinary_native_containers_preserve_identity_and_standard_serialization(native):
    converted = json_safe(native)
    assert converted is native
    assert json.loads(json.dumps(converted)) == json.loads(json.dumps(native))


def test_json_safe_ordinary_unsupported_scalar_keeps_native_container_shape():
    class Weird:
        def __str__(self):
            return "native-value"

    native = {"nested": ["first", {"weird": Weird()}]}
    converted = json_safe(native)
    assert isinstance(converted, dict) and isinstance(converted["nested"], list)
    assert json.loads(json.dumps(converted)) == {"nested": ["first", {"weird": "native-value"}]}
    assert not isinstance(native["nested"][1]["weird"], str)


@pytest.mark.parametrize("shape", ["root", "nested", "array", "headers"])
def test_result_spool_adopts_independent_documents_into_one_owner_and_text_arena(shape):
    records = SpoolingRecords()
    references = []
    key = "ключ/" * 1000
    text = "exact-long-value-" + "q" * 70_000
    for index in range(40):
        value = _decode(json.dumps({"index": index, "headers": {}, key: text}).encode())
        references.append(weakref.ref(value.reference_owner))
        if shape == "root":
            record = value
        elif shape == "nested":
            record = {"wrapped": value}
        elif shape == "array":
            record = {"array": [value]}
        else:
            record = {"headers": value["headers"]}
        records.append(record)
    del record, value
    assert not any(reference() is not None for reference in references)
    assert len(records._spool_refs) == 1
    owner = next(iter(records._spool_refs.values()))
    assert isinstance(owner, DiskObjectStore)
    assert len(owner._spool_refs) <= 1
    decoded = _plain(records)
    for index, record in enumerate(decoded):
        expected = {"index": index, "headers": {}, key: text}
        if shape == "root":
            assert record == expected
        elif shape == "nested":
            assert record == {"wrapped": expected}
        elif shape == "array":
            assert record == {"array": [expected]}
        else:
            assert record == {"headers": {}}
    restored = records[0]
    del records, owner
    assert _plain(restored) == decoded[0]


def test_result_spool_preserves_existing_destination_node_references_without_copying():
    records = SpoolingRecords()
    records.append(_decode(b'{"nested":{"password":"complete"}}'))
    restored = records[0]
    owner = restored.reference_owner
    count = owner._db.execute("SELECT count(*) FROM containers").fetchone()[0]
    records.append(restored)
    assert records[1].reference_owner is owner
    assert records[1].reference_locator == restored.reference_locator
    assert owner._db.execute("SELECT count(*) FROM containers").fetchone()[0] == count
    assert len(records._spool_refs) == 1


class _BrokenJSONTransport:
    def __init__(self, prefix):
        self.prefix = prefix

    def request_stream(self, _method, _url, **kwargs):
        from redposture_core.clients.http_api import HttpResponse

        if "on_response" in kwargs:
            kwargs["on_response"](200, {"Content-Type": "application/json"})
        kwargs["on_chunk"](self.prefix)
        return HttpResponse(200, b"", {}, error="connection_reset", truncated=True)


def test_transport_prefix_kafka_full_json_keeps_closed_array_items():
    from redposture_core.modules.kafka import ui

    response, value = ui._full_json(
        _BrokenJSONTransport(b'[{"name":"first","status":"online","password":"first-secret"},{"name":"unfinished'),
        "http://qa",
        "/api/clusters",
        budget=ui._UiDiscoveryBudget(2**63 - 1, time.monotonic() + 30),
    )
    assert response.error == "connection_reset" and response.truncated
    assert _plain(value) == [{"name": "first", "status": "online", "password": "first-secret"}]


def test_transport_prefix_etcd_v3_page_keeps_closed_kvs(monkeypatch):
    from redposture_core.modules.etcd import actions as etcd

    prefix = b'{"kvs":[{"key":"YQ==","value":"c2VjcmV0"},'
    pool = _BrokenJSONTransport(prefix)
    monkeypatch.setattr(etcd._ETCD_HTTP_LOCAL, "state", etcd._EtcdHttpLifecycle(pool, scheme="http"), raising=False)
    status, value, error, size = etcd._stream_v3_page(
        "qa", 2379, 1, {"key": "AA==", "range_end": "AA=="}, auth_token=None, deadline=time.monotonic() + 30
    )
    assert status == 200 and error == "connection_reset" and size == len(prefix)
    assert _plain(value["kvs"]) == [{"key": "YQ==", "value": "c2VjcmV0"}]


def test_transport_prefix_etcd_v2_tree_keeps_closed_leaf_nodes(monkeypatch):
    from redposture_core.modules.etcd import actions as etcd

    prefix = b'{"action":"get","node":{"key":"/","dir":true,"nodes":[{"key":"/password","value":"first-secret"},'
    pool = _BrokenJSONTransport(prefix)
    monkeypatch.setattr(etcd._ETCD_HTTP_LOCAL, "state", etcd._EtcdHttpLifecycle(pool, scheme="http"), raising=False)
    status, value, error, size = etcd._stream_v2_tree(
        "qa", 2379, 1, "/v2/keys?recursive=true", deadline=time.monotonic() + 30
    )
    assert status == 200 and error == "connection_reset" and size == len(prefix)
    assert _plain(value["node"]["nodes"]) == [{"key": "/password", "value": "first-secret"}]


def _discovery_context():
    return SimpleNamespace(
        args=SimpleNamespace(discover=True, discover_time=30, _discover_implicit_dump=True),
        host="qa",
        port=2379,
        discovery_started_at=time.monotonic(),
    )


def _etcd_collector_budget():
    from redposture_core.modules.etcd import actions as etcd
    from redposture_core.storage_discovery import DiscoveryCollector

    collector = DiscoveryCollector("etcd", _discovery_context(), {"status": "open_no_auth"})
    return collector, etcd._EtcdDiscoveryBudget(collector.deadline, 2**63 - 1, collector)


def _b64(text):
    return base64.b64encode(text.encode()).decode()


def test_etcd_v3_failed_page_ingests_closed_records_marks_partial_and_never_continues(monkeypatch):
    from redposture_core.modules.etcd import actions as etcd

    calls = []

    def oversized(*args, **kwargs):
        calls.append(kwargs["payload"])
        raise urllib.error.URLError("HTTP response exceeds limit")

    prefix = (
        '{"more":true,"kvs":[{"key":"' + _b64("/password") + '","value":"' + _b64("first-secret") + '"},'
        '{"key":"' + _b64("/password-incomplete") + '","value":"unfinished'
    ).encode()
    monkeypatch.setattr(etcd, "_http_json_request", oversized)
    monkeypatch.setattr(
        etcd._ETCD_HTTP_LOCAL,
        "state",
        etcd._EtcdHttpLifecycle(_BrokenJSONTransport(prefix), scheme="http"),
        raising=False,
    )
    collector, budget = _etcd_collector_budget()
    entries, error = etcd._stream_dump_v3_all("qa", 2379, 1, batch=1, delay_ms=0, discovery_budget=budget)
    assert error == "connection_reset"
    assert len(calls) == 1
    assert _plain(entries) == [{"key": "/password", "value": "first-secret", "error": None}]
    result = collector.result()
    assert result["status"] == "partial"
    assert [finding["value"] for finding in result["findings"]] == ["first-secret"]
    # The source is the decoded KV value, not an extra synthetic JSON field.
    assert [finding["object_path"] for finding in result["findings"]] == ["$.key_value_entries./password"]
    assert any("connection_reset" in reason for reason in result["partial_reasons"])


@pytest.mark.parametrize("version", ["v2", "v3"])
def test_etcd_selected_key_retains_closed_value_with_original_error(monkeypatch, version):
    from redposture_core.modules.etcd import actions as etcd

    def oversized(*args, **kwargs):
        raise urllib.error.URLError("HTTP response exceeds limit")

    if version == "v2":
        prefix = b'{"action":"get","node":{"key":"/password","value":"first-secret"},'
    else:
        prefix = ('{"kvs":[{"key":"' + _b64("/password") + '","value":"' + _b64("first-secret") + '"},').encode()
    monkeypatch.setattr(etcd, "_http_json_request", oversized)
    monkeypatch.setattr(
        etcd._ETCD_HTTP_LOCAL,
        "state",
        etcd._EtcdHttpLifecycle(_BrokenJSONTransport(prefix), scheme="http"),
        raising=False,
    )
    collector, budget = _etcd_collector_budget()
    read = etcd._dump_v2_key if version == "v2" else etcd._dump_v3_key
    entry, error = read("qa", 2379, "/password", 1, discovery_budget=budget)
    assert error == "connection_reset"
    assert entry == {"key": "/password", "value": "first-secret", "error": None}
    result = collector.result()
    assert result["status"] == "partial"
    assert [finding["value"] for finding in result["findings"]] == ["first-secret"]


@pytest.mark.parametrize("version", ["v2", "v3"])
def test_etcd_selected_key_excludes_open_records_and_never_claims_not_found(monkeypatch, version):
    from redposture_core.modules.etcd import actions as etcd

    def oversized(*args, **kwargs):
        raise urllib.error.URLError("HTTP response exceeds limit")

    if version == "v2":
        prefix = b'{"action":"get","node":{"key":"/password","value":"first-secret",'
    else:
        prefix = ('{"kvs":[{"key":"' + _b64("/password") + '","value":"' + _b64("first-secret") + '",').encode()
    monkeypatch.setattr(etcd, "_http_json_request", oversized)
    monkeypatch.setattr(
        etcd._ETCD_HTTP_LOCAL,
        "state",
        etcd._EtcdHttpLifecycle(_BrokenJSONTransport(prefix), scheme="http"),
        raising=False,
    )
    collector, budget = _etcd_collector_budget()
    read = etcd._dump_v2_key if version == "v2" else etcd._dump_v3_key
    entry, error = read("qa", 2379, "/password", 1, discovery_budget=budget)
    assert entry is None and error == "connection_reset"
    result = collector.result()
    assert result["status"] == "partial"
    assert not result["findings"]


def test_etcd_v2_audit_ingests_prefix_but_count_stays_unknown_and_source_is_not_refetched(monkeypatch):
    from redposture_core.modules.etcd import actions as etcd

    reads = []

    def request(_host, _port, _method, path, _timeout, **kwargs):
        reads.append(path)
        if path == "/version":
            return 200, '{"etcdserver":"2.3.8","etcdcluster":"2.3.0"}'
        assert path.startswith("/v2/keys")
        raise urllib.error.URLError("HTTP response exceeds limit")

    prefix = b'{"action":"get","node":{"key":"/","dir":true,"nodes":[{"key":"/password","value":"first-secret"},'
    monkeypatch.setattr(etcd, "_http_json_request", request)
    monkeypatch.setattr(
        etcd._ETCD_HTTP_LOCAL,
        "state",
        etcd._EtcdHttpLifecycle(_BrokenJSONTransport(prefix), scheme="http"),
        raising=False,
    )
    report = etcd._audit_etcd_host(
        "qa", 2379, 1, 0, False, True, None, discover=True, discover_ctx=_discovery_context()
    )
    assert len([path for path in reads if path.startswith("/v2/keys")]) == 1
    assert report["key_count_by_api"]["v2"] is None
    assert "connection_reset" in report["dump_error"]
    assert [entry["value"] for entry in report["key_value_entries"]] == ["first-secret"]
    assert report["content_discovery"]["status"] == "partial"
    assert [finding["value"] for finding in report["content_discovery"]["findings"]] == ["first-secret"]


@pytest.mark.parametrize("failed_source", ["clusters", "topics"])
def test_kafka_full_audit_ingests_prefix_marks_partial_and_stops_requests(failed_source):
    from redposture_core.clients.http_api import HttpResponse
    from redposture_core.modules.kafka import ui

    reads = []

    class Pool:
        def request_stream(self, _method, url, **kwargs):
            reads.append(url)
            kwargs["on_response"](200, {})
            if url.endswith("/api/clusters") and failed_source != "clusters":
                kwargs["on_chunk"](b'[{"name":"qa","status":"online"}]')
                return HttpResponse(200, b"", {})
            if failed_source == "clusters":
                kwargs["on_chunk"](b'[{"name":"qa","status":"online","password":"first-secret"},{"name":"unfinished')
            else:
                assert "/topics?" in url
                kwargs["on_chunk"](b'{"topics":[{"name":"orders","password":"first-secret"},{"name":"unfinished')
            return HttpResponse(200, b"", {}, error="connection_reset", truncated=True)

    state = SimpleNamespace(ui_base="http://qa", ui_http=Pool(), ui_cookie="", ui_vendor="kafbat")
    result = ui.collect_ui(
        _discovery_context(), {"status": "open_no_auth"}, state, {"ui_dump_all": True, "show_topics": True}
    )
    assert len(reads) == (1 if failed_source == "clusters" else 2)
    if failed_source == "clusters":
        assert len(result["ui_clusters"]) == 1 and result["ui_clusters"][0]["name"] == "qa"
        assert result["ui_clusters_partial"] and result["cluster_count"] is None
    else:
        assert _plain(result["ui_topics"]) == [{"cluster": "qa", "name": "orders"}]
        assert result["ui_topics_partial"] and result["topic_count"] is None
    discovery = result["content_discovery"]
    assert discovery["status"] == "partial"
    assert any("connection_reset" in reason for reason in discovery["partial_reasons"])
    assert [finding["value"] for finding in discovery["findings"]] == ["first-secret"]
    expected_path = "$.ui.clusters[0].password" if failed_source == "clusters" else "$.ui.cluster.qa.topics[0].password"
    assert [finding["object_path"] for finding in discovery["findings"]] == [expected_path]


class _FaultJSONTransport(_BrokenJSONTransport):
    def __init__(self, prefix, fault):
        super().__init__(prefix)
        self.fault = fault

    def request_stream(self, _method, _url, **kwargs):
        from redposture_core.clients.http_api import HttpResponse

        kwargs["on_response"](200, {})
        kwargs["on_chunk"](self.prefix)
        if self.fault == "exception":
            raise OSError("connection_reset")
        if self.fault == "invalid_json":
            kwargs["on_chunk"](b"!")
        return HttpResponse(200, b"", {}, truncated=True)


@pytest.mark.parametrize("fault", ["exception", "invalid_json", "truncated"])
def test_kafka_helper_faults_preserve_status_and_completed_records(fault):
    from redposture_core.modules.kafka import ui

    response, value = ui._full_json(
        _FaultJSONTransport(b'[{"name":"first"},', fault),
        "http://qa",
        "/api/clusters",
        budget=ui._UiDiscoveryBudget(2**63 - 1, time.monotonic() + 30),
    )
    assert response.status == 200 and response.truncated
    assert fault == "truncated" or response.error
    assert _plain(value) == [{"name": "first"}]


@pytest.mark.parametrize("version", ["v2", "v3"])
@pytest.mark.parametrize("fault", ["exception", "invalid_json", "truncated"])
def test_etcd_helper_faults_preserve_completed_records_and_error(monkeypatch, version, fault):
    from redposture_core.modules.etcd import actions as etcd

    if version == "v2":
        prefix = b'{"node":{"dir":true,"nodes":[{"key":"/password","value":"first-secret"},'
    else:
        prefix = b'{"kvs":[{"key":"YQ==","value":"c2VjcmV0"},'
    pool = _FaultJSONTransport(prefix, fault)
    monkeypatch.setattr(etcd._ETCD_HTTP_LOCAL, "state", etcd._EtcdHttpLifecycle(pool, scheme="http"), raising=False)
    if version == "v2":
        status, value, error, size = etcd._stream_v2_tree("qa", 2379, 1, "/v2/keys", deadline=time.monotonic() + 30)
        assert _plain(value["node"]["nodes"]) == [{"key": "/password", "value": "first-secret"}]
    else:
        status, value, error, size = etcd._stream_v3_page(
            "qa", 2379, 1, {}, auth_token=None, deadline=time.monotonic() + 30
        )
        assert _plain(value["kvs"]) == [{"key": "YQ==", "value": "c2VjcmV0"}]
    assert status == 200 and error
    assert size == len(prefix) + (1 if fault == "invalid_json" else 0)


def test_kafka_partial_partition_snapshot_cannot_prove_a_complete_topic():
    from redposture_core.modules.kafka import ui

    prefix = b'{"partitions":[{"partition":0,"offsetMin":0,"offsetMax":10},'
    result = ui._legacy_topic_offsets(
        _BrokenJSONTransport(prefix),
        "http://qa",
        "qa",
        "orders",
        cookie="",
        budget=ui._UiDiscoveryBudget(2**63 - 1, time.monotonic() + 30),
    )
    assert result is None
