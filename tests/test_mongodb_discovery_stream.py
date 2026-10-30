from __future__ import annotations

import gc
import tracemalloc
from types import SimpleNamespace

import pytest

from redposture_core.clients.mongodb import MongoAuditClient, MongoBudgetStop, MongoPartialReadError
from redposture_core.discovery_values import DiskBackedText, iter_json_chunks
from redposture_core.modules.mongodb.actions import _collect_mongodb_data
from redposture_core.storage_discovery import DiscoveryCollector


class _Cursor:
    closed = False

    def __init__(self, count=1200, failure=None):
        self.count, self.failure = count, failure

    def batch_size(self, count):
        assert count == 1
        return self

    def __iter__(self):
        for index in range(self.count):
            yield {"_id": index, "message": "ordinary-" + "z" * 50_000}
        if self.failure:
            raise self.failure

    def close(self):
        self.closed = True


def _client(cursor):
    collection = SimpleNamespace(find=lambda *args: cursor)

    class Database:
        def __getitem__(self, name):
            return collection

    class Raw:
        def __getitem__(self, name):
            return Database()

    return MongoAuditClient(Raw())


def _measured(run):
    gc.collect()
    tracemalloc.start()
    try:
        result = run()
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    return result, peak


def test_mongodb_discovery_cursor_does_not_retain_all_documents_in_ram():
    cursor = _Cursor()
    seen = 0

    def accept(doc):
        nonlocal seen
        assert doc["_id"] == seen
        seen += 1
        return True

    result, peak = _measured(lambda: _client(cursor).find_documents("qa", "docs", on_document=accept, batch_size=1))
    assert cursor.closed and seen == len(result) == 1200
    assert result[-1]["_id"] == 1199
    assert peak < 12_000_000, peak


def test_mongodb_discovery_stage_does_not_retain_a_second_document_list(monkeypatch):
    cursor = _Cursor()
    # The scanner is deliberately inert here: isolate retention in the action
    # from detector costs. The cursor and stage themselves are production code.
    collector = DiscoveryCollector("mongodb", SimpleNamespace(args=SimpleNamespace()), {"status": "open_no_auth"})
    monkeypatch.setattr(collector, "add", lambda *args: True)
    result, peak = _measured(
        lambda: _collect_mongodb_data(
            _client(cursor),
            database_names=["qa"],
            selected_database="qa",
            collection_targets=["docs"],
            collection_targets_by_database={"qa": ["docs"]},
            show_databases=False,
            show_collections=False,
            show_indexes=False,
            dump_documents=True,
            dump_limit=None,
            query_filter=None,
            projection=None,
            discovery_collector=collector,
        )
    )
    assert cursor.closed and len(result["documents"]) == 1200
    assert result["documents"][-1]["document"]["_id"] == 1199
    assert peak < 12_000_000, peak


def test_mongodb_large_document_is_not_json_roundtripped_in_memory():
    import hashlib

    value = "Utf8-秘密/7a" * 700_000

    class Cursor(_Cursor):
        def __iter__(self):
            yield {"token": value}

    cursor = Cursor()
    result, peak = _measured(
        lambda: _client(cursor).find_documents("qa", "docs", on_document=lambda doc: True, batch_size=1)
    )
    assert cursor.closed
    saved = result[0]["token"]
    assert isinstance(saved, DiskBackedText)
    assert saved.digest == hashlib.sha256(value.encode()).hexdigest()
    assert peak < 10_000_000, peak


def test_mongodb_discovery_keeps_relaxed_extended_json_types():
    import datetime
    import json

    from bson import Binary, Code, Decimal128, Int64, ObjectId, Regex, Timestamp, json_util

    document = {
        "oid": ObjectId("0123456789abcdef01234567"),
        "binary": Binary(b"a\x00b", subtype=128),
        "date": datetime.datetime(2026, 1, 2, tzinfo=datetime.timezone.utc),
        "decimal": Decimal128("1.2300"),
        "code": Code("return x", {"x": "scope-value"}),
        "int": Int64(123),
        "regex": Regex("a+", "i"),
        "timestamp": Timestamp(123, 4),
        "nan": float("nan"),
        "float": 1.25,
        "list": ["ordinary", {"nested": True}],
    }

    class Cursor(_Cursor):
        def __iter__(self):
            yield document

    result = _client(Cursor()).find_documents("qa", "docs", on_document=lambda doc: True, batch_size=1)
    assert json.loads("".join(iter_json_chunks(result[0]))) == json.loads(
        json_util.dumps(document, json_options=json_util.RELAXED_JSON_OPTIONS)
    )


@pytest.mark.parametrize("failure", [ConnectionResetError("reset"), TimeoutError("timed out")])
def test_mongodb_stream_failure_keeps_completed_documents(failure):
    cursor = _Cursor(count=2, failure=failure)
    seen = []
    with pytest.raises(MongoPartialReadError) as error:
        _client(cursor).find_documents("qa", "docs", on_document=lambda doc: seen.append(doc["_id"]) or True)
    assert cursor.closed and seen == [0, 1]
    assert [doc["_id"] for doc in error.value.documents] == [0, 1]


def test_mongodb_callback_cancellation_keeps_prefix_and_closes_cursor():
    cursor = _Cursor(count=4)
    with pytest.raises(MongoBudgetStop) as error:
        _client(cursor).find_documents("qa", "docs", on_document=lambda doc: doc["_id"] < 2)
    assert cursor.closed
    assert [doc["_id"] for doc in error.value.documents] == [0, 1]


def test_mongodb_expired_deadline_does_not_start_find():
    import time

    class Raw:
        def __getitem__(self, name):
            pytest.fail("expired discovery must not start another operation")

    with pytest.raises(TimeoutError, match="discover_time"):
        MongoAuditClient(Raw()).find_documents(
            "qa", "docs", on_document=lambda doc: True, deadline=time.monotonic() - 1
        )


def test_mongodb_disk_failure_keeps_prior_complete_document(monkeypatch):
    class Cursor(_Cursor):
        def __iter__(self):
            yield {"password": "first-secret"}
            yield {"password": "long-secret-" * 10_000}

    def disk_full(*args):
        raise OSError("test disk full")

    monkeypatch.setattr(DiskBackedText, "append_text", disk_full)
    cursor = Cursor()
    with pytest.raises(MongoPartialReadError, match="test disk full") as error:
        _client(cursor).find_documents("qa", "docs", on_document=lambda doc: True)
    assert cursor.closed
    assert error.value.documents == [{"password": "first-secret"}]


def _collect(client, collector):
    return _collect_mongodb_data(
        client,
        database_names=["qa"],
        selected_database="qa",
        collection_targets=["docs"],
        collection_targets_by_database={"qa": ["docs"]},
        show_databases=False,
        show_collections=False,
        show_indexes=False,
        dump_documents=True,
        dump_limit=None,
        query_filter=None,
        projection=None,
        discovery_collector=collector,
    )


def test_mongodb_all_documents_denied_is_unavailable():
    from pymongo.errors import OperationFailure

    cursor = _Cursor(count=0, failure=OperationFailure("not authorized on qa to execute find", code=13))
    collector = DiscoveryCollector("mongodb", SimpleNamespace(args=SimpleNamespace()), {"status": "auth_valid"})
    result = _collect(_client(cursor), collector)
    assert result["content_discovery"]["status"] == "unavailable"
    assert result["content_discovery"]["partial_reasons"] == ["qa.docs: access_denied"]
    assert cursor.closed


def test_mongodb_cursor_cleanup_obeys_discovery_deadline():
    import time

    from pymongo import _csot

    cleanup_remaining = []

    class Cursor(_Cursor):
        def close(self):
            cleanup_remaining.append(_csot.remaining())
            super().close()

    cursor = Cursor(count=2)
    _client(cursor).find_documents("qa", "docs", on_document=lambda doc: True, deadline=time.monotonic() + 0.2)
    assert cursor.closed
    assert cleanup_remaining[0] is not None and 0 < cleanup_remaining[0] <= 0.2


@pytest.mark.parametrize(
    "field,formatter",
    [("documents", "_format_documents_detail_records"), ("query_documents", "_format_query_detail_records")],
)
def test_mongodb_discovery_dump_preview_accepts_disk_values(field, formatter):
    from redposture_core.modules.mongodb import actions

    value = DiskBackedText()
    for _ in range(100):
        value.append_text("long-secret-" * 1000)
    value.finish()
    record = {
        "host": "qa",
        "port": 27017,
        field: [{"database": "qa", "collection": "docs", "document": {"password": value}}],
    }
    lines, peak = _measured(lambda: getattr(actions, formatter)(record, "txt"))
    assert len(lines) == 2 and '{"password":"long-secret-' in lines[1]
    assert lines[1].endswith("...")
    assert peak < 1_000_000, peak


def test_mongodb_discovery_cursor_defaults_to_one_document_batches():
    batch = []

    class Cursor(_Cursor):
        def batch_size(self, count):
            batch.append(count)
            return self

    cursor = Cursor(count=0)
    assert _client(cursor).find_documents("qa", "docs", on_document=lambda doc: True) == []
    assert batch == [1]


def test_mongodb_large_binary_preserves_subtype_and_complete_encoded_value():
    import base64
    import hashlib

    from bson import Binary

    source = b"binary-qa/\x00\xff" * 200_000
    # Measure conversion/result storage after the SDK has produced a BSON
    # value, just as for the large string case. Binary's constructor itself
    # makes two bounded copies; real CLI RSS includes SDK decoding separately.
    binary = Binary(source, subtype=128)

    class Cursor(_Cursor):
        def __iter__(self):
            yield {"data": binary}

    result, peak = _measured(lambda: _client(Cursor()).find_documents("qa", "docs", on_document=lambda doc: True))
    encoded = result[0]["data"]["$binary"]
    assert encoded["subType"] == "80"
    assert isinstance(encoded["base64"], DiskBackedText)
    assert encoded["base64"].digest == hashlib.sha256(base64.b64encode(source)).hexdigest()
    assert peak < 4_000_000, peak


def test_mongodb_callback_runs_before_requesting_the_next_document():
    from redposture_core.data_discovery import _scan_portioned_value

    seen = []

    class Cursor(_Cursor):
        def __iter__(self):
            yield {"password": "early-secret"}
            assert seen == [("password", "early-secret")]
            yield {"password": "late-secret"}

    def observe(doc):
        matches, _, complete = _scan_portioned_value(doc, "$", 65536)
        assert complete
        seen.extend((m.detector, m.value) for m in matches)
        return True

    cursor = Cursor()
    result = _client(cursor).find_documents("qa", "docs", on_document=observe)
    assert cursor.closed and len(result) == 2
    assert seen == [("password", "early-secret"), ("password", "late-secret")]


def test_mongodb_releases_decoded_bson_before_fetching_next_document():
    import weakref

    class Document(dict):
        pass

    class Cursor(_Cursor):
        def __iter__(self):
            document = Document(password="large-secret-" * 10000)
            previous = weakref.ref(document)
            yield document
            del document
            assert previous() is None, "previous decoded BSON survived into the next wire read"
            yield {"password": "second-secret"}

    cursor = Cursor()
    result = _client(cursor).find_documents("qa", "docs", on_document=lambda doc: True)
    assert cursor.closed and len(result) == 2
