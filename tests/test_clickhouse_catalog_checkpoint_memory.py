"""Catalog cardinality and durable progress must not grow the Python heap."""

from __future__ import annotations

import json
import tracemalloc

from redposture_core.modules.clickhouse.discover.checkpoint import CheckpointStore, InMemoryCheckpointStore
from redposture_core.modules.clickhouse.discover.inventory import collect_inventory


def _catalog_query(table_count, column_count=1):
    def query(sql):
        if "FROM system.tables " in sql:
            return (["app", f"t{i:05d}", "MergeTree", "", "", "", 0, 0] for i in range(table_count)), None
        if "FROM system.columns " in sql:
            return (
                ["app", f"t{i:05d}", f"c{j:05d}", "String", j + 1, 1, 2]
                for i in range(table_count)
                for j in range(column_count)
            ), None
        return iter(()), None

    return query


def test_catalog_many_tables_keeps_exact_inventory_with_bounded_heap():
    tracemalloc.start()
    try:
        tables, errors = collect_inventory(_catalog_query(10_000))
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert errors == []
    assert len(tables) == 10_000
    assert tables[9999].to_dict() == {
        "database": "app",
        "table": "t09999",
        "engine": "MergeTree",
        "partition_key": "",
        "sorting_key": "",
        "primary_key": "",
        "total_rows": 0,
        "total_bytes": 0,
        "columns": [
            {
                "database": "app",
                "table": "t09999",
                "name": "c00000",
                "type_name": "String",
                "position": 1,
                "compressed_bytes": 1,
                "uncompressed_bytes": 2,
            }
        ],
        "partitions": [],
        "inventory_errors": [],
    }
    assert peak < 4_000_000, f"catalog retained {peak} bytes for 10k tables"


def test_catalog_wide_table_keeps_columns_mutable_without_heap_growth():
    tracemalloc.start()
    try:
        tables, errors = collect_inventory(_catalog_query(1, 30_000))
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert not errors
    table = tables[0]
    assert len(table.columns) == 30_000
    assert table.columns[-1].name == "c29999"
    table.partitions.append({"partition_id": "p", "rows": 7})
    table.inventory_errors.append("denied")
    assert tables[0].to_dict()["partitions"] == [{"partition_id": "p", "rows": 7}]
    assert tables[0].inventory_errors == ["denied"]
    assert peak < 4_000_000, f"wide catalog retained {peak} bytes"


def test_ephemeral_checkpoint_keeps_30k_chunks_without_heap_growth():
    tracemalloc.start()
    try:
        store = InMemoryCheckpointStore("qa:9000")
        for number in range(30_000):
            store.update(chunk_id=f"app.t|<all>|{number}|1", chunk={"status": "complete", "rows_scanned": 1})
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert len(store.target_state()["chunks"]) == 30_000
    assert store.is_complete("app.t|<all>|29999|1")
    assert peak < 4_000_000, f"checkpoint retained {peak} bytes"


def test_durable_checkpoint_updates_do_not_reparse_unchanged_document(tmp_path, monkeypatch):
    path = tmp_path / "checkpoint.json"
    store = CheckpointStore(path, "qa:9000", resume=False)
    original = store._read_document
    reads = 0

    def read():
        nonlocal reads
        reads += 1
        return original()

    monkeypatch.setattr(store, "_read_document", read)
    for number in range(4):
        store.update(chunk_id=str(number), chunk={"status": "complete", "rows_scanned": 1})
    assert json.loads(path.read_text())["targets"]["qa:9000"]["chunks"]["3"]["rows_scanned"] == 1
    assert reads == 0, f"reparsed the unchanged checkpoint {reads} times"


def test_checkpoint_interleaving_and_resume_preserve_nested_state(tmp_path):
    path = tmp_path / "checkpoint.json"
    first = CheckpointStore(path, "a:9000", resume=False)
    first.update(
        chunk_id="a0",
        chunk={"status": "complete"},
        findings={"secret:a": {"occurrences": 1}},
        coverage={"app.a.payload": {"rows_scanned": 1, "completed_chunks": 1}},
    )
    second = CheckpointStore(path, "b:9000", resume=False)
    second.update(chunk_id="b0", chunk={"status": "complete"})
    first.update(status="partial")
    resumed = CheckpointStore(path, "a:9000", resume=True)
    state = resumed.target_state()
    assert resumed.is_complete("a0")
    assert state["findings"]["secret:a"]["occurrences"] == 1
    assert state["coverage"]["app.a.payload"]["completed_chunks"] == 1
    assert CheckpointStore(path, "b:9000", resume=True).is_complete("b0")


def test_engine_catalog_report_keeps_10k_table_metadata_bounded():
    from types import SimpleNamespace

    from redposture_core.modules.clickhouse.discover.engine import DiscoverConfig, run_discovery

    tracemalloc.start()
    try:
        report = run_discovery(
            SimpleNamespace(),
            host="qa",
            port=9000,
            config=DiscoverConfig(max_seconds=900),
            query_rows=_catalog_query(10_000),
        )
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert report["status"] == "complete"
    assert report["tables_inventory_count"] == report["tables_scanned"] == 10_000
    assert len(report["inventory"]) == len(report["coverage"]) == 10_000
    assert report["coverage"]["app.t09999.c00000"]["coverage_percent"] == 100.0
    assert peak < 6_000_000, f"engine retained {peak} bytes for 10k tables"


def test_successful_scan_clears_previous_disk_coverage_error():
    from redposture_core.modules.clickhouse.discover.catalog import CatalogTree
    from redposture_core.modules.clickhouse.discover.engine import _scan_rows
    from redposture_core.modules.clickhouse.discover.findings import FindingStore
    from redposture_core.modules.clickhouse.discover.models import ScanChunk

    coverage = CatalogTree().mapping(
        {
            "app.events.payload": {
                "rows_scanned": 0,
                "bytes_scanned": 0,
                "scan_incomplete": True,
                "scan_error": "old failure",
            }
        }
    )
    assert _scan_rows(
        [["ordinary"]],
        ScanChunk("app", "events", ("payload",), None, 0, 1),
        FindingStore(),
        coverage,
        enabled=("password",),
        redact=False,
    )
    restored = coverage["app.events.payload"]
    assert "scan_incomplete" not in restored and "scan_error" not in restored
    assert restored["rows_scanned"] == 1


def test_disk_mapping_delete_then_append_preserves_order_and_copy():
    from redposture_core.modules.clickhouse.discover.catalog import CatalogTree

    values = CatalogTree().mapping({"a": 1, "b": 2, "c": 3, "d": 4, "e": 5})
    del values["a"]
    del values["b"]
    values["f"] = 6
    values["g"] = 7
    assert list(values) == ["c", "d", "e", "f", "g"]
    assert values.copy() == {"c": 3, "d": 4, "e": 5, "f": 6, "g": 7}
    values.clear()
    assert len(values) == 0 and list(values) == []


def test_null_target_update_preserves_new_progress(tmp_path):
    path = tmp_path / "null.json"
    path.write_text('{"schema_version":1,"targets":{"qa:9000":null,"other:9000":{"future":7}}}')
    store = CheckpointStore(path, "qa:9000", resume=True)
    store.update(chunk_id="first", chunk={"status": "complete"}, coverage={"app.t.c": {"rows_scanned": 1}})
    restored = CheckpointStore(path, "qa:9000", resume=True)
    assert restored.is_complete("first")
    assert restored.target_state()["coverage"]["app.t.c"]["rows_scanned"] == 1
    assert json.loads(path.read_text())["targets"]["other:9000"] == {"future": 7}


def test_replacing_catalog_columns_and_partitions_updates_inventory():
    from redposture_core.modules.clickhouse.discover.models import ColumnInventory

    tables, _ = collect_inventory(_catalog_query(1))
    table = tables[0]
    table.columns = [ColumnInventory("app", "t00000", "replacement", "String", 1)]
    table.partitions = [{"partition_id": "new", "rows": 2}]
    assert tables[0].columns[0].name == "replacement"
    assert tables[0].partitions[0]["partition_id"] == "new"


def test_checkpoint_import_many_chunk_and_coverage_keys_stays_bounded(tmp_path):
    path = tmp_path / "large.json"
    with path.open("w") as stream:
        stream.write('{"schema_version":1,"targets":{"qa:9000":{"chunks":{')
        for number in range(10_000):
            if number:
                stream.write(",")
            stream.write(json.dumps(f"chunk-{number}") + ':{"status":"complete","rows_scanned":1}')
        stream.write('},"coverage":{')
        for number in range(10_000):
            if number:
                stream.write(",")
            stream.write(json.dumps(f"app.t{number}.c") + ':{"rows_scanned":1,"completed_chunks":1}')
        stream.write('},"findings":{},"future":{"keep":true}},"other:9000":{"future":17}}}')
    tracemalloc.start()
    try:
        store = CheckpointStore(path, "qa:9000", resume=True)
        state = store.target_state()
        assert store.is_complete("chunk-9999")
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert len(state["chunks"]) == len(state["coverage"]) == 10_000
    assert state["coverage"]["app.t9999.c"]["completed_chunks"] == 1
    assert state["future"]["keep"] is True
    assert CheckpointStore(path, "other:9000", resume=True).target_state()["future"] == 17
    assert peak < 4_000_000, f"checkpoint import retained {peak} bytes for 10k chunks and coverage keys"


def test_catalog_retains_completed_table_prefix_after_source_error():
    source = _catalog_query(1)

    def query(sql):
        if sql == "SHOW DATABASES":
            return [], "catalog connection reset"
        rows, error = source(sql)
        if "FROM system.tables " in sql:
            return rows, "catalog connection reset"
        return rows, error

    tables, errors = collect_inventory(query)
    assert len(tables) == 1
    assert tables[0].full_name == "app.t00000"
    assert tables[0].columns[0].name == "c00000"
    assert any("system.tables" in error and "catalog connection reset" in error for error in errors)


def test_checkpoint_preserves_long_unknown_object_key_on_resume_and_update(tmp_path):
    from redposture_core.discovery_values import iter_json_chunks

    full_key = "catalog_" + "q" * 5000
    original = {
        "schema_version": 1,
        "targets": {
            "qa:9000": {
                "chunks": {},
                "findings": {},
                "coverage": {},
                "future": {full_key: {"kept": 17}},
            }
        },
    }
    path = tmp_path / "long-key.json"
    path.write_text(json.dumps(original))
    store = CheckpointStore(path, "qa:9000", resume=True)
    state = store.target_state()
    assert state["future"][full_key]["kept"] == 17
    assert json.loads("".join(iter_json_chunks(state["future"]))) == {full_key: {"kept": 17}}
    store.update(status="partial")
    original["targets"]["qa:9000"]["status"] = "partial"
    assert json.loads(path.read_text()) == original


def test_catalog_disk_object_key_matches_full_string_and_survives_source_close():
    from redposture_core.discovery_values import iter_json_chunks
    from redposture_core.json_stream import DiskJSONKey
    from redposture_core.modules.clickhouse.discover.catalog import CatalogTree

    full_key = "catalog_" + "q" * 5000
    source = DiskJSONKey()
    source.append_text(full_key)
    source.finish()
    values = CatalogTree().mapping()
    try:
        values[source] = "before"
        assert values[full_key] == "before"
        values[full_key] = "after"
        assert len(values) == 1
        assert values[source] == "after"
    finally:
        source.close()
    assert json.loads("".join(iter_json_chunks(values))) == {full_key: "after"}
    assert values == {full_key: "after"}


def test_catalog_conversion_honors_discovery_deadline_and_keeps_processed_prefix(monkeypatch):
    from types import SimpleNamespace

    from redposture_core.modules.clickhouse.discover import engine

    clock = [0.0]
    consumed = 0
    monkeypatch.setattr(engine.time, "monotonic", lambda: clock[0])

    def table_rows():
        nonlocal consumed
        for number in range(10_000):
            consumed += 1
            clock[0] += 1.0
            yield ["app", f"t{number:05d}", "MergeTree", "", "", "", 0, 0]

    def query(sql):
        if "FROM system.tables " in sql:
            return table_rows(), None
        return [], None

    report = engine.run_discovery(
        SimpleNamespace(),
        host="qa",
        port=9000,
        config=engine.DiscoverConfig(max_seconds=3),
        query_rows=query,
    )
    assert consumed <= 4, f"consumed {consumed} catalog rows after deadline"
    assert 0 < report["tables_inventory_count"] <= 3
    assert [table["table"] for table in report["inventory"]] == [
        f"t{number:05d}" for number in range(report["tables_inventory_count"])
    ]
    assert report["status"] == "partial"
    assert "discover_time" in report["partial_reasons"]


def test_engine_checkpoint_import_stops_before_next_block_without_rewriting(tmp_path, monkeypatch):
    from types import SimpleNamespace

    import pytest

    from redposture_core.modules.clickhouse.discover import engine
    from redposture_core.modules.clickhouse.discover.catalog import CatalogDocument

    path = tmp_path / "large-deadline.json"
    original = json.dumps(
        {
            "schema_version": 1,
            "targets": {
                "qa:9000": {
                    "chunks": {},
                    "findings": {},
                    "coverage": {},
                    "future": "q" * 120_000,
                }
            },
        }
    )
    path.write_text(original)
    clock = [0.0]
    feeds = 0
    real_feed = CatalogDocument.feed
    monkeypatch.setattr(engine.time, "monotonic", lambda: clock[0])

    def feed(document, portion):
        nonlocal feeds
        feeds += 1
        real_feed(document, portion)
        clock[0] = 3.0

    monkeypatch.setattr(CatalogDocument, "feed", feed)
    with pytest.raises(TimeoutError, match="discover_time"):
        engine.run_discovery(
            SimpleNamespace(),
            host="qa",
            port=9000,
            config=engine.DiscoverConfig(checkpoint=path, resume=True, max_seconds=3),
            query_rows=lambda _: ([], None),
        )
    assert feeds == 1
    assert path.read_text() == original
