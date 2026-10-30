"""ClickHouse discovery must not retain every finding between bounded chunks."""

from __future__ import annotations

import re
import tracemalloc
from types import SimpleNamespace

from redposture_core.modules.clickhouse.discover import engine
from redposture_core.modules.clickhouse.discover.models import ColumnInventory, TableInventory
from redposture_core.modules.clickhouse.discover.reader import ReadResult


def test_clickhouse_range_planning_does_not_materialize_all_chunks() -> None:
    from itertools import islice

    table = TableInventory("app", "events", total_rows=50_000)
    tracemalloc.start()
    try:
        planned = engine._planned_chunks(table, ("payload",), 1)
        first = list(islice(planned, 3))
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert [(item.offset, item.limit) for item in first] == [(0, 1), (1, 1), (2, 1)]
    assert peak < 256_000, f"range planning retained {peak} bytes before the first query"


def test_clickhouse_serial_scan_reads_before_planning_every_range(monkeypatch) -> None:
    table = TableInventory(
        "app", "events", total_rows=100, columns=[ColumnInventory("app", "events", "payload", "String", 1)]
    )
    monkeypatch.setattr(engine, "collect_inventory", lambda query: ([table], []))
    original = engine.ScanChunk
    constructed = 0
    first_read_after = []

    def construct(*args, **kwargs):
        nonlocal constructed
        constructed += 1
        return original(*args, **kwargs)

    def read(*args, **kwargs):
        if not first_read_after:
            first_read_after.append(constructed)
        return ReadResult([["ordinary"]], 8)

    monkeypatch.setattr(engine, "ScanChunk", construct)
    monkeypatch.setattr(engine, "read_chunk", read)
    report = engine.run_discovery(
        SimpleNamespace(),
        host="qa",
        port=9000,
        config=engine.DiscoverConfig(chunk_rows=1, max_seconds=30),
        query_rows=lambda query: ([], None),
    )
    assert report["status"] == "complete" and report["coverage"]["app.events.payload"]["completed_chunks"] == 100
    assert first_read_after[0] <= 2, first_read_after


def test_many_clickhouse_findings_stay_bounded_across_chunks(monkeypatch) -> None:
    count = 20_000
    table = TableInventory(
        "app", "events", total_rows=count, columns=[ColumnInventory("app", "events", "payload", "String", 1)]
    )
    monkeypatch.setattr(engine, "collect_inventory", lambda query: ([table], []))

    def read(_session, query, **kwargs):
        limit, offset = map(int, re.search(r"LIMIT (\d+) OFFSET (\d+)", query).groups())
        rows = [[f'password="secret-{number:08d}"'] for number in range(offset, min(offset + limit, count))]
        return ReadResult(rows, sum(len(row[0]) for row in rows))

    monkeypatch.setattr(engine, "read_chunk", read)
    published = 0

    def publish(_chunk, findings):
        nonlocal published
        published += len(findings)

    tracemalloc.start()
    try:
        report = engine.run_discovery(
            SimpleNamespace(),
            host="qa",
            port=9000,
            config=engine.DiscoverConfig(chunk_rows=250, max_seconds=900, detectors=("password",)),
            query_rows=lambda query: ([], None),
            on_chunk_findings=publish,
        )
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert report["status"] == "complete"
    assert report["finding_count"] == published == count
    assert report["occurrence_count"] == count
    assert len(report["findings"]) == count
    assert all(
        item["locations"][0]["row_offset"] == int(item["value"].removeprefix("secret-")) for item in report["findings"]
    )
    assert peak < 12_000_000, f"ClickHouse retained {peak} bytes across chunks"


def test_clickhouse_finding_storage_failure_keeps_completed_prefix_and_reports_partial(monkeypatch) -> None:
    from redposture_core.modules.clickhouse.discover.findings import FindingStore

    class FailingStore(FindingStore):
        def __setitem__(self, key, value):
            if value["value"] == "second-secret":
                raise OSError("database full")
            super().__setitem__(key, value)

    monkeypatch.setattr(engine, "FindingStore", FailingStore)
    table = TableInventory(
        "app", "events", total_rows=2, columns=[ColumnInventory("app", "events", "password", "String", 1)]
    )
    monkeypatch.setattr(engine, "collect_inventory", lambda query: ([table], []))
    monkeypatch.setattr(engine, "read_chunk", lambda *a, **kw: ReadResult([["first-secret"], ["second-secret"]], 25))
    report = engine.run_discovery(
        SimpleNamespace(),
        host="qa",
        port=9000,
        config=engine.DiscoverConfig(max_seconds=30, detectors=("password",)),
        query_rows=lambda q: ([], None),
    )
    assert report["status"] == "partial"
    assert report["finding_count"] == 1
    assert report["findings"][0]["value"] == "first-secret"
    assert report["coverage"]["app.events.password"]["scan_error"] == "database full"


def test_clickhouse_finding_store_full_preserves_previous_value_and_sort_order() -> None:
    import pytest

    from redposture_core.modules.clickhouse.discover.findings import FindingStore

    values = FindingStore({"password:b": {"type": "password", "fingerprint": "b", "value": "kept-secret"}})
    db = values._db
    pages = db.execute("PRAGMA page_count").fetchone()[0]
    db.execute(f"PRAGMA max_page_count={pages}")
    with pytest.raises(OSError, match="storage failure"):
        values["password:c"] = {"type": "password", "fingerprint": "c", "value": "Ab0" * 20000}
    assert len(values) == 1
    assert values["password:b"]["value"] == "kept-secret"
    assert list(values.created_after(0))[0]["value"] == "kept-secret"
    assert list(values.created_after(1)) == []
    assert list(values.sorted_values())[0]["value"] == "kept-secret"


def test_clickhouse_keyed_findings_preserve_mutable_locations_and_new_only_callback() -> None:
    from redposture_core.modules.clickhouse.discover.findings import FindingStore
    from redposture_core.modules.clickhouse.discover.models import ScanChunk

    findings = FindingStore()
    coverage = {"app.events.password": {"rows_scanned": 0, "bytes_scanned": 0}}
    for offset in (0, 1, 1):
        assert engine._scan_rows(
            [["same-secret"]],
            ScanChunk("app", "events", ("password",), None, offset, 1),
            findings,
            coverage,
            enabled=("password",),
            redact=False,
        )
    assert len(findings) == 1
    value = next(iter(findings.values()))
    assert value["occurrences"] == value["location_count"] == 2
    assert [loc["row_offset"] for loc in value["locations"]] == [0, 1]
    assert len(findings.created_after(0)) == 1 and len(findings.created_after(1)) == 0
