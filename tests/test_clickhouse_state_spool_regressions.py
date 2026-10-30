"""Preserve bounded partial rows, continuation state, and owned finding fields."""

from __future__ import annotations

import gc
import json
import re
import tracemalloc
import weakref
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.discovery_containers import DiskSequence
from redposture_core.discovery_spool import SpoolingValues
from redposture_core.discovery_values import DiskBackedText, iter_json_chunks
from redposture_core.modules.clickhouse.discover import engine
from redposture_core.modules.clickhouse.discover.findings import FindingStore
from redposture_core.modules.clickhouse.discover.models import ColumnInventory, TableInventory
from redposture_core.modules.clickhouse.discover.native_values import NativeValues
from redposture_core.modules.clickhouse.discover.reader import ReadResult


@pytest.mark.parametrize("shape", ["spool", "container", "text"])
def test_finding_store_restores_owned_nested_metadata_after_caller_cleanup(shape):
    nested: Any
    expected: object
    if shape == "spool":
        nested = SpoolingValues()
        nested.append({"offset": 3})
        expected = [{"offset": 3}]
    elif shape == "container":
        owner = NativeValues()
        nested = owner.view(owner.scalar({"offset": 3}))
        expected = {"offset": 3}
        del owner
    else:
        nested = DiskBackedText()
        nested.append_text("exact metadata")
        nested.finish()
        expected = "exact metadata"
    store = FindingStore()
    store["password:qa"] = {"type": "password", "fingerprint": "qa", "value": "known-secret", "metadata": nested}
    del nested
    gc.collect()
    actual = store["password:qa"]["metadata"]
    assert json.loads("".join(iter_json_chunks(actual))) == expected


def test_partial_rows_are_scanned_without_copying_the_entire_prefix(monkeypatch):
    count = 10_000

    class Rows(DiskSequence):
        def __len__(self):
            return count

        def __iter__(self):
            for number in range(count):
                yield [
                    "password=first-secret"
                    if number == 0
                    else "password=last-secret"
                    if number == count - 1
                    else "ordinary"
                ]

    table = TableInventory(
        "qa", "events", total_rows=count, columns=[ColumnInventory("qa", "events", "payload", "String", 1)]
    )
    monkeypatch.setattr(engine, "collect_inventory", lambda query: ([table], []))
    bytes_read = 8 * (count - 2) + len("password=first-secret") + len("password=last-secret")
    monkeypatch.setattr(
        engine, "read_chunk", lambda *args, **kwargs: ReadResult(Rows(), bytes_read, "connection reset")
    )
    scan = engine._scan_rows

    def guarded_scan(*args, **kwargs):
        peak = tracemalloc.get_traced_memory()[1]
        assert peak < 256_000, f"partial prefix copied {peak} Python bytes before scanning"
        return scan(*args, **kwargs)

    monkeypatch.setattr(engine, "_scan_rows", guarded_scan)
    tracemalloc.start()
    try:
        report = engine.run_discovery(
            SimpleNamespace(),
            host="qa",
            port=9000,
            config=engine.DiscoverConfig(chunk_rows=count, detectors=("password",)),
            query_rows=lambda query: ([], None),
        )
    finally:
        tracemalloc.stop()
    assert report["status"] == "partial" and report["bytes_scanned"] == bytes_read
    assert {item["value"] for item in report["findings"]} == {"first-secret", "last-secret"}
    assert {item["locations"][0]["row_offset"] for item in report["findings"]} == {0, count - 1}


def test_completed_portion_originals_are_released_before_later_ranges(monkeypatch):
    count = 20
    table = TableInventory(
        "qa", "events", total_rows=count, columns=[ColumnInventory("qa", "events", "payload", "String", 1)]
    )
    monkeypatch.setattr(engine, "collect_inventory", lambda query: ([table], []))
    originals = []
    construct = engine.ScanChunk
    scanned = []

    def chunk(*args, **kwargs):
        value = construct(*args, **kwargs)
        if value.limit == 2:
            originals.append(weakref.ref(value))
        return value

    def read(session, query, **kwargs):
        limit, offset = map(int, re.search(r"LIMIT (\d+) OFFSET (\d+)", query).groups())
        gc.collect()
        if offset >= 6:
            alive = sum(reference() is not None for reference in originals)
            assert alive <= 2, f"retained {alive} originals from completed ranges"
        scanned.append(offset)
        value = f"password=secret-{offset:04d}"
        return ReadResult([[value]], len(value), "discover_max_bytes" if limit > 1 else None)

    monkeypatch.setattr(engine, "ScanChunk", chunk)
    monkeypatch.setattr(engine, "read_chunk", read)
    report = engine.run_discovery(
        SimpleNamespace(),
        host="qa",
        port=9000,
        config=engine.DiscoverConfig(chunk_rows=2, detectors=("password",)),
        query_rows=lambda query: ([], None),
    )
    assert report["status"] == "complete" and report["finding_count"] == count
    assert scanned == list(range(count))
