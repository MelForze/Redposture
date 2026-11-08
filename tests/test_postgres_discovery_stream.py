"""PostgreSQL DataRow discovery reads fields without the ordinary frame cap."""

from __future__ import annotations

import hashlib
import struct
import time
from types import SimpleNamespace

import pytest

from redposture_core.discovery_values import DiskBackedText
from redposture_core.modules.postgres import actions as pg
from redposture_core.storage_discovery import DiscoveryCollector


class Wire:
    def __init__(self, body: bytes):
        self.body = body
        self.position = 0
        self.timeout = 1.0
        self.requested = []

    def recv(self, size):
        self.requested.append(size)
        part = self.body[self.position : self.position + min(size, 8191)]
        self.position += len(part)
        return part

    def gettimeout(self):
        return self.timeout

    def settimeout(self, timeout):
        self.timeout = timeout

    def sendall(self, _body):
        pass


def row(value: bytes):
    payload = struct.pack(">h", 1) + struct.pack(">i", len(value)) + value
    return b"D" + struct.pack(">i", len(payload) + 4) + payload


@pytest.mark.parametrize("denied", [False, True])
def test_table_source_manifest_confirms_even_empty_success_and_denied_sqlstate(denied):
    ready = b"Z\0\0\0\5I"
    error = b"SERROR\0C42501\0Mpermission denied for table settings\0\0"
    wire = Wire((b"E" + struct.pack(">i", len(error) + 4) + error if denied else b"") + ready)
    c = DiscoveryCollector(
        "postgres",
        SimpleNamespace(host="qa", port=5432, args=SimpleNamespace(discover_time=30)),
        {"status": "open_no_auth"},
    )
    _, values, problem = pg._pg_query_table_rows(
        wire, "public.settings", discovery_collector=c, database_name="qa", retain_rows=False
    )
    report = c.result()
    rows = {r["id"]: r for r in report["sources"]}
    table = rows["postgres.table_rows"]
    assert table["read"] == int(not denied) and table["denied"] == int(denied)
    assert table["complete"] == (not denied)
    assert rows["postgres.table_catalog"]["requested"] == 0
    assert bool(problem) == denied
    assert report["status"] == ("unavailable" if denied else "complete")


def test_discovery_reads_large_datarow_field_on_disk_and_keeps_next_frame(monkeypatch):
    monkeypatch.setattr(pg, "_PG_MAX_MESSAGE_SIZE", 1024)
    value = b"qa-long-" + b"Ab0" * 400000
    wire = Wire(row(value) + b"Z\0\0\0\5I")
    seen = []
    rows, error = pg._pg_query_rows(
        wire,
        "SELECT value",
        stream_data_rows=True,
        on_row=lambda item: seen.append(item) or True,
        retain_rows=False,
        deadline=time.monotonic() + 10,
    )
    assert not rows and error is None
    assert isinstance(seen[0][0], DiskBackedText)
    assert seen[0][0].digest == hashlib.sha256(value).hexdigest()
    assert max(wire.requested) <= 65536
    assert wire.position == len(wire.body)


def test_postgres_table_discover_scans_long_json_value_without_materializing(monkeypatch):
    monkeypatch.setattr(pg, "_PG_MAX_MESSAGE_SIZE", 1024)
    value = "qa-long-" + "Ab0" * 400000
    wire = Wire(row(('{"password":"' + value + '"}').encode()) + b"Z\0\0\0\5I")
    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=30), host="qa", port=5432)
    collector = DiscoveryCollector("postgres", ctx, {"status": "open_no_auth"})
    _, rows, error = pg._pg_query_table_rows(
        wire, "public.settings", database_name="app", discovery_collector=collector, retain_rows=False
    )
    assert error is None and not rows
    report = collector.result()
    assert report["status"] == "complete"
    assert len(report["findings"]) == 1
    assert report["findings"][0]["value"].digest == hashlib.sha256(value.encode()).hexdigest()
    assert report["findings"][0]["object_path"] == "$.table.app.public.settings.password"


def test_postgres_streaming_rows_keep_distinct_honest_source_locators():
    from redposture_core.discovery_values import iter_json_chunks

    password = "inactive-repeated-row-password"
    wire = Wire(row(('{"id":7,"password":"' + password + '"}').encode()) * 2 + b"Z\0\0\0\5I")
    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=30), host="qa", port=5432)
    collector = DiscoveryCollector("postgres", ctx, {"status": "open_no_auth"})
    _, _, error = pg._pg_query_table_rows(
        wire, "public.settings", database_name="app", discovery_collector=collector, retain_rows=False
    )
    assert error is None
    import json

    finding = json.loads("".join(iter_json_chunks(collector.result())))["findings"][0]
    assert finding["occurrence_count"] == 2
    assert [item["row_ordinal"] for item in finding["locations"]] == [0, 1]
    assert all(item["database"] == "app" and item["table"] == "public.settings" for item in finding["locations"])
    assert all(item["locator_kind"] == "read_order" and "primary_key" not in item for item in finding["locations"])


def test_streaming_query_keeps_completed_row_when_later_frame_breaks():
    wire = Wire(row(b'{"password":"qa-first-secret"}') + b"D\0\0\0\x1c\0\1\0\0\0\x12broken")
    seen = []
    rows, error = pg._pg_query_rows(
        wire, "SELECT value", stream_data_rows=True, on_row=lambda item: seen.append(item) or True, retain_rows=False
    )
    assert not rows and len(seen) == 1
    assert error and ("EOF" in error or "closed" in error)


@pytest.mark.parametrize("suffix", [b"\0\1\xff\xff\xff\xfe", b"\0\1\0\0\0\x08short"])
def test_invalid_datarow_field_never_reaches_callback(suffix):
    wire = Wire(b"D" + struct.pack(">i", len(suffix) + 4) + suffix)
    seen = []
    with pytest.raises((ValueError, ConnectionError)):
        pg._pg_query_rows(
            wire,
            "SELECT value",
            stream_data_rows=True,
            on_row=lambda item: seen.append(item) or True,
            retain_rows=False,
        )
    assert not seen


def test_explicit_dump_retains_raw_json_disk_value_instead_of_object_repr(monkeypatch):
    import json

    from redposture_core.discovery_spool import SpoolingValues
    from redposture_core.discovery_values import iter_json_chunks

    monkeypatch.setattr(pg, "_PG_MAX_MESSAGE_SIZE", 1024)
    value = "qa-long-" + "Ab0" * 400000
    raw = '{"password":"' + value + '"}'
    wire = Wire(row(raw.encode()) + b"Z\0\0\0\5I")
    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=30), host="qa", port=5432)
    collector = DiscoveryCollector("postgres", ctx, {"status": "open_no_auth"})
    _, rows, error = pg._pg_query_table_rows(
        wire, "public.settings", database_name="app", discovery_collector=collector, retain_rows=True
    )
    assert error is None
    assert isinstance(rows, SpoolingValues)
    assert isinstance(rows[0], DiskBackedText)
    assert json.loads("".join(iter_json_chunks(rows))) == [raw]


def test_large_explicit_dump_txt_streams_full_value_and_escapes_controls(tmp_path):
    from pathlib import Path

    from redposture_core.discovery_spool import SpoolingValues
    from redposture_core.modules.postgres import render

    value = DiskBackedText(directory=tmp_path)
    text = '{"password":"qa-full-λ","note":"' + "n" * 1200000 + '"}\n'
    value.append_text(text)
    value.finish()
    rows = SpoolingValues()
    rows.append(value)
    rows.finish()
    record = {
        "host": "qa",
        "port": 5432,
        "table_dump_enabled": True,
        "table_dumps": [{"table": "public.settings", "rows": rows}],
        "table_names": ["public.settings"],
    }
    path = render.spool_table_dump_details(record)
    try:
        output = Path(path).read_text()
        assert text.rstrip("\n") + r"\n" in output
        assert "DiskBackedText" not in output and "\x1b" not in output
        assert "[*] Dump Table public.settings" in output
    finally:
        Path(path).unlink(missing_ok=True)


def test_postgres_emits_finished_json_field_before_large_datarow_ends():
    body = row(b'{"password":"qa-first-secret","note":"' + b"x" * 1_200_000 + b'"}') + b"Z\0\0\0\5I"
    positions = []
    wire = Wire(body)
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_time=30),
        host="qa",
        port=5432,
        live_emit=lambda line: positions.append(wire.position),
    )
    collector = DiscoveryCollector("postgres", ctx, {"status": "open_no_auth"})
    _, _, error = pg._pg_query_table_rows(
        wire, "public.settings", database_name="app", discovery_collector=collector, retain_rows=False
    )
    assert error is None
    assert positions and positions[0] < 100000, positions
    assert collector.result()["status"] == "complete"


def test_postgres_table_keeps_early_finding_when_same_field_is_interrupted():
    prefix = b'{"password":"qa-first-secret","note":"' + b"x" * 100000
    declared_size = len(prefix) + 500000
    wire = Wire(b"D" + struct.pack(">i", declared_size + 10) + b"\0\1" + struct.pack(">i", declared_size) + prefix)
    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=30), host="qa", port=5432)
    collector = DiscoveryCollector("postgres", ctx, {"status": "open_no_auth"})
    _, _, error = pg._pg_query_table_rows(
        wire, "public.settings", database_name="app", discovery_collector=collector, retain_rows=False
    )
    assert error and "EOF" in error
    report = collector.result()
    assert report["status"] == "partial"
    assert [item["value"] for item in report["findings"]] == ["qa-first-secret"]


@pytest.mark.parametrize("ending", [b"", b"E\0\0\0\x17Mread failed here\0\0Z\0\0\0\5I"])
def test_postgres_returned_read_error_cannot_leave_discovery_complete(ending):
    wire = Wire(row(b'{"password":"qa-first-secret"}') + ending)
    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=30), host="qa", port=5432)
    collector = DiscoveryCollector("postgres", ctx, {"status": "open_no_auth"})
    _, _, error = pg._pg_query_table_rows(
        wire, "public.settings", database_name="app", discovery_collector=collector, retain_rows=False
    )
    assert error
    report = collector.result()
    assert report["status"] == "partial"
    assert [item["value"] for item in report["findings"]] == ["qa-first-secret"]
