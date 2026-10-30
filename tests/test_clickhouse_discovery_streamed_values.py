from __future__ import annotations

import base64
import gc
import gzip
import hashlib
import json
import time
import tracemalloc
import weakref
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.discovery_values import DiskBackedText
from redposture_core.modules.clickhouse import actions, stage
from redposture_core.modules.clickhouse.discover import DiscoverConfig, run_discovery
from redposture_core.modules.clickhouse.discover.checkpoint import CheckpointStore
from redposture_core.modules.clickhouse.discover.engine import _initial_finding, _scan_rows
from redposture_core.modules.clickhouse.discover.models import ScanChunk
from redposture_core.modules.clickhouse.discover.reader import _estimate_bytes, read_chunk
from redposture_core.stage_runtime import AuditCommandPlan, AuditCommandRunner, AuditRecord, ModuleAuditSpec


def _text(value: Any) -> str:
    return "".join(value.iter_text_chunks()) if isinstance(value, DiskBackedText) else value


@pytest.mark.parametrize("shape", ["json", "xml", "gzip", "assignment", "column"])
def test_clickhouse_large_scalar_retains_complete_value_and_location(shape: str) -> None:
    secret = "Sa7-кириллица/" * 12_000
    column = "password" if shape == "column" else "payload"
    if shape == "json":
        raw = json.dumps({"password": secret}, ensure_ascii=False)
    elif shape == "xml":
        raw = f"<root><password>{secret}</password></root>"
    elif shape == "gzip":
        raw = base64.b64encode(gzip.compress(json.dumps({"password": secret}).encode())).decode()
    elif shape == "assignment":
        raw = f'password="{secret}"'
    else:
        raw = secret
    coverage = {f"app.events.{column}": {"rows_scanned": 0, "bytes_scanned": 0}}
    findings: dict[str, Any] = {}
    _scan_rows(
        [[raw]],
        ScanChunk("app", "events", (column,), None, 7, 1),
        findings,
        coverage,
        enabled=("password",),
        redact=False,
    )
    assert len(findings) == 1
    finding = next(iter(findings.values()))
    assert _text(finding["value"]) == secret
    assert isinstance(finding["value"], DiskBackedText)
    assert finding["fingerprint"] == hashlib.sha256(secret.encode()).hexdigest()
    assert finding["locations"][0]["row_offset"] == 7
    assert finding["locations"][0]["column"] == column


def test_clickhouse_byte_count_does_not_copy_whole_unicode_scalar() -> None:
    raw = "Ж" * 10_000_000
    tracemalloc.start()
    try:
        assert _estimate_bytes([raw]) == 20_000_000
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 4_000_000


def test_checkpoint_roundtrip_keeps_long_secret_on_disk(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    secret = "Sa7-кириллица/" * 20_000
    value = DiskBackedText()
    value.append_text(secret)
    value.finish()
    store = CheckpointStore(path, "host:9000", resume=False)
    store.update(findings={"password:sha": {"value": value, "locations": [{"column": "payload"}]}})
    # Persistent JSON must remain standalone, without ephemeral file references.
    assert json.loads(path.read_text())["targets"]["host:9000"]["findings"]["password:sha"]["value"] == secret
    value.close()
    restored = CheckpointStore(path, "host:9000", resume=True).target_state()["findings"]["password:sha"]
    assert isinstance(restored["value"], DiskBackedText)
    assert _text(restored["value"]) == secret
    assert restored["locations"][0]["column"] == "payload"


def test_clickhouse_checkpoint_read_does_not_retain_private_value_copies_until_gc(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    store = CheckpointStore(path, "host:9000", resume=False)
    store.update(findings={"one": {"value": "Sa7/" * 30_000}})
    enabled = gc.isenabled()
    gc.disable()
    try:
        state = store.target_state()
        value = state["findings"]["one"]["value"]
        reference = weakref.ref(value)
        del value, state
        assert reference() is None
    finally:
        if enabled:
            gc.enable()
        gc.collect()


def test_clickhouse_reader_portion_is_not_a_single_value_limit() -> None:
    raw = "Sa7-кириллица/" * 12_000
    client = SimpleNamespace(execute_iter=lambda _: iter([(raw,)]))
    result = read_chunk(SimpleNamespace(protocol="native", client=client), "SELECT value", max_bytes=1024)
    assert len(result.rows) == 1
    assert _text(result.rows[0][0]) == raw
    assert isinstance(result.rows[0][0], DiskBackedText)


def test_clickhouse_reader_does_not_accumulate_a_chunk_in_memory() -> None:
    def rows():
        for i in range(100):
            yield (f"row-{i}:" + "Sa7-кириллица/" * 12_000,)

    client = SimpleNamespace(execute_iter=lambda _: rows())
    tracemalloc.start()
    try:
        result = read_chunk(SimpleNamespace(protocol="native", client=client), "SELECT value")
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert len(result.rows) == 100
    assert _text(result.rows[-1][0]).startswith("row-99:")
    assert peak < 4_000_000


def test_clickhouse_default_query_has_no_source_byte_limit() -> None:
    assert DiscoverConfig().max_query_bytes == 0


def test_clickhouse_cli_does_not_restore_legacy_64mib_query_limit() -> None:
    args = parse_args(["clickhouse", "-t", "127.0.0.1:9000", "--discover"])
    options = stage._build_clickhouse_host_stage_options(args)
    assert options["discover_max_query_bytes"] == 0


def test_clickhouse_default_does_not_impose_a_256mib_server_memory_limit() -> None:
    assert DiscoverConfig().max_memory is None
    args = parse_args(["clickhouse", "-t", "127.0.0.1:9000", "--discover"])
    assert stage._build_clickhouse_host_stage_options(args)["discover_max_memory"] is None


def test_clickhouse_detector_selection_preserves_column_context() -> None:
    raw = "sk_live_1234567890abcdefghijkl"
    findings: dict[str, Any] = {}
    coverage = {"app.events.password": {"rows_scanned": 0, "bytes_scanned": 0}}
    _scan_rows(
        [[raw]],
        ScanChunk("app", "events", ("password",), None, 0, 1),
        findings,
        coverage,
        enabled=("password",),
        redact=False,
    )
    assert [item["value"] for item in findings.values()] == [raw]


def test_clickhouse_checkpoint_finding_can_add_new_locations(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    store = CheckpointStore(path, "host:9000", resume=False)
    coverage = {"app.events.payload": {"rows_scanned": 0, "bytes_scanned": 0}}
    findings: dict[str, Any] = {}
    _scan_rows(
        [["password=secret-value-123"]],
        ScanChunk("app", "events", ("payload",), None, 0, 1),
        findings,
        coverage,
        enabled=("password",),
        redact=False,
    )
    store.update(findings=findings)
    restored = {key: _initial_finding(item) for key, item in store.target_state()["findings"].items()}
    _scan_rows(
        [["password=secret-value-123"]],
        ScanChunk("app", "events", ("payload",), None, 1, 1),
        restored,
        coverage,
        enabled=("password",),
        redact=False,
    )
    finding = next(iter(restored.values()))
    assert finding["occurrences"] == 2
    assert [location["row_offset"] for location in finding["locations"]] == [0, 1]


def test_clickhouse_local_scan_obeys_target_deadline() -> None:
    findings: dict[str, Any] = {}
    coverage = {"app.events.payload": {"rows_scanned": 0, "bytes_scanned": 0}}
    _scan_rows(
        [["password=" + "Sa7/" * 100_000]],
        ScanChunk("app", "events", ("payload",), None, 0, 1),
        findings,
        coverage,
        enabled=("password",),
        redact=False,
        deadline=time.monotonic() - 1,
    )
    assert not findings
    assert coverage["app.events.payload"]["scan_incomplete"] is True


def test_clickhouse_disk_failure_preserves_completed_rows_and_partial_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    original = DiskBackedText.append_text

    def full_disk(self, text):
        if "disk-full-marker" in text:
            raise OSError("No space left on device")
        return original(self, text)

    monkeypatch.setattr(DiskBackedText, "append_text", full_disk)
    coverage = {"app.events.payload": {"rows_scanned": 0, "bytes_scanned": 0}}
    findings: dict[str, Any] = {}
    complete = _scan_rows(
        [
            ["password=first-secret-123"],
            ["disk-full-marker " + "Sa7/" * 100_000],
            ["password=last-secret-456"],
        ],
        ScanChunk("app", "events", ("payload",), None, 0, 3),
        findings,
        coverage,
        enabled=("password",),
        redact=False,
    )
    assert complete is False
    assert {item["value"] for item in findings.values()} == {"first-secret-123", "last-secret-456"}
    assert coverage["app.events.payload"]["scan_incomplete"] is True
    assert "No space" in coverage["app.events.payload"]["scan_error"]


def test_clickhouse_partial_local_scan_is_not_a_completed_resume_chunk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from redposture_core.modules.clickhouse.discover import engine

    def inventory(query):
        if "FROM system.tables" in query:
            return [["app", "events", "Memory", "", "", "", 1, 100]], None
        if "FROM system.columns" in query:
            return [["app", "events", "payload", "String", 1, 100, 100]], None
        return [], None

    real_scan = engine._scan_portioned_value

    def incomplete(*args, **kwargs):
        matches, size, _ = real_scan(*args, **kwargs)
        return matches, size, False

    monkeypatch.setattr(engine, "_scan_portioned_value", incomplete)
    checkpoint = tmp_path / "state.json"
    session = SimpleNamespace(
        protocol="native", client=SimpleNamespace(execute_iter=lambda _: iter([("password=secret-value-123",)]))
    )
    config = DiscoverConfig(checkpoint=checkpoint, chunk_rows=1, detectors=("password",))
    first = run_discovery(session, host="host", port=9000, config=config, query_rows=inventory)
    assert first["status"] == "partial"
    assert first["finding_count"] == 1
    assert first["coverage_percent"] < 100
    store = CheckpointStore(checkpoint, "host:9000", resume=True)
    chunk = ScanChunk("app", "events", ("payload",), None, 0, 1)
    assert not store.is_complete(chunk.chunk_id)
    monkeypatch.setattr(engine, "_scan_portioned_value", real_scan)
    resumed = run_discovery(
        session,
        host="host",
        port=9000,
        config=DiscoverConfig(checkpoint=checkpoint, resume=True, chunk_rows=1, detectors=("password",)),
        query_rows=inventory,
    )
    assert resumed["status"] == "complete"
    assert resumed["findings"][0]["occurrences"] == 1


@pytest.mark.parametrize("output_format", ["txt", "json"])
def test_clickhouse_runtime_writes_full_disk_finding(tmp_path: Path, capsys: Any, output_format: str) -> None:
    secret = "Sa7-кириллица/" * 12_000
    value = DiskBackedText()
    value.append_text(secret)
    value.finish()
    finding = {
        "type": "password",
        "value": value,
        "confidence": "high",
        "locations": [{"database": "app", "table": "events", "column": "payload", "object_path": "$.password"}],
    }
    report = {"status": "complete", "coverage_percent": 100.0, "finding_count": 1, "findings": [finding]}

    def detect(ctx):
        return AuditRecord(
            host=ctx.host, port=ctx.port, module="clickhouse", service="clickhouse", status="open_no_auth"
        )

    def data(ctx, record):
        return AuditRecord.from_mapping(
            {**record.to_dict(), "discover_requested": True, "discover_report": report},
            module="clickhouse",
            service="clickhouse",
        )

    def render(record):
        return actions._format_discover_detail_records(record.to_dict(), "txt")

    output = tmp_path / f"result.{output_format}"
    lines: list[str] = []
    runner = AuditCommandRunner(
        args=SimpleNamespace(discover=True, debug=False, no_color=True),
        spec=ModuleAuditSpec(
            module="clickhouse",
            label="CLICKHOUSE",
            default_port=9000,
            detect=detect,
            data=data,
            render=render,
            deep_gate=lambda _: (True, "run"),
            is_detected=lambda _: True,
        ),
        emit_line=lines.append,
    )
    result = runner.run_plan(
        AuditCommandPlan(
            targets_by_port={9000: ("127.0.0.1",)}, output_path=str(output), output_format=output_format, workers=1
        )
    )
    assert result.record_count == 1
    text = output.read_text()
    assert "\x1b[" not in text
    assert "DiskBackedText object" not in text
    if output_format == "txt":
        findings = [line for line in text.splitlines() if " Value=" in line]
        assert len(findings) == 1
        found, _ = json.JSONDecoder().raw_decode(findings[0].split(" Value=", 1)[1])
        assert found == secret
        assert 'Place="app.events.payload$.password"' in findings[0]
        assert secret in capsys.readouterr().out
    else:
        assert json.loads(text)["discover_report"]["findings"][0]["value"] == secret
