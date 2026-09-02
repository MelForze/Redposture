from __future__ import annotations

import json
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.cli import parse_args
from redposture_core.modules.clickhouse import actions, policy
from redposture_core.modules.clickhouse.discover import DiscoverConfig, run_discovery
from redposture_core.modules.clickhouse.discover.checkpoint import CheckpointStore
from redposture_core.modules.clickhouse.discover.inventory import (
    collect_inventory,
    is_content_type,
    quote_identifier,
    quote_literal,
)
from redposture_core.modules.clickhouse.discover.models import ScanChunk
from redposture_core.modules.clickhouse.discover.reader import build_chunk_query, read_chunk
from redposture_core.secret_detection import detector_names, fingerprint, mask_secret, scan_value


class _NativeClient:
    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        self.rows = rows
        self.queries: list[str] = []

    def execute_iter(self, query: str):
        self.queries.append(query)
        yield from self.rows


def _session(rows: list[tuple[Any, ...]]) -> Any:
    return SimpleNamespace(protocol="native", client=_NativeClient(rows))


def _inventory_query(query: str) -> tuple[list[list[Any]] | None, str | None]:
    if "FROM system.tables" in query:
        return [["app", "events", "MergeTree", "toYYYYMM(ts)", "ts", "ts", 2, 1024]], None
    if "FROM system.columns" in query:
        return [
            ["app", "events", "id", "UInt64", 1, 8, 8],
            ["app", "events", "payload", "String", 2, 128, 256],
            ["app", "events", "labels", "Map(String, String)", 3, 64, 128],
        ], None
    if "FROM system.parts_columns" in query:
        return [
            ["app", "events", "payload", 128, 256],
            ["app", "events", "labels", 64, 128],
        ], None
    if "FROM system.parts" in query:
        return [["app", "events", "202609", 2, 1024, 1, 1]], None
    raise AssertionError(query)


def test_detector_engine_handles_nested_json_neutral_column_and_dedup_material() -> None:
    value = json.dumps(
        {
            "neutral": {"client_secret": "super-secret-value-123"},
            "headers": {"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature"},
        }
    )
    matches = scan_value(value)
    assert {match.detector for match in matches} >= {"client_secret", "bearer_token", "jwt"}
    assert any(match.object_path == "$.neutral.client_secret" for match in matches)
    assert fingerprint("same") == fingerprint("same")
    assert mask_secret("super-secret-value-123") != "super-secret-value-123"


@pytest.mark.parametrize(
    ("type_name", "expected"),
    [
        ("String", True),
        ("Nullable(LowCardinality(String))", True),
        ("Array(FixedString(32))", True),
        ("Map(String, Array(Nullable(String)))", True),
        ("JSON", True),
        ("UInt64", False),
        ("Array(UInt32)", False),
    ],
)
def test_content_type_selection_is_schema_aware(type_name: str, expected: bool) -> None:
    assert is_content_type(type_name) is expected


def test_chunk_query_has_partition_and_resource_settings() -> None:
    query = build_chunk_query(
        ScanChunk("app", "events", ("payload", "labels"), "202609", 10, 5),
        max_query_time=3.0,
        max_query_rows=100,
        max_query_bytes=2048,
        max_memory=4096,
        max_threads=1,
    )
    assert "_partition_id='202609'" in query
    assert "LIMIT 5 OFFSET 10" in query
    assert "max_execution_time=3.0" in query
    assert "max_bytes_to_read=2048" in query
    assert "max_memory_usage=4096" in query
    assert "max_threads=1" in query


def test_native_reader_streams_without_execute_materialization() -> None:
    session = _session([("a",), ("b",)])
    result = read_chunk(session, "SELECT payload")
    assert result.error is None
    assert result.rows == [["a"], ["b"]]
    assert session.client.queries == ["SELECT payload"]


def test_inventory_catalog_sizes_partitions_and_fallbacks() -> None:
    tables, errors = collect_inventory(_inventory_query)
    assert errors == []
    assert tables[0].full_name == "app.events"
    assert tables[0].partitions[0]["partition_id"] == "202609"
    assert tables[0].columns[1].uncompressed_bytes == 256
    assert quote_identifier("odd`name") == "`odd``name`"
    assert quote_literal("a'b") == "'a\\'b'"

    def fallback(query: str):
        if "system.tables" in query:
            return None, "denied"
        if query == "SHOW DATABASES":
            return [["app"]], None
        if query == "SHOW TABLES FROM `app`":
            return [["events"]], None
        if query == "DESCRIBE TABLE `app`.`events`":
            return [["payload", "Nullable(String)"], ["id", "UInt64"]], None
        raise AssertionError(query)

    fallback_tables, fallback_errors = collect_inventory(fallback)
    assert fallback_tables[0].columns[0].type_name == "Nullable(String)"
    assert fallback_errors == ["system.tables: denied"]


def test_inventory_permission_errors_are_preserved_per_catalog() -> None:
    def denied(query: str):
        if "system.tables" in query:
            return [["app", "events", "Memory", "", "", "", None, None]], None
        if "system.columns" in query:
            return None, "columns denied"
        if query.startswith("DESCRIBE"):
            return None, "describe denied"
        if "system.parts_columns" in query:
            return None, "parts columns denied"
        if "system.parts" in query:
            return None, "parts denied"
        raise AssertionError(query)

    tables, errors = collect_inventory(denied)
    assert tables[0].inventory_errors == ["describe denied"]
    assert any("system.columns" in error for error in errors)
    assert any("system.parts_columns" in error for error in errors)
    assert any("system.parts:" in error for error in errors)


def test_reader_http_stream_fallbacks_and_errors() -> None:
    class Stream:
        def __enter__(self):
            return iter([("one",), ("two",)])

        def __exit__(self, *_args):
            return None

    http_stream = SimpleNamespace(protocol="http", client=SimpleNamespace(query_rows_stream=lambda _query: Stream()))
    assert read_chunk(http_stream, "SELECT x").rows == [["one"], ["two"]]

    http_fallback = SimpleNamespace(
        protocol="http",
        client=SimpleNamespace(query=lambda _query: SimpleNamespace(result_rows=[("fallback",)])),
    )
    assert read_chunk(http_fallback, "SELECT x").rows == [["fallback"]]

    native_fallback = SimpleNamespace(
        protocol="native",
        client=SimpleNamespace(execute=lambda _query: [("native",)]),
    )
    assert read_chunk(native_fallback, "SELECT x").rows == [["native"]]

    failing = SimpleNamespace(
        protocol="native",
        client=SimpleNamespace(execute=lambda _query: (_ for _ in ()).throw(RuntimeError("broken"))),
    )
    assert read_chunk(failing, "SELECT x").error == "broken"


def test_discovery_inventory_scan_checkpoint_and_resume(tmp_path: Path) -> None:
    checkpoint = tmp_path / "discover.json"
    secret = "sk_live_1234567890abcdefghijkl"
    session = _session(
        [
            (json.dumps({"client_secret": secret}), {"cookie": "session-id-123456789"}),
            (f"duplicate {secret}", {"neutral": "plain"}),
        ]
    )
    config = DiscoverConfig(checkpoint=checkpoint, chunk_rows=2, detectors=("stripe_key", "generic_secret"))
    report = run_discovery(
        session,
        host="127.0.0.1",
        port=9000,
        config=config,
        query_rows=_inventory_query,
    )
    assert report["status"] == "complete"
    assert report["coverage_percent"] == 100.0
    assert report["tables_scanned"] == 1
    stripe = next(item for item in report["findings"] if item["type"] == "stripe_key")
    assert stripe["occurrences"] == 2
    assert stripe["value"] is None
    assert stripe["masked_value"] != secret
    assert checkpoint.exists()
    assert "SELECT `payload`,`labels`" in session.client.queries[0]

    resumed_session = _session([])
    resumed = run_discovery(
        resumed_session,
        host="127.0.0.1",
        port=9000,
        config=DiscoverConfig(
            checkpoint=checkpoint,
            resume=True,
            chunk_rows=2,
            detectors=("stripe_key", "generic_secret"),
        ),
        query_rows=_inventory_query,
    )
    assert resumed["finding_count"] == report["finding_count"]
    assert resumed_session.client.queries == []


def test_checkpoint_is_target_aware_and_atomic(tmp_path: Path) -> None:
    path = tmp_path / "checkpoint.json"
    first = CheckpointStore(path, "a:1", resume=False)
    first.update(chunk_id="chunk", chunk={"status": "complete"})
    second = CheckpointStore(path, "b:2", resume=False)
    second.update(status="partial")
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert set(payload["targets"]) == {"a:1", "b:2"}
    assert first.is_complete("chunk") is True


def test_resource_failure_splits_chunk_without_sampling_or_losing_coverage(tmp_path: Path) -> None:
    class SplitClient:
        def __init__(self) -> None:
            self.queries: list[str] = []

        def execute_iter(self, query: str):
            self.queries.append(query)
            limit = int(re.search(r"LIMIT (\d+)", query).group(1))
            if limit > 1:
                raise RuntimeError("max_execution_time timeout")
            yield ("password=split-secret", {"plain": "value"})

    client = SplitClient()
    report = run_discovery(
        SimpleNamespace(protocol="native", client=client),
        host="127.0.0.1",
        port=9000,
        config=DiscoverConfig(checkpoint=tmp_path / "split.json", chunk_rows=2, detectors=("password",)),
        query_rows=_inventory_query,
    )
    assert report["status"] == "complete"
    assert report["coverage_percent"] == 100.0
    assert len(client.queries) == 3
    assert all("SAMPLE" not in query.upper() for query in client.queries)


def test_permission_error_is_partial_and_never_reports_full_coverage(tmp_path: Path) -> None:
    class DeniedClient:
        def execute_iter(self, _query: str):
            raise RuntimeError("Not enough privileges. Required grant SELECT")
            yield  # pragma: no cover

    report = run_discovery(
        SimpleNamespace(protocol="native", client=DeniedClient()),
        host="127.0.0.1",
        port=9000,
        config=DiscoverConfig(checkpoint=tmp_path / "denied.json", chunk_rows=2),
        query_rows=_inventory_query,
    )
    assert report["status"] == "partial"
    assert report["coverage_percent"] < 100.0
    assert report["scan_errors"][0]["kind"] == "permission_denied"


def test_discover_cli_contract_and_validation(tmp_path: Path) -> None:
    checkpoint = tmp_path / "state.json"
    args = parse_args(
        [
            "clickhouse",
            "-t",
            "127.0.0.1",
            "--discover",
            "--resume",
            "--checkpoint",
            str(checkpoint),
            "--discover-exclude",
            "system.*,logs.noisy",
            "--detectors",
            "jwt,private_key",
        ]
    )

    class Console:
        def __init__(self) -> None:
            self.errors: list[str] = []

        def error(self, message: str) -> None:
            self.errors.append(message)

    console = Console()
    assert policy.validate_args(args, console) is None
    assert args.discover_redact is False
    assert set(args.detectors.split(",")) <= set(detector_names())

    invalid = parse_args(["clickhouse", "-t", "127.0.0.1", "--resume"])
    assert policy.validate_args(invalid, console) == 2
    assert "--resume requires --discover" in console.errors[-1]


def test_discover_txt_renderer_is_compact_masked_and_does_not_clip_values() -> None:
    long_masked_value = "abcd" + ("x" * 120) + "wxyz"
    record = {
        "host": "127.0.0.1",
        "port": 9000,
        "discover_requested": True,
        "discover_report": {
            "status": "complete",
            "coverage_percent": 100.0,
            "tables_scanned": 1,
            "finding_count": 1,
            "occurrence_count": 2,
            "checkpoint": "state.json",
            "scan_errors": [],
            "findings": [
                {
                    "type": "api_key",
                    "confidence": "high",
                    "masked_value": long_masked_value,
                    "value": None,
                    "occurrences": 2,
                    "location_count": 1,
                    "locations": [
                        {"database": "app", "table": "events", "column": "payload", "object_path": "$.token"}
                    ],
                }
            ],
        },
    }
    lines = actions._format_discover_detail_records(record, "txt")
    assert "coverage:100.00%" in lines[0]
    finding_line = next(line for line in lines if " [+] api_key " in line)
    assert f'value="{long_masked_value}"' in finding_line
    assert 'place="app.events.payload$.token"' in finding_line
    assert "confidence" not in finding_line
    assert "occurrences" not in finding_line
    assert "locations" not in finding_line
    assert actions._format_discover_detail_records(record, "json") == []


def test_discover_txt_renderer_json_escapes_full_value_and_place() -> None:
    record = {
        "host": "127.0.0.1",
        "port": 9000,
        "discover_requested": True,
        "discover_report": {
            "status": "complete",
            "findings": [
                {
                    "type": "password",
                    "value": "full value\nwith\ttabs",
                    "locations": [
                        {
                            "database": "app",
                            "table": "events",
                            "column": "payload",
                            "object_path": "$.secret value",
                        }
                    ],
                }
            ],
        },
    }

    finding_line = next(
        line for line in actions._format_discover_detail_records(record, "txt") if " [+] password " in line
    )
    assert 'value="full value\\nwith\\ttabs"' in finding_line
    assert 'place="app.events.payload$.secret value"' in finding_line
    assert "\n" not in finding_line


def test_clickhouse_discover_finding_payload_is_colored_orange() -> None:
    class _Console:
        def __init__(self) -> None:
            self.lines: list[str] = []

        def _paint(self, text: str, color: str, _stream: object) -> str:
            return f"<{color}>{text}</{color}>"

        def plain(self, line: str) -> None:
            self.lines.append(line)

    console = _Console()
    line = 'CLICKHOUSE\t127.0.0.1\t9000\t [+] api_key value="complete" place="app.events.token$"'

    assert actions._render_colored_clickhouse_line(console, line) is True
    assert '<orange>api_key value="complete" place="app.events.token$"</orange>' in console.lines[0]


def _discover_summary_line(*, status: str, coverage: float, findings: int) -> str:
    record = {
        "host": "127.0.0.1",
        "port": 9000,
        "discover_requested": True,
        "discover_report": {
            "status": status,
            "coverage_percent": coverage,
            "tables_scanned": 7,
            "finding_count": findings,
            "occurrence_count": findings * 3,
            "checkpoint": "state.json",
            "findings": [],
            "scan_errors": [],
        },
    }
    return actions._format_discover_detail_records(record, "txt")[0]


def test_discover_summary_places_tables_last() -> None:
    line = _discover_summary_line(status="complete", coverage=100.0, findings=21)
    assert "(status:complete) (coverage:100.00%) (findings:21) (occurrences:63) (tables:7)" in line
    # tables is the final token, occurrences precedes it
    assert line.index("(occurrences:") < line.index("(tables:")


class _ColorConsole:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def _paint(self, text: str, color: str, _stream: object) -> str:
        return f"<{color}>{text}</{color}>"

    def plain(self, line: str) -> None:
        self.lines.append(line)


def test_discover_summary_health_colors_complete_clean() -> None:
    console = _ColorConsole()
    line = _discover_summary_line(status="complete", coverage=100.0, findings=0)
    assert actions._render_colored_clickhouse_line(console, line) is True
    rendered = console.lines[0]
    assert "<bright_green>status:complete</bright_green>" in rendered
    assert "<bright_green>coverage:100.00%</bright_green>" in rendered
    assert "<bright_green>findings:0</bright_green>" in rendered


def test_discover_summary_health_colors_partial_and_findings() -> None:
    console = _ColorConsole()
    line = _discover_summary_line(status="partial", coverage=42.0, findings=21)
    assert actions._render_colored_clickhouse_line(console, line) is True
    rendered = console.lines[0]
    assert "<yellow>status:partial</yellow>" in rendered
    assert "<red>coverage:42.00%</red>" in rendered  # below 50% -> red
    assert "<red>findings:21</red>" in rendered  # anything found -> red


def test_discover_summary_coverage_yellow_band() -> None:
    console = _ColorConsole()
    line = _discover_summary_line(status="partial", coverage=63.5, findings=0)
    assert actions._render_colored_clickhouse_line(console, line) is True
    rendered = console.lines[0]
    assert "<yellow>coverage:63.50%</yellow>" in rendered  # 50..99.99 -> yellow
    assert "<bright_green>findings:0</bright_green>" in rendered


def test_discovery_without_checkpoint_is_in_memory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    session = _session([("sk_live_1234567890abcdefghijkl",)])
    report = run_discovery(
        session,
        host="127.0.0.1",
        port=9000,
        config=DiscoverConfig(chunk_rows=2, detectors=("stripe_key",)),
        query_rows=_inventory_query,
    )
    assert report["status"] == "complete"
    assert report["checkpoint"] is None
    # No --checkpoint path -> nothing is persisted anywhere.
    assert list(tmp_path.iterdir()) == []


def test_discover_summary_omits_checkpoint_line_when_absent() -> None:
    record = {
        "host": "127.0.0.1",
        "port": 9000,
        "discover_requested": True,
        "discover_report": {
            "status": "complete",
            "coverage_percent": 100.0,
            "tables_scanned": 1,
            "finding_count": 0,
            "occurrence_count": 0,
            "checkpoint": None,
            "findings": [],
            "scan_errors": [],
        },
    }
    lines = actions._format_discover_detail_records(record, "txt")
    assert not any("Checkpoint" in line for line in lines)


def test_discover_summary_shows_checkpoint_line_when_present() -> None:
    record = {
        "host": "127.0.0.1",
        "port": 9000,
        "discover_requested": True,
        "discover_report": {
            "status": "complete",
            "coverage_percent": 100.0,
            "tables_scanned": 1,
            "finding_count": 0,
            "occurrence_count": 0,
            "checkpoint": "state.json",
            "findings": [],
            "scan_errors": [],
        },
    }
    lines = actions._format_discover_detail_records(record, "txt")
    assert any(line.endswith("[*] Checkpoint state.json") for line in lines)


def test_resume_requires_checkpoint() -> None:
    args = parse_args(["clickhouse", "-t", "127.0.0.1", "--discover", "--resume"])

    class _Console:
        def __init__(self) -> None:
            self.errors: list[str] = []

        def error(self, message: str) -> None:
            self.errors.append(message)

    console = _Console()
    assert policy.validate_args(args, console) == 2
    assert "--resume requires --checkpoint" in console.errors[-1]
