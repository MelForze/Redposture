"""Model-based discovery checks that stay cheap enough for the ordinary CI."""

from __future__ import annotations

import json
from urllib.parse import parse_qs, urlsplit

import pytest
from hypothesis import given
from hypothesis import strategies as st

from redposture_core.clients.airflow_api import AirflowResponse
from redposture_core.modules.airflow.discover import DiscoverConfig, _collection, _read_log, discover_task_logs
from redposture_core.modules.clickhouse.discover.inventory import collect_inventory, quote_identifier


def _airflow_response(payload: object, status: int = 200) -> AirflowResponse:
    return AirflowResponse(status, {"Content-Type": "application/json"}, json.dumps(payload).encode())


@given(st.lists(st.text(alphabet="abc123_-", min_size=1, max_size=10), unique=True, max_size=240), st.integers(0, 260))
def test_airflow_collection_matches_independent_offset_model(names: list[str], cap: int) -> None:
    calls: list[int] = []

    class Client:
        def get(self, path: str) -> AirflowResponse:
            query = parse_qs(urlsplit(path).query)
            offset = int(query["offset"][0])
            page_size = int(query["limit"][0])
            calls.append(offset)
            return _airflow_response(
                {
                    "dags": [{"dag_id": value} for value in names[offset : offset + page_size]],
                    "total_entries": len(names),
                }
            )

    result = _collection(Client(), "/api/v1/dags", "dags", cap, None)
    assert [item["dag_id"] for item in result.items] == names[:cap]
    assert calls == sorted(set(calls))
    assert all(next_offset - offset <= 100 for offset, next_offset in zip(calls, calls[1:], strict=False))
    if cap > 0 and cap >= len(names):
        assert result.complete


@given(
    st.lists(st.text(alphabet="abc123 ", max_size=60), max_size=12),
    st.integers(0, 200),
    st.integers(0, 200),
)
def test_airflow_log_stream_never_exceeds_either_byte_budget(chunks: list[str], per_log: int, per_target: int) -> None:
    seen: list[str] = []

    class Client:
        def get(self, path: str, **_kwargs: object) -> AirflowResponse:
            seen.append(path)
            index = len(seen) - 1
            assert index < len(chunks)
            token = str(index + 1) if index + 1 < len(chunks) else None
            return _airflow_response({"content": chunks[index], "continuation_token": token})

    # An empty stream still has one legitimate terminal response.
    pages = chunks or [""]
    client = Client()
    if not chunks:
        chunks = pages
    value, used, reason = _read_log(
        client,
        "/api/v1/dags/example/logs/1",
        max_log_bytes=per_log,
        max_total_bytes=per_target,
        deadline=None,
    )
    expected = "".join(chunks).encode()[: min(per_log, per_target)].decode(errors="replace")
    assert value == expected
    assert used <= min(per_log, per_target)
    assert len(seen) <= len(chunks)
    if used < len("".join(chunks).encode()):
        assert reason in {"max_log_bytes", "max_bytes"}


@given(
    st.lists(
        st.tuples(
            st.text(alphabet="ab_`", min_size=1, max_size=8),
            st.text(alphabet="xy_`", min_size=1, max_size=8),
            st.integers(0, 1000),
        ),
        unique_by=lambda row: row[:2],
        max_size=30,
    ),
    st.booleans(),
)
def test_clickhouse_inventory_catalog_and_fallback_agree_on_table_identity(
    entries: list[tuple[str, str, int]], fallback: bool
) -> None:
    expected = {(database, table) for database, table, _size in entries}
    calls: list[str] = []

    def query(sql: str):
        calls.append(sql)
        if sql.startswith("SELECT database,name"):
            return (
                (None, "permission denied")
                if fallback
                else (
                    [[database, table, "MergeTree", "", "", "", size, size] for database, table, size in entries],
                    None,
                )
            )
        if sql.startswith("SELECT database,table,name"):
            return [], None
        if sql.startswith("SELECT database,table,column") or sql.startswith("SELECT database,table,partition_id"):
            return [], None
        if sql == "SHOW DATABASES":
            return [[database] for database in sorted({row[0] for row in entries})], None
        if sql.startswith("SHOW TABLES FROM "):
            quoted_database = sql.removeprefix("SHOW TABLES FROM ")
            database = next(name for name in {row[0] for row in entries} if quote_identifier(name) == quoted_database)
            return [[table] for source, table, _size in entries if source == database], None
        if sql.startswith("DESCRIBE TABLE "):
            return [["payload", "String"]], None
        raise AssertionError(sql)

    tables, errors = collect_inventory(query)
    assert {(table.database, table.name) for table in tables} == expected
    if fallback:
        assert errors == ["system.tables: permission denied"]
        assert all(table.columns[0].name == "payload" for table in tables)
    else:
        assert errors == []
        assert {(table.database, table.name): table.total_rows for table in tables} == {
            (database, table): size for database, table, size in entries
        }
    assert all(sql.startswith(("SELECT", "SHOW", "DESCRIBE")) for sql in calls)


def test_clickhouse_catalog_ignores_short_foreign_rows_and_invalid_size_fields() -> None:
    def query(sql: str):
        if "system.tables" in sql:
            return [[], ["orphan"], ["app", "events", "Memory", "", "", "", "not-an-int", None]], None
        if "system.columns" in sql:
            return [[], ["foreign", "events", "x", "String", 1], ["app", "events", "payload", "String", 1]], None
        if "system.parts_columns" in sql:
            return [[], ["app", "events", "payload", 10, 20]], None
        if "system.parts" in sql:
            return [[], ["foreign", "events", "p", 1, 2], ["app", "events", "p", 1, 2, "bad", 3]], None
        raise AssertionError(sql)

    tables, errors = collect_inventory(query)
    assert errors == []
    assert len(tables) == 1 and len(tables[0].columns) == 1 and len(tables[0].partitions) == 1
    assert tables[0].total_rows is None
    assert tables[0].partitions[0]["min_block"] is None


@given(st.lists(st.text(alphabet="abc", min_size=1, max_size=5), unique=True, max_size=10))
def test_clickhouse_permission_fallback_keeps_partial_tables(names: list[str]) -> None:
    def query(sql: str):
        if "system.tables" in sql:
            return None, "denied"
        if sql == "SHOW DATABASES":
            return [[], ["app"]], None
        if sql == "SHOW TABLES FROM `app`":
            return [[], *[[name] for name in names]], None
        if sql.startswith("DESCRIBE TABLE"):
            return None, "no describe"
        raise AssertionError(sql)

    tables, errors = collect_inventory(query)
    assert [table.name for table in tables] == names
    assert all(table.inventory_errors == ["no describe"] for table in tables)
    assert errors == ["system.tables: denied"]


def test_clickhouse_permission_fallback_reports_unavailable_database_and_table_listing() -> None:
    def denied_database(sql: str):
        if "system.tables" in sql:
            return None, "denied"
        assert sql == "SHOW DATABASES"
        return None, "denied"

    assert collect_inventory(denied_database) == ([], ["system.tables: denied", "SHOW DATABASES: denied"])

    def denied_table(sql: str):
        if "system.tables" in sql:
            return None, "denied"
        if sql == "SHOW DATABASES":
            return [["app"]], None
        assert sql == "SHOW TABLES FROM `app`"
        return None, "denied"

    assert collect_inventory(denied_table) == ([], ["system.tables: denied", "app: denied"])


@pytest.mark.parametrize(
    ("limits", "reason"),
    [
        ({"max_dags": 1}, "max_dags"),
        ({"max_runs": 1}, "max_runs"),
        ({"max_tasks": 1}, "max_tasks"),
        ({"max_logs": 1}, "max_logs"),
        ({"max_findings": 1}, "max_findings"),
        ({"max_bytes": 0}, "max_bytes"),
        ({"max_seconds": 0}, "discover_time"),
    ],
)
def test_airflow_discovery_reports_exact_resource_limit_without_losing_live_findings(
    limits: dict[str, int], reason: str
) -> None:
    class Client:
        def get(self, path: str, **_kwargs: object) -> AirflowResponse:
            raw = urlsplit(path)
            query = parse_qs(raw.query)
            offset = int(query.get("offset", ["0"])[0])
            page_size = int(query.get("limit", ["100"])[0])
            if raw.path.endswith("/dags"):
                items = [{"dag_id": "first"}, {"dag_id": "second"}]
                return _airflow_response({"dags": items[offset : offset + page_size], "total_entries": 2})
            if raw.path.endswith("/dagRuns"):
                items = [{"dag_run_id": "one"}, {"dag_run_id": "two"}]
                return _airflow_response({"dag_runs": items[offset : offset + page_size], "total_entries": 2})
            if raw.path.endswith("/taskInstances"):
                task_items: list[dict[str, object]] = [
                    {"task_id": "one", "try_number": 1},
                    {"task_id": "two", "try_number": 1},
                ]
                return _airflow_response(
                    {"task_instances": task_items[offset : offset + page_size], "total_entries": 2}
                )
            if "/logs/" in raw.path:
                return _airflow_response({"content": f"password=strongSecret{raw.path[-3:]}"})
            raise AssertionError(path)

    findings: list[dict[str, object]] = []
    report = discover_task_logs(Client(), "v1", DiscoverConfig(**limits), on_finding=findings.append)
    assert report["status"] == "partial"
    assert any(item == reason or item.endswith(":" + reason) for item in report["partial_reasons"])
    assert report["bytes_scanned"] <= limits.get("max_bytes", 50 * 1024 * 1024)
    assert len(findings) == report["finding_count"]
