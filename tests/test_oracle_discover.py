from __future__ import annotations

import time
from types import SimpleNamespace

from redposture_core.data_discovery import inspect_record, prepare_discovery_request
from redposture_core.modules.oracle import actions as oracle_actions
from redposture_core.modules.oracle.actions import _collect_oracle_data
from tests.stage_runtime_helpers import run_module_targets_for_test


class _OracleDiscoveryClient:
    def __init__(self, *, fail_table: str | None = None) -> None:
        self.fail_table = fail_table
        self.dumped: list[str] = []

    def current_context(self):
        return {"session_user": "QA"}

    def server_banner(self):
        return {"version": "23ai", "banner": "Oracle Database"}

    def list_tables(self, _schema):
        return [
            {"owner": "QA", "table_name": "FIRST"},
            {"owner": "QA", "table_name": "SECOND"},
        ]

    def dump_table(self, _schema, table, *, limit):
        self.dumped.append(table)
        if table == self.fail_table:
            raise RuntimeError("read denied")
        values = {
            "FIRST": [{"display_name": "ordinary text"}],
            "SECOND": [{"api_token": "glpat-abcdefghijklmnopqrst"}],
        }
        return values[table][:limit]


def _collect(
    client,
    *,
    limit=10,
    max_bytes=None,
    started_at=None,
    discover_time=None,
    schema=None,
    table=None,
    implicit=False,
    discover_ctx=None,
):
    return _collect_oracle_data(
        client,
        host="qa",
        port=1521,
        protocol="tcp",
        insecure=True,
        listener_dump=False,
        nne_check=False,
        show_pdbs=False,
        show_users=False,
        show_roles=False,
        show_privs=False,
        show_schemas=False,
        show_tables=False,
        schema=schema,
        table=table,
        dump_rows=True,
        dump_limit=limit,
        query=None,
        privesc_check=False,
        privesc_chain=False,
        exec_cmd=None,
        exec_method="auto",
        reverse_shell=None,
        reverse_shell_type="nc",
        os_read=None,
        os_write=None,
        download=None,
        delete=None,
        wallet_search=False,
        hashes=False,
        sensitive_scan=False,
        dblink_check=False,
        discover=True,
        discover_max_bytes=max_bytes,
        discovery_started_at=started_at,
        discover_time=discover_time,
        discover_implicit_dump=implicit,
        **({"discover_ctx": discover_ctx} if discover_ctx is not None else {}),
    )


def test_unscoped_discovery_reads_every_visible_table() -> None:
    client = _OracleDiscoveryClient()
    record = _collect(client)
    assert client.dumped == ["FIRST", "SECOND"]
    assert {item["table"] for item in record["rows"]} == {"FIRST", "SECOND"}
    result = inspect_record("oracle", {"status": "open_no_auth", **record})
    assert result["status"] == "complete"
    assert result["findings"]
    assert any(item["value"] == "glpat-abcdefghijklmnopqrst" for item in result["findings"])


def test_schema_scoped_discovery_reads_every_visible_table_in_schema() -> None:
    client = _OracleDiscoveryClient()
    record = _collect(client, schema="QA")
    assert client.dumped == ["FIRST", "SECOND"]
    assert {item["table"] for item in record["rows"]} == {"FIRST", "SECOND"}


def test_oracle_discovery_without_visible_tables_is_unavailable() -> None:
    class Client(_OracleDiscoveryClient):
        def iter_tables(self, _schema):
            return iter(())

        def iter_table_rows(self, _schema, _table):
            raise AssertionError("no table should be opened")

    record = _collect(Client(), schema="OTHER", implicit=True)
    result = inspect_record("oracle", {"status": "valid_credentials", **record})
    assert result["status"] == "unavailable"
    assert result["findings"] == []
    assert "no_readable_table" in result["partial_reasons"]


def test_oracle_empty_own_schema_is_complete() -> None:
    class Client(_OracleDiscoveryClient):
        def iter_tables(self, _schema):
            return iter(())

    record = _collect(Client(), schema="QA", implicit=True)
    result = inspect_record("oracle", {"status": "valid_credentials", **record})
    assert result["status"] == "complete"
    assert result["findings"] == []


def test_oracle_discovery_ignores_token_labels_and_public_namespace_uri() -> None:
    record = {
        "status": "valid_credentials",
        "rows": [
            {
                "schema": "REDPOSTURE",
                "table": "SERVICE_TOKENS",
                "row": {"token_name": "wallet_password", "token_value": "glpat-abcdefghijklmnopqrst"},
            },
            {
                "schema": "XDB",
                "table": "XDB_NS",
                "row": {"nmspcuri": "http://www.w3.org/2001/XMLSchema-instance"},
            },
        ],
    }
    result = inspect_record("oracle", record)
    assert {finding["object_path"] for finding in result["findings"]} == {
        "$.table.REDPOSTURE.SERVICE_TOKENS.token_value"
    }


def test_discovery_row_cap_reports_partial_and_keeps_other_tables() -> None:
    record = _collect(_OracleDiscoveryClient(), limit=1)
    assert {item["table"] for item in record["rows"]} == {"FIRST", "SECOND"}
    assert record["discover_partial"] is True
    assert inspect_record("oracle", record)["status"] == "partial"


def test_discovery_read_failure_keeps_prior_rows_and_reports_partial() -> None:
    record = _collect(_OracleDiscoveryClient(fail_table="SECOND"))
    assert [item["table"] for item in record["rows"]] == ["FIRST"]
    assert record["discover_partial"] is True
    assert inspect_record("oracle", record)["status"] == "partial"


def test_discovery_portion_limit_allows_second_table() -> None:
    record = _collect(_OracleDiscoveryClient(), max_bytes=90)
    assert record["discover_partial"] is False
    assert [item["table"] for item in record["rows"]] == ["FIRST", "SECOND"]


def test_expired_discovery_stops_before_oracle_source_queries() -> None:
    client = _OracleDiscoveryClient()
    record = _collect(client, started_at=time.monotonic() - 1, discover_time=0.01)
    assert client.dumped == []
    assert record["tables"] == []
    assert record["discover_partial"] is True
    assert "discovery budget reached" in record["discover_reasons"]


def test_expired_selected_table_discovery_skips_row_query() -> None:
    client = _OracleDiscoveryClient()
    record = _collect(client, schema="QA", table="SECOND", started_at=time.monotonic() - 1, discover_time=0.01)
    assert client.dumped == []
    assert record["rows"] == []
    assert record["discover_partial"] is True


def test_selected_table_discovery_continues_past_obsolete_byte_budget() -> None:
    record = _collect(_OracleDiscoveryClient(), schema="QA", table="SECOND", max_bytes=30)
    assert len(record["rows"]) == 1
    assert record["rows"][0]["row"]["api_token"] == "glpat-abcdefghijklmnopqrst"
    assert record["discover_partial"] is False
    assert record["discover_reasons"] == []


def test_implicit_discovery_streams_past_two_hundred_rows() -> None:
    class Client(_OracleDiscoveryClient):
        def iter_table_rows(self, _schema, table):
            self.dumped.append(table)
            for index in range(201):
                yield {"api_token": "glpat-abcdefghijklmnopqrst"} if index == 200 else {"item": index}

    client = Client()
    record = _collect(client, schema="QA", table="SECOND", limit=200, implicit=True)
    assert len(record["rows"]) == 201
    assert record["discover_partial"] is False
    assert inspect_record("oracle", record)["findings"]


def test_explicit_dump_limit_remains_effective_with_streaming_client() -> None:
    class Client(_OracleDiscoveryClient):
        def iter_table_rows(self, _schema, _table):
            for index in range(8):
                yield {"item": index}

    record = _collect(Client(), schema="QA", table="FIRST", limit=5, implicit=False)
    assert len(record["rows"]) == 5
    assert record["discover_partial"] is True
    assert "QA.FIRST: row limit reached" in record["discover_reasons"]


def test_implicit_discovery_streams_past_thousand_visible_tables() -> None:
    class Client(_OracleDiscoveryClient):
        def list_tables(self, _schema):
            raise AssertionError("discovery should stream catalog")

        def iter_tables(self, _schema):
            for index in range(1001):
                yield {"owner": "QA", "table_name": f"T_{index}"}

        def iter_table_rows(self, _schema, table):
            self.dumped.append(table)
            if table == "T_1000":
                yield {"api_token": "glpat-abcdefghijklmnopqrst"}

    client = Client()
    record = _collect(client, limit=200, implicit=True)
    assert "T_1000" in client.dumped
    assert record["discover_partial"] is False
    assert inspect_record("oracle", record)["findings"]


def test_oracle_catalog_failure_preserves_earlier_table_finding() -> None:
    class Client(_OracleDiscoveryClient):
        def iter_tables(self, _schema):
            yield {"owner": "QA", "table_name": "FIRST"}
            raise RuntimeError("catalog read interrupted")

        def iter_table_rows(self, _schema, _table):
            yield {"api_token": "glpat-abcdefghijklmnopqrst"}

    record = _collect(Client(), implicit=True)
    assert record["discover_partial"] is True
    assert "table catalog read failed" in record["discover_reasons"]
    assert inspect_record("oracle", record)["findings"]


def test_oracle_row_failure_preserves_earlier_finding() -> None:
    class Client(_OracleDiscoveryClient):
        def iter_table_rows(self, _schema, _table):
            yield {"api_token": "glpat-abcdefghijklmnopqrst"}
            raise RuntimeError("row fetch interrupted")

    record = _collect(Client(), schema="QA", table="FIRST", implicit=True)
    assert record["discover_partial"] is True
    assert "QA.FIRST: read failed" in record["discover_reasons"]
    assert inspect_record("oracle", record)["findings"]


def test_oracle_discovery_caps_each_catalog_and_row_call_to_remaining_deadline() -> None:
    observed: list[int] = []

    class Client(_OracleDiscoveryClient):
        def __init__(self) -> None:
            super().__init__()
            self.connection = SimpleNamespace(call_timeout=5000)

        def iter_tables(self, _schema):
            observed.append(self.connection.call_timeout)
            yield {"owner": "QA", "table_name": "FIRST"}

        def iter_table_rows(self, _schema, _table):
            observed.append(self.connection.call_timeout)
            yield {"api_token": "glpat-abcdefghijklmnopqrst"}

    client = Client()
    record = _collect(client, discover_time=0.5, implicit=True)
    assert record["discover_partial"] is False
    assert len(record["rows"]) == 1
    assert len(observed) == 2 and all(0 < timeout <= 500 for timeout in observed)
    assert client.connection.call_timeout == 5000


def test_oracle_discovery_preserves_prefix_and_stops_tables_after_lob_budget() -> None:
    from redposture_core.clients.oracle import OracleReadBudgetError

    class Client(_OracleDiscoveryClient):
        def iter_tables(self, _schema):
            yield {"owner": "QA", "table_name": "FIRST"}
            yield {"owner": "QA", "table_name": "SECOND"}

        def iter_table_rows(self, _schema, table):
            self.dumped.append(table)
            yield {"api_token": "glpat-abcdefghijklmnopqrst"}
            raise OracleReadBudgetError("discover_max_bytes")

    client = Client()
    record = _collect(client, implicit=True)
    assert record["discover_partial"] is True
    assert record["discover_reasons"] == ["discover_max_bytes"]
    assert len(record["rows"]) == 1
    assert client.dumped == ["FIRST"]
    assert inspect_record("oracle", record)["findings"]


def test_oracle_stage_discovery_reaches_second_table(monkeypatch, tmp_path) -> None:
    from tests import test_stage_oracle

    test_stage_oracle._patch_open(monkeypatch, auth_required=True)
    starts: list[float | None] = []
    original_collect = oracle_actions._collect_oracle_data

    def _capture_collect(*args, **kwargs):
        starts.append(kwargs.get("discovery_started_at"))
        return original_collect(*args, **kwargs)

    monkeypatch.setattr(oracle_actions, "_collect_oracle_data", _capture_collect)
    monkeypatch.setattr(
        test_stage_oracle._FakeOracleClient,
        "list_tables",
        lambda _self, _schema=None: [
            {"owner": "QA", "table_name": "FIRST"},
            {"owner": "QA", "table_name": "SECOND"},
        ],
    )
    monkeypatch.setattr(
        test_stage_oracle._FakeOracleClient,
        "dump_table",
        lambda _self, _schema, table, *, limit: (
            [{"api_token": "glpat-abcdefghijklmnopqrst"}] if table == "SECOND" else [{"display_name": "ordinary text"}]
        ),
    )
    lines: list[str] = []
    args = test_stage_oracle._args(
        command="oracle", protocol="tcp", discover=True, username="system", password="oracle"
    )
    prepare_discovery_request(args)
    options = vars(args)
    for name in ("targets", "hosts", "port", "ports", "output", "output_format"):
        options.pop(name, None)
    result = run_module_targets_for_test(
        "oracle",
        hosts=["127.0.0.1"],
        port=1521,
        output_path=str(tmp_path / "oracle-discover.txt"),
        emit_line=lines.append,
        **options,
    )
    assert result[0] == 1
    assert starts and all(isinstance(start, float) for start in starts)
    assert any("Discover Secrets" in line and "status:complete" in line for line in lines), lines
    assert any("Value=" in line for line in lines), lines
    assert 'Value="glpat-abcdefghijklmnopqrst"' in "\n".join(lines)
    saved = (tmp_path / "oracle-discover.txt").read_text()
    assert 'Value="glpat-abcdefghijklmnopqrst"' in saved
    assert "\x1b[" not in saved


def test_oracle_discovery_large_serialized_row_is_not_limited_by_internal_portion():
    from redposture_core.discovery_values import DiskBackedText

    value = DiskBackedText()
    value.append_text("b'" + "\\x00" * 25000 + "'")
    value.finish()

    class Client(_OracleDiscoveryClient):
        def iter_table_rows(self, _schema, _table):
            yield {"password": "early-secret"}
            yield {"password": value}
            yield {"password": "last-secret"}

    try:
        record = _collect(
            Client(),
            schema="QA",
            table="FIRST",
            implicit=True,
            max_bytes=64,
            discover_ctx=SimpleNamespace(args=SimpleNamespace(discover_time=900), host="qa", port=1521),
        )
        result = record["content_discovery"]
        assert result["status"] == "complete", result["partial_reasons"]
        findings = list(result["findings"])
        assert len(findings) == 3
        actual = [item["value"] for item in findings]
        assert actual[0] == "early-secret" and actual[2] == "last-secret"
        assert isinstance(actual[1], DiskBackedText)
        assert actual[1].byte_length == value.byte_length and actual[1].digest == value.digest
        assert len(record["rows"]) == 3
    finally:
        value.close()
