from __future__ import annotations

from redposture_core.data_discovery import inspect_record, prepare_discovery_request
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


def _collect(client, *, limit=10, max_bytes=None):
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
        schema=None,
        table=None,
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
    )


def test_unscoped_discovery_reads_every_visible_table() -> None:
    client = _OracleDiscoveryClient()
    record = _collect(client)
    assert client.dumped == ["FIRST", "SECOND"]
    assert {item["table"] for item in record["rows"]} == {"FIRST", "SECOND"}
    result = inspect_record("oracle", {"status": "open_no_auth", **record})
    assert result["status"] == "complete"
    assert result["findings"]
    assert "glpat-abcdefghijklmnopqrst" not in str(result)


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


def test_discovery_byte_budget_stops_before_second_table() -> None:
    record = _collect(_OracleDiscoveryClient(), max_bytes=90)
    assert record["discover_partial"] is True
    assert len(record["rows"]) <= 1


def test_oracle_stage_discovery_reaches_second_table(monkeypatch, tmp_path) -> None:
    from tests import test_stage_oracle

    test_stage_oracle._patch_open(monkeypatch, auth_required=True)
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
    assert any("Discover Secrets" in line and "status:complete" in line for line in lines), lines
    assert any("Value=" in line for line in lines), lines
    assert "glpat-abcdefghijklmnopqrst" not in "\n".join(lines)
    saved = (tmp_path / "oracle-discover.txt").read_text()
    assert "glpat-abcdefghijklmnopqrst" not in saved
    assert "\x1b[" not in saved
