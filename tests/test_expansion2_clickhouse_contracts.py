"""ClickHouse discovery ownership, denied operations, and evidence retention."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from redposture_core.modules.clickhouse import actions as ch
from redposture_core.shell_capture import CommandResult


def _session(database: str = "app", protocol: str = "native") -> ch._ChSession:
    return ch._ChSession(protocol, Mock(), "audit", "pw", database)


def _options(**overrides: Any) -> dict[str, Any]:
    options: dict[str, Any] = dict(
        protocol="native",
        database="app",
        show_databases=False,
        show_tables=False,
        show_columns=False,
        table_targets=[],
        table_columns=[],
        dump_table_rows=False,
        dump_row_limit=3,
        execute_command=None,
        sql_command=None,
        show_databases_limit=None,
        show_tables_limit=None,
    )
    options.update(overrides)
    return options


def _context(session: ch._ChSession, *, limited: bool = True, workers: int = 1) -> SimpleNamespace:
    state = ch.ClickHouseLifecycleState(selected_protocol="native")
    key = ("audit", "pw", "provided")
    state.credential_sessions[key] = session
    if limited:
        state.credential_limited.add(key)
    return SimpleNamespace(
        lifecycle_state=state,
        credential=SimpleNamespace(username="audit", password="pw", source="provided"),
        host="db",
        port=9000,
        args=SimpleNamespace(timeout=2.0, _audit_nested_workers=workers),
        nested_scheduler=object() if workers > 1 else None,
        debug_emit=Mock(),
        live_emit=Mock(),
    )


@pytest.mark.parametrize("worker_failure", [False, True])
def test_discovery_forwards_limits_streams_findings_and_closes_workers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, worker_failure: bool
) -> None:
    session = _session()
    extra = _session()
    first_extra = _session()
    ctx = _context(session, workers=3)
    opening = Mock(
        side_effect=[(extra, None), (None, "connection refused")]
        if worker_failure
        else [(first_extra, None), (extra, None)]
    )
    monkeypatch.setattr(ch, "_open_operational_session", opening)
    checkpoint = tmp_path / "checkpoint.json"
    report = {
        "status": "complete",
        "finding_count": 1,
        "findings": [{"kind": "email", "table": "app.t", "column": "email", "value": "a@example.org"}],
    }

    def discover(actual: Any, **kwargs: Any) -> dict[str, Any]:
        assert actual is session
        config = kwargs["config"]
        assert config.checkpoint == checkpoint and config.resume is True
        assert (
            config.chunk_rows,
            config.max_query_time,
            config.max_query_rows,
            config.max_query_bytes,
            config.max_memory,
            config.max_threads,
        ) == (17, 2.5, 23, 31, 47, 2)
        assert config.exclusions == ("app.skip",) and config.detectors == ("email",)
        assert config.redact is True and config.max_seconds == 5.0 and config.max_total_bytes == 99
        assert kwargs["sessions"] == ((session, extra) if worker_failure else (session, first_extra, extra))
        assert kwargs["nested_scheduler"] is ctx.nested_scheduler
        assert kwargs["scheduler_key"] == ("clickhouse-discover", "db", 9000)
        kwargs["on_chunk_findings"](None, report["findings"])
        return report

    monkeypatch.setattr(ch, "run_discovery", discover)
    result = ch.collect_clickhouse_data(
        ctx,
        {"status": "valid_credentials", "is_clickhouse": True},
        _options(
            discover=True,
            discover_checkpoint=checkpoint,
            discover_resume=True,
            discover_chunk_rows=17,
            discover_max_query_time=2.5,
            discover_max_query_rows=23,
            discover_max_query_bytes=31,
            discover_max_memory=47,
            discover_max_threads=2,
            discover_exclusions=["app.skip"],
            discover_detectors=["email"],
            discover_redact=True,
            discover_max_seconds=5.0,
            discover_max_total_bytes=99,
        ),
    )
    assert result["discover_report"] == report
    assert result["action_statuses"]["discover"] == "ok"
    assert result["_discover_findings_streamed"] is True
    assert not result["requested_operation_failure"]
    assert ctx.lifecycle_state.discovery_report is report
    ctx.live_emit.assert_called_once()
    assert "a@example.org" in str(ctx.live_emit.call_args.args[0])
    session.client.disconnect.assert_called_once()
    extra.client.disconnect.assert_called_once()
    if worker_failure:
        first_extra.client.disconnect.assert_not_called()
    else:
        first_extra.client.disconnect.assert_called_once()
    assert not ctx.lifecycle_state.credential_sessions
    if worker_failure:
        assert "connection refused" in str(ctx.debug_emit.call_args_list)


@pytest.mark.parametrize("error", [OSError("checkpoint inaccessible"), ValueError("invalid resume state")])
def test_discovery_error_keeps_successful_sql_and_closes_all_sessions(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    session, extra = _session(), _session()
    ctx = _context(session, workers=2)
    monkeypatch.setattr(ch, "_open_operational_session", Mock(return_value=(extra, None)))
    monkeypatch.setattr(ch, "_run_sql_query", Mock(return_value=(["[1]"], None)))
    monkeypatch.setattr(ch, "run_discovery", Mock(side_effect=error))
    result = ch.collect_clickhouse_data(
        ctx, {"status": "valid_credentials"}, _options(discover=True, sql_command="SELECT 1")
    )
    assert result["sql_ok"] is True and result["sql_output"] == ["[1]"]
    assert result["requested_operation_failure"] is True and result["partial"] is True
    assert result["action_statuses"]["discover"] == "partial"
    assert result["discover_report"]["scan_errors"] == [{"kind": "discovery_error", "error": str(error)}]
    assert result["partial_reasons"] == ["discover: error"]
    session.client.disconnect.assert_called_once()
    extra.client.disconnect.assert_called_once()


def test_cached_discovery_is_reused_and_runtime_auth_attempts_merge(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _session()
    ctx = _context(session)
    report = {"status": "partial", "finding_count": 2}
    ctx.lifecycle_state.discovery_report = report
    actual = {"username": "audit", "password": "pw", "source": "provided", "ok": True, "error": ""}
    ctx.lifecycle_state.auth_attempts = [actual]
    discover = Mock(side_effect=AssertionError("cached discovery repeated"))
    monkeypatch.setattr(ch, "run_discovery", discover)
    attempts = [
        None,
        {"username": "audit", "password": "pw", "source": "provided", "status": "auth_required"},
        {"username": "default", "password": None, "source": "default", "status": "weak_default_creds"},
        {"username": "wrong", "password": "bad", "status": "auth_required", "error": "denied"},
    ]
    result = ch.collect_clickhouse_data(
        ctx, {"status": "valid_credentials", "attempted_credentials": attempts}, _options(discover=True)
    )
    assert result["credential_attempts"] == [
        actual,
        {"username": "default", "password": "", "source": "default", "ok": True, "error": ""},
        {"username": "wrong", "password": "bad", "source": "provided", "ok": False, "error": "denied"},
    ]
    assert result["credential_attempt_count"] == 3 and result["defcreds_enabled"] is True
    assert result["discover_report"] is report and result["requested_operation_failure"] is True
    assert "attempted_credentials" not in result
    discover.assert_not_called()


@pytest.mark.parametrize("warning", ["database denied", None])
def test_database_reopen_failure_preserves_authentication_evidence(
    monkeypatch: pytest.MonkeyPatch, warning: str | None
) -> None:
    session = _session("default")
    ctx = _context(session)
    monkeypatch.setattr(ch, "_open_operational_session", Mock(return_value=(None, warning)))
    actions = Mock(side_effect=AssertionError("data ran without session"))
    monkeypatch.setattr(ch, "_run_clickhouse_actions_on_session", actions)
    result = ch.collect_clickhouse_data(
        ctx, {"status": "valid_credentials", "is_clickhouse": True, "server_version": "25.1"}, _options()
    )
    assert result["status"] == "valid_credentials" and result["server_version"] == "25.1"
    assert result["requested_operation_failure"] is True
    assert result["error"] == (warning or "failed to open database app")
    session.client.disconnect.assert_called_once()
    actions.assert_not_called()


@pytest.mark.parametrize("status", ["open_no_auth", "anonymous_limited", "invalid_credentials_anonymous"])
def test_anonymous_session_is_consumed_once(monkeypatch: pytest.MonkeyPatch, status: str) -> None:
    session = _session()
    ctx = _context(session)
    ctx.lifecycle_state.credential_sessions.clear()
    ctx.lifecycle_state.anonymous_session = session
    ctx.lifecycle_state.anonymous_access_limited = True
    result = ch.collect_clickhouse_data(ctx, {"status": status}, _options())
    assert result["status"] == status and result["read_capability"] is None
    assert ctx.lifecycle_state.anonymous_session is None
    session.client.disconnect.assert_called_once()
    result2 = ch.collect_clickhouse_data(ctx, result, _options())
    assert result2 == result
    session.client.disconnect.assert_called_once()


@pytest.mark.parametrize("stdout,stderr,exit_code", [(b"\0\xff", b"\xfe\0", 0), (b"ok", b"failure", 7)])
def test_execute_binary_evidence_and_nonzero_exit_are_retained(
    monkeypatch: pytest.MonkeyPatch, stdout: bytes, stderr: bytes, exit_code: int
) -> None:
    import base64

    monkeypatch.setattr(
        ch,
        "_run_execute_command_bytes",
        Mock(
            return_value=CommandResult(stdout=stdout, stderr=stderr, exit_code=exit_code, stdout_total=len(stdout) + 1)
        ),
    )
    result = ch._run_clickhouse_actions_on_session(
        _session(),
        **{key: value for key, value in _options(execute_command="id").items() if key != "protocol"},
        limited_session=True,
    )
    assert result["execute_exit_code"] == exit_code and result["execute_truncated"] is True
    assert result["execute_ok"] is (exit_code == 0)
    if exit_code:
        assert result["execute_error"] == "exit code 7" and result["requested_operation_failure"]
    else:
        assert result["execute_stdout_base64"] == base64.b64encode(stdout).decode()
        assert result["execute_stderr_base64"] == base64.b64encode(stderr).decode()


@pytest.mark.parametrize("failure", ["open", "query", "limited"])
@pytest.mark.parametrize("protocol", ["native", "http"])
def test_probe_closes_failed_clients_but_retains_limited_sessions(
    monkeypatch: pytest.MonkeyPatch, protocol: str, failure: str
) -> None:
    client = Mock()
    code = 497 if failure == "limited" else 516
    if protocol == "native":
        from clickhouse_driver.errors import ServerException

        error: Exception = ServerException("Access denied", code=code)
    else:
        error = RuntimeError(f"Received ClickHouse exception, code: {code}. Access denied")
    opening = Mock(side_effect=error if failure == "open" else None, return_value=client)
    client.execute.side_effect = error
    client.query.side_effect = error
    monkeypatch.setattr(ch, "_open_clickhouse_client", opening)
    result = ch._connect_and_probe(protocol, "db", 9000, 2.0, "audit", "pw")
    assert result.confirms_service is True
    if failure == "limited":
        assert result.session is not None and result.access_limited is True
        client.disconnect.assert_not_called()
        client.close.assert_not_called()
    else:
        assert result.session is None and result.auth_required is True
        closer = client.disconnect if protocol == "native" else client.close
        assert closer.call_count == (0 if failure == "open" else 1)


@pytest.mark.parametrize("operation", ["sql", "execute"])
@pytest.mark.parametrize("failure", ["setup_retry", "exhausted", "command_denied"])
def test_shell_operations_bound_retries_and_keep_command_errors(
    monkeypatch: pytest.MonkeyPatch, operation: str, failure: str
) -> None:
    session = _session()
    opening = Mock(
        side_effect=[(None, "connection timeout"), (session, None)] if failure == "setup_retry" else None,
        return_value=(None, None) if failure == "exhausted" else (session, None),
    )
    command = Mock(return_value=(["partial evidence"], "permission denied" if failure == "command_denied" else None))
    monkeypatch.setattr(ch, "_open_operational_session", opening)
    monkeypatch.setattr(ch, "_run_sql_query" if operation == "sql" else "_run_execute_command", command)
    monkeypatch.setattr(ch.time, "sleep", Mock())
    helper = ch._run_sql_query_once if operation == "sql" else ch._run_execute_command_once
    output, error = helper(
        "db", 9000, 2.0, 1, "native", "audit", "pw", "app", "SELECT 1" if operation == "sql" else "id"
    )
    if failure == "exhausted":
        assert output == [] and error == ("query failed" if operation == "sql" else "execute failed")
        command.assert_not_called()
    else:
        assert output == ["partial evidence"]
        assert error == ("permission denied" if failure == "command_denied" else None)
        command.assert_called_once()
        session.client.disconnect.assert_called_once()
    assert opening.call_count == (1 if failure == "command_denied" else 2)


@pytest.mark.parametrize(
    "error,attempts", [("connection timeout", 2), ("Code: 516. Authentication failed", 1), (None, 1)]
)
def test_shell_reconnect_retries_only_transport_failure(
    monkeypatch: pytest.MonkeyPatch, error: str | None, attempts: int
) -> None:
    opening = Mock(return_value=(None, error))
    monkeypatch.setattr(ch, "_open_operational_session", opening)
    monkeypatch.setattr(ch.time, "sleep", Mock())
    session, actual_error = ch._open_shell_session("db", 9000, 2.0, 1, "native", "audit", "pw", "app")
    assert session is None and actual_error == (error or "connection failed")
    assert opening.call_count == attempts


@pytest.mark.parametrize("command", ["", " ; ", "id\nwhoami", "id"])
def test_byte_execute_rejects_empty_multiline_or_unframed_response(
    monkeypatch: pytest.MonkeyPatch, command: str
) -> None:
    query = Mock(return_value=([["unframed output"]], None))
    monkeypatch.setattr(ch, "_query_rows", query)
    result = ch._run_execute_command_bytes(_session(), command)
    assert result.error
    assert query.call_count == (1 if command == "id" else 0)
    assert result.outcome_unknown is (command == "id")


@pytest.mark.parametrize("error,unknown", [("connection timeout", True), ("Code: 497. Access denied", False)])
def test_byte_execute_distinguishes_transport_uncertainty_from_denial(
    monkeypatch: pytest.MonkeyPatch, error: str, unknown: bool
) -> None:
    monkeypatch.setattr(ch, "_query_rows", Mock(return_value=(None, error)))
    result = ch._run_execute_command_bytes(_session(), "id")
    assert result.error == error and result.outcome_unknown is unknown


@pytest.mark.parametrize("error", [None, "not enough privileges"])
def test_system_commands_keep_direct_sql_semantics(monkeypatch: pytest.MonkeyPatch, error: str | None) -> None:
    query = Mock(return_value=([["done"]], error))
    monkeypatch.setattr(ch, "_query_rows", query)
    result = ch._run_execute_command_bytes(_session(), "SYSTEM FLUSH LOGS;")
    assert query.call_args.args[1] == "SYSTEM FLUSH LOGS"
    assert result.error == error and result.exit_code == (0 if error is None else None)
    assert result.outcome_unknown is False


@pytest.mark.parametrize("rows", [None, [], [[]], [["not a number"]], [[None]]])
def test_database_count_invalid_response_is_unknown(monkeypatch: pytest.MonkeyPatch, rows: Any) -> None:
    monkeypatch.setattr(ch, "_query_rows", Mock(return_value=(rows, None)))
    assert ch._query_database_count(_session()) == (None, "invalid database count response")


def test_inventory_queries_retain_permission_errors_and_skip_short_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ch, "_query_rows", Mock(return_value=(None, "not enough privileges")))
    assert ch._query_database_names(_session()) == (None, "not enough privileges")
    assert ch._query_database_count(_session()) == (None, "not enough privileges")
    assert ch._query_visible_tables(_session()) == (None, "not enough privileges")
    monkeypatch.setattr(ch, "_query_rows", Mock(return_value=([[], ["app"], ["app", "odd.table"]], None)))
    assert ch._query_visible_tables(_session()) == (["app.`odd.table`"], None)


@pytest.mark.parametrize("raw", ["", "a..b", "a.b.c", "a-b", "`unterminated", "``", '"unterminated', '""', "a.", ".b"])
def test_invalid_table_selector_is_retained_as_operation_error(monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
    columns = Mock(side_effect=AssertionError("invalid selector queried"))
    monkeypatch.setattr(ch, "_query_table_columns", columns)
    result = ch._run_clickhouse_actions_on_session(
        _session(),
        **{key: value for key, value in _options(show_columns=True, table_targets=[raw]).items() if key != "protocol"},
        limited_session=True,
    )
    assert result["action_statuses"]["columns"] == "error"
    assert result["table_columns_info"][0]["table"] == raw
    assert result["requested_operation_failure"] is True
    columns.assert_not_called()


@pytest.mark.parametrize("metadata_error,row_error", [("columns denied", None), ("columns denied", "rows denied")])
def test_dump_keeps_rows_when_metadata_denied_and_combines_errors(
    monkeypatch: pytest.MonkeyPatch, metadata_error: str, row_error: str | None
) -> None:
    monkeypatch.setattr(ch, "_query_table_columns", Mock(return_value=(None, metadata_error)))
    monkeypatch.setattr(ch, "_query_table_rows", Mock(return_value=(["[1]"], row_error)))
    result = ch._run_clickhouse_actions_on_session(
        _session(),
        **{
            key: value
            for key, value in _options(dump_table_rows=True, table_targets=["app.t"]).items()
            if key != "protocol"
        },
        limited_session=True,
    )
    assert result["table_dumps"] == [
        {
            "table": "app.t",
            "columns": [],
            "rows": ["[1]"],
            "error": ("rows denied; " if row_error else "") + "columns: columns denied",
        }
    ]
    assert result["action_statuses"]["dump"] == "error" and result["requested_operation_failure"]


@pytest.mark.parametrize(
    "table,expected",
    [
        ("`Odd.DB`.`a``b`", ("Odd.DB", "a`b")),
        ("`a.b`", ("app", "a.b")),
        ("app.`commas,allowed`", ("app", "commas,allowed")),
    ],
)
def test_quoted_table_selectors_preserve_delimiters_when_querying(
    monkeypatch: pytest.MonkeyPatch, table: str, expected: tuple[str, str]
) -> None:
    metadata = Mock(return_value=(["ID"], None))
    rows = Mock(return_value=(["[1]"], None))
    monkeypatch.setattr(ch, "_query_table_columns", metadata)
    monkeypatch.setattr(ch, "_query_table_rows", rows)
    result = ch._run_clickhouse_actions_on_session(
        _session(),
        **{
            key: value
            for key, value in _options(dump_table_rows=True, table_targets=[table]).items()
            if key != "protocol"
        },
        limited_session=True,
    )
    assert metadata.call_args.args[1:] == expected
    assert rows.call_args.args[1:] == expected
    assert result["table_dumps"][0]["rows"] == ["[1]"]
    assert result["requested_operation_failure"] is False


@pytest.mark.parametrize("operation", ["execute", "sql"])
@pytest.mark.parametrize("status", [True, False, None])
def test_operation_exports_keep_empty_success_denial_and_pending_distinct(operation: str, status: bool | None) -> None:
    import json

    record = {
        "host": "db",
        "port": 9000,
        f"{operation}_command": "SELECT 1" if operation == "sql" else "id",
        f"{operation}_attempted": True,
        f"{operation}_ok": status,
        f"{operation}_output": [],
        f"{operation}_error": "permission denied" if status is False else None,
    }
    helper = getattr(ch, f"_format_{operation}_detail_records")
    text = "\n".join(helper(record, "txt"))
    assert ("<ok>" if status is True else "<error:permission denied>" if status is False else "<not attempted>") in text
    exported = helper(record, "json")
    assert len(exported) == 1 and json.loads(exported[0])["ok"] is status
    assert "\x1b" not in text and "\x1b" not in exported[0]
    record[f"{operation}_attempted"] = False
    assert helper(record, "txt") == [] and helper(record, "json") == []
