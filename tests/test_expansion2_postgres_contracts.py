"""PostgreSQL query draining, cleanup, selector validation, and retry contracts."""

from __future__ import annotations

import struct
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from redposture_core.modules.postgres import actions as pg


def _socket() -> MagicMock:
    sock = MagicMock()
    sock.__enter__.return_value = sock
    return sock


def test_query_drains_error_to_ready_and_preserves_received_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    row = struct.pack("!Hi", 1, 3) + b"one"
    messages = Mock(
        side_effect=[(b"T", b""), (b"D", row), (b"E", b"C42501\0Mpermission denied\0\0"), (b"N", b""), (b"Z", b"I")]
    )
    send = Mock()
    monkeypatch.setattr(pg, "_pg_read_message", messages)
    monkeypatch.setattr(pg, "_pg_send_query", send)
    assert pg._pg_query_rows(None, "SELECT secret") == ([["one"]], "permission denied")
    assert messages.call_count == 5
    send.assert_called_once_with(None, "SELECT secret")


@pytest.mark.parametrize("payload", [b"", b"\0", b"\0\1", b"\0\1\0\0\0", b"\0\1\xff\xff\xff\xfe", b"\0\1\0\0\0\2x"])
def test_malformed_data_rows_never_become_results(payload: bytes) -> None:
    with pytest.raises(ValueError, match="DataRow"):
        pg._pg_parse_data_row(payload)


@pytest.mark.parametrize("helper", [pg._pg_query_databases, pg._pg_query_accessible_databases])
def test_database_lists_skip_empty_names_but_keep_identifiers(monkeypatch: pytest.MonkeyPatch, helper: Any) -> None:
    query = Mock(return_value=([[], [None], ["  "], [" app "], ["Case DB"]], None))
    monkeypatch.setattr(pg, "_pg_query_rows", query)
    assert helper(None) == (["app", "Case DB"], None)
    if helper is pg._pg_query_accessible_databases:
        assert "has_database_privilege(datname, 'CONNECT')" in query.call_args.args[1]


@pytest.mark.parametrize(
    "helper", [pg._pg_query_databases, pg._pg_query_accessible_databases, pg._pg_query_readable_tables]
)
def test_inventory_permission_denial_remains_unknown(monkeypatch: pytest.MonkeyPatch, helper: Any) -> None:
    monkeypatch.setattr(pg, "_pg_query_rows", Mock(return_value=([], "permission denied")))
    assert helper(None) == (None, "permission denied")


def test_table_inventory_discards_incomplete_rows_and_quotes_names(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        pg,
        "_pg_query_rows",
        Mock(
            return_value=([[], ["public"], ["", "t"], ["s", None], ["public", "events"], ["Odd Schema", 'A"B']], None)
        ),
    )
    assert pg._pg_query_readable_tables(None) == (["public.events", '"Odd Schema"."A""B"'], None)


@pytest.mark.parametrize("table", ["", "a-b", "a..b", "a.b.c", '"unterminated', '""', ".events", "public.events;DROP"])
@pytest.mark.parametrize("helper", [pg._pg_query_table_rows, pg._pg_query_table_columns, pg._pg_query_table_row_count])
def test_invalid_selectors_never_reach_server(monkeypatch: pytest.MonkeyPatch, table: str, helper: Any) -> None:
    query = Mock(side_effect=AssertionError("invalid identifier reached database"))
    monkeypatch.setattr(pg, "_pg_query_rows", query)
    monkeypatch.setattr(pg, "_pg_query_scalar_int", query)
    display, value, error = helper(None, table)
    assert display and value is None and error
    query.assert_not_called()


@pytest.mark.parametrize("failure", ["create", "copy", "select", "frame"])
def test_byte_command_failure_cleans_temp_table_and_marks_ambiguity(
    monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    calls: list[str] = []

    def query(_sock: Any, sql: str) -> tuple[list[list[str]], str | None]:
        calls.append(sql)
        if sql.startswith({"create": "CREATE", "copy": "COPY", "select": "SELECT", "frame": "never"}[failure]):
            return [], "permission denied"
        return ([["not a capture frame"]] if sql.startswith("SELECT") else []), None

    monkeypatch.setattr(pg, "_pg_query_rows", query)
    result = pg._pg_try_execute_command_bytes(None, "id")
    assert result.error
    assert result.outcome_unknown is (failure != "create")
    assert sum(sql.startswith("DROP") for sql in calls) == (0 if failure == "create" else 1)
    assert sum(sql.startswith("COPY") for sql in calls) == (0 if failure == "create" else 1)


@pytest.mark.parametrize("failure", ["authentication", "connection", "execution", "terminate"])
def test_byte_execution_retries_setup_only(monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    sock = _socket()
    opening = Mock(side_effect=[OSError("not reachable"), sock] if failure == "connection" else [sock])
    auth = Mock(
        side_effect=pg._PgAuditError("bad credentials", detected=True, auth_required=True)
        if failure == "authentication"
        else None
    )
    from redposture_core.shell_capture import CommandResult

    execution = Mock(
        side_effect=OSError("connection lost") if failure == "execution" else None,
        return_value=CommandResult(stdout=b"ok", exit_code=0),
    )
    terminate = Mock(side_effect=OSError("closed") if failure == "terminate" else None)
    monkeypatch.setattr(pg, "_pg_open_socket", opening)
    monkeypatch.setattr(pg, "_pg_startup_and_auth", auth)
    monkeypatch.setattr(pg, "_pg_try_execute_command_bytes", execution)
    monkeypatch.setattr(pg, "_pg_send_terminate", terminate)
    monkeypatch.setattr(pg.time, "sleep", Mock())
    result = pg._pg_execute_remote_command_bytes("db", 5432, 2.0, 3, "audit", "pw", "app", "id", max_bytes=42)
    assert opening.call_count == (2 if failure == "connection" else 1)
    assert execution.call_count == (0 if failure == "authentication" else 1)
    if failure in {"connection", "terminate"}:
        assert result.stdout == b"ok" and result.exit_code == 0
    else:
        assert result.error
        assert result.outcome_unknown is (failure == "execution")
    if execution.called:
        assert execution.call_args.kwargs == {"max_bytes": 42}
    sock.__exit__.assert_called_once()


@pytest.mark.parametrize("helper", [pg._pg_execute_remote_command, pg._pg_execute_sql_query])
@pytest.mark.parametrize("failure", ["authentication", "exhausted", "terminate"])
def test_remote_operations_expose_failures_and_close_sessions(
    monkeypatch: pytest.MonkeyPatch, helper: Any, failure: str
) -> None:
    sock = _socket()
    sock.close.side_effect = OSError("already closed")
    opening = Mock(side_effect=OSError("offline") if failure == "exhausted" else None, return_value=sock)
    auth = Mock(
        side_effect=pg._PgAuditError("bad credentials", detected=True, auth_required=True)
        if failure == "authentication"
        else None
    )
    query = Mock(return_value=(["data"], None))
    monkeypatch.setattr(pg, "_pg_open_socket", opening)
    monkeypatch.setattr(pg, "_pg_startup_and_auth", auth)
    monkeypatch.setattr(pg, "_pg_try_execute_command", query)
    monkeypatch.setattr(pg, "_pg_try_query_sql", query)
    monkeypatch.setattr(pg, "_pg_send_terminate", Mock(side_effect=OSError("closed")))
    monkeypatch.setattr(pg.time, "sleep", Mock())
    output, error = helper("db", 5432, 2.0, 1, "audit", "pw", "app", "SELECT 1")
    if failure == "terminate":
        assert (output, error) == (["data"], None)
        query.assert_called_once()
    else:
        assert output is None and error
        query.assert_not_called()
    assert opening.call_count == (2 if failure == "exhausted" else 1)
    assert sock.close.call_count == (0 if failure == "exhausted" else 1)


@pytest.mark.parametrize("failure", ["authentication", "connection", "terminate"])
def test_remote_artifact_collection_keeps_flags_and_result(monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    sock = _socket()
    sock.close.side_effect = OSError("already closed")
    opening = Mock(side_effect=OSError("offline") if failure == "connection" else None, return_value=sock)
    auth = Mock(
        side_effect=pg._PgAuditError("denied", detected=True, auth_required=True)
        if failure == "authentication"
        else None
    )
    retained = (["app.public.t"], [], [], [{"rows": ["row"], "error": None}], 1, "partial metadata")
    collect = Mock(return_value=retained)
    monkeypatch.setattr(pg, "_pg_open_socket", opening)
    monkeypatch.setattr(pg, "_pg_startup_and_auth", auth)
    monkeypatch.setattr(pg, "_pg_collect_database_artifacts", collect)
    monkeypatch.setattr(pg, "_pg_send_terminate", Mock(side_effect=OSError("closed")))
    monkeypatch.setattr(pg.time, "sleep", Mock())
    options = dict(
        include_database_prefix=True,
        show_tables=False,
        show_row_counts=True,
        show_columns=False,
        table_targets=["public.t"],
        table_columns=["ID"],
        dump_table_rows=True,
        dump_row_limit=7,
    )
    result = pg._pg_collect_database_artifacts_remote("db", 5432, 2.0, 1, "audit", "pw", "app", **options)
    if failure == "terminate":
        assert result == retained
        assert collect.call_args.kwargs == {"database_name": "app", **options}
    else:
        assert result[:5] == (None, [], [], [], None) and result[5]
        collect.assert_not_called()
    assert opening.call_count == (2 if failure == "connection" else 1)


def _audit_options(**overrides: Any) -> dict[str, Any]:
    options: dict[str, Any] = dict(
        host="db",
        port=5432,
        timeout=2.0,
        retries=0,
        username="audit",
        password="pw",
        defcreds=False,
        database=None,
        show_databases=True,
        show_tables=True,
        show_row_counts=False,
        show_columns=False,
        table_targets=[],
        table_targets_by_database={},
        table_columns=[],
        dump_table_rows=False,
        dump_row_limit=4,
        execute_command=None,
        sql_command=None,
    )
    options.update(overrides)
    return options


def _audit_session(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    sock = _socket()
    monkeypatch.setattr(pg, "_pg_open_socket", Mock(return_value=sock))
    monkeypatch.setattr(
        pg,
        "_pg_startup_and_auth",
        Mock(return_value=pg._PgSession(auth_required=True, auth_method="md5", server_version="16.4")),
    )
    monkeypatch.setattr(pg, "_collect_postgres_privileges", Mock(return_value=(False, False, None, None, None)))
    monkeypatch.setattr(pg, "_pg_query_databases", Mock(return_value=(["postgres", "app"], None)))
    monkeypatch.setattr(pg, "_pg_send_terminate", Mock(side_effect=OSError("closed")))
    return sock


@pytest.mark.parametrize(
    "accessible,error,expected",
    [
        (["app", "app", "", "postgres"], None, ["postgres", "app"]),
        ([], None, ["postgres"]),
        (None, "CONNECT catalog denied", ["postgres"]),
    ],
)
def test_audit_database_walk_deduplicates_accessible_names_and_retains_partial_inventory(
    monkeypatch: pytest.MonkeyPatch, accessible: list[str] | None, error: str | None, expected: list[str]
) -> None:
    _audit_session(monkeypatch)
    monkeypatch.setattr(pg, "_pg_query_accessible_databases", Mock(return_value=(accessible, error)))
    local = Mock(return_value=(["postgres.public.ok"], [], [], [], 1, None))
    remote = Mock(return_value=(None, [], [], [], None, "app: connection lost"))
    monkeypatch.setattr(pg, "_pg_collect_database_artifacts", local)
    monkeypatch.setattr(pg, "_pg_collect_database_artifacts_remote", remote)
    result = pg._audit_postgres_host(**_audit_options())
    assert result["status"] == "valid_credentials" and result["is_postgres"] is True
    assert result["database_names"] == ["postgres", "app"]
    assert result["table_names"] == ["postgres.public.ok"]
    assert local.call_args.kwargs["database_name"] == "postgres"
    assert local.call_args.kwargs["include_database_prefix"] is (len(expected) > 1)
    assert remote.call_count == len(expected) - 1
    if error:
        assert error in result["error"]
    if remote.called:
        assert remote.call_args.args[6] == "app"
        assert "app: connection lost" in result["error"]


def test_database_prefixed_targets_keep_local_selector_order_and_skip_inventory_walk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _audit_session(monkeypatch)
    accessible = Mock(side_effect=AssertionError("explicit selector walked all databases"))
    monkeypatch.setattr(pg, "_pg_query_accessible_databases", accessible)
    local = Mock(return_value=(None, [], [], [], None, None))
    remote = Mock(return_value=(None, [], [], [], None, None))
    monkeypatch.setattr(pg, "_pg_collect_database_artifacts", local)
    monkeypatch.setattr(pg, "_pg_collect_database_artifacts_remote", remote)
    targets = ["public.a", "app.public.b"]
    result = pg._audit_postgres_host(
        **_audit_options(
            table_targets=targets,
            table_targets_by_database={None: ["public.a"], "postgres": ["public.a", "public.c"], "app": ["public.b"]},
            show_tables=False,
        )
    )
    assert result["table_targets"] == targets
    assert local.call_args.kwargs["table_targets"] == ["public.a", "public.c"]
    assert remote.call_args.kwargs["table_targets"] == ["public.b"]
    assert remote.call_args.args[6] == "app"
    accessible.assert_not_called()


@pytest.mark.parametrize("mode", ["binary", "exit", "exception"])
def test_audit_execute_failure_keeps_sql_and_authenticated_session_evidence(
    monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    import base64

    from redposture_core.shell_capture import CommandResult

    _audit_session(monkeypatch)
    monkeypatch.setattr(pg, "_pg_collect_database_artifacts", Mock(return_value=(None, [], [], [], None, None)))
    command = Mock(
        side_effect=OSError("command reply lost") if mode == "exception" else None,
        return_value=CommandResult(
            stdout=b"\x00\xff" if mode == "binary" else b"failed",
            stderr=b"\xfe\x00",
            exit_code=7 if mode == "exit" else 0,
        ),
    )
    monkeypatch.setattr(pg, "_pg_try_execute_command_bytes", command)
    monkeypatch.setattr(pg, "_pg_try_query_sql", Mock(return_value=(["query result"], None)))
    result = pg._audit_postgres_host(
        **_audit_options(database="postgres", show_tables=False, execute_command="id", sql_command="SELECT 1")
    )
    assert result["status"] == "valid_credentials" and result["server_version"] == "16.4"
    assert result["sql_ok"] is True and result["sql_output"] == ["query result"]
    command.assert_called_once()
    if mode == "binary":
        assert result["execute_stdout_base64"] == base64.b64encode(b"\0\xff").decode()
        assert result["execute_stderr_base64"] == base64.b64encode(b"\xfe\0").decode()
        assert result["execute_ok"] is True
    else:
        assert result["execute_ok"] is False
        assert result["execute_error"] == ("exit code 7" if mode == "exit" else "command reply lost")
        assert result["execute_outcome_unknown"] is (mode == "exception")


@pytest.mark.parametrize(
    "payload,password,expected",
    [
        (b"\0", "pw", "invalid authentication payload"),
        (struct.pack("!I", 3), None, "password authentication required"),
        (struct.pack("!I", 5), "pw", "invalid MD5 authentication payload"),
        (struct.pack("!I", 5) + b"salt", None, "md5 authentication required"),
        (struct.pack("!I", 10), None, "SCRAM authentication required"),
        (struct.pack("!I", 10) + b"PLAIN\0\0", "pw", "unsupported SASL mechanisms"),
    ],
)
def test_auth_challenges_without_usable_credentials_fail_explicitly(
    monkeypatch: pytest.MonkeyPatch, payload: bytes, password: str | None, expected: str
) -> None:
    monkeypatch.setattr(pg, "_pg_send_startup", Mock())
    monkeypatch.setattr(pg, "_pg_read_message", Mock(return_value=(b"R", payload)))
    with pytest.raises(pg._PgAuditError, match=expected) as raised:
        pg._pg_startup_and_auth(None, "audit", password, "app")
    assert raised.value.detected is True


@pytest.mark.parametrize("wrapped", [False, True])
def test_tls_socket_cleanup_survives_close_errors(monkeypatch: pytest.MonkeyPatch, wrapped: bool) -> None:
    raw, secure = MagicMock(), MagicMock()
    raw.close.side_effect = OSError("raw already closed")
    secure.close.side_effect = OSError("TLS already closed")
    monkeypatch.setattr(pg.socket, "create_connection", Mock(return_value=raw))
    monkeypatch.setattr(pg, "_recv_exact", Mock(return_value=b"S"))
    context = Mock()
    context.wrap_socket.return_value = secure
    monkeypatch.setattr(pg, "shared_client_ssl_context", Mock(return_value=context))
    with pg._pg_open_socket("db", 5432, 2.0, tls_config=pg._PgTlsConfig("require" if wrapped else "disable")) as sock:
        assert sock is (secure if wrapped else raw)
    raw.close.assert_called_once()
    assert secure.close.call_count == int(wrapped)


@pytest.mark.parametrize("operation,empty", [("execute", "<no output>"), ("sql", "<ok>"), ("os_read", "<empty file>")])
@pytest.mark.parametrize("status", [True, False, None])
def test_operation_exports_distinguish_empty_success_denial_and_not_attempted(
    operation: str, empty: str, status: bool | None
) -> None:
    import json

    record = {
        "host": "db",
        "port": 5432,
        "database": "app",
        f"{operation}_ok": status,
        f"{operation}_output": [],
        f"{operation}_error": "permission denied" if status is False else None,
        f"{operation}_command" if operation != "os_read" else "os_read_path": "SELECT 1"
        if operation == "sql"
        else "id"
        if operation == "execute"
        else "/secret",
    }
    helper = getattr(pg, f"_format_{operation}_detail_records")
    text = "\n".join(helper(record, "txt"))
    assert (empty if status is True else "<error:permission denied>" if status is False else "<not attempted>") in text
    exported = helper(record, "json")
    assert len(exported) == 1 and json.loads(exported[0])["ok"] is status
    assert "\x1b" not in text and "\x1b" not in exported[0]
