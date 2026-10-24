"""Contracts for bounded inventories, mixed action outcomes, and stream ownership."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import Mock

import pytest

from redposture_core.modules.clickhouse import actions as ch
from redposture_core.shell_capture import CommandResult


def _session(protocol: str = "native", client: Any = None) -> ch._ChSession:
    return ch._ChSession(protocol, client, "audit", "secret", "app")


@pytest.mark.parametrize(
    ("first_error", "fallback_error", "verdict", "supported", "query_count"),
    [
        ("Code: 62. syntax error", None, True, False, 2),
        ("Code: 48. not implemented", "access denied", False, False, 2),
        ("Code: 62. syntax error", "transport failed", None, False, 2),
        ("Code: 497. access denied", None, False, True, 1),
        ("transport failed", None, None, None, 1),
    ],
)
def test_read_grant_fallback_only_for_unsupported_syntax(
    monkeypatch: pytest.MonkeyPatch,
    first_error: str,
    fallback_error: str | None,
    verdict: bool | None,
    supported: bool | None,
    query_count: int,
) -> None:
    session = _session()
    query = Mock(side_effect=[(None, first_error), ([], fallback_error)])
    monkeypatch.setattr(ch, "_query_rows", query)
    result, error = ch._check_table_read_access(session, "app space", "odd`table")
    assert result is verdict and session.check_grant_supported is supported
    assert query.call_count == query_count
    assert query.call_args_list[0].args[1] == "CHECK GRANT SELECT ON `app space`.`odd``table`"
    if query_count == 2:
        assert query.call_args.args[1] == "SELECT * FROM `app space`.`odd``table` LIMIT 0"
    assert error == (
        fallback_error
        if query_count == 2 and verdict is None
        else first_error
        if query_count == 1 and verdict is None
        else None
    )


def test_unsupported_check_grant_is_cached_per_session(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _session()
    query = Mock(side_effect=[(None, "Code: 62. syntax error"), ([], None), ([], None)])
    monkeypatch.setattr(ch, "_query_rows", query)
    assert ch._check_table_read_access(session, "app", "one") == (True, None)
    assert ch._check_table_read_access(session, "app", "two") == (True, None)
    assert [call.args[1] for call in query.call_args_list] == [
        "CHECK GRANT SELECT ON `app`.`one`",
        "SELECT * FROM `app`.`one` LIMIT 0",
        "SELECT * FROM `app`.`two` LIMIT 0",
    ]


def test_readable_inventory_keeps_denied_unknown_and_invalid_siblings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        ch,
        "_query_visible_tables",
        Mock(return_value=(["app.good", "app.denied", "app.unknown", "a.b.c", "app.unchecked"], None)),
    )
    check = Mock(side_effect=[(True, None), (False, None), (None, "timeout")])
    monkeypatch.setattr(ch, "_check_table_read_access", check)
    result = ch._query_readable_tables(_session(), 4, detailed=True)
    assert result == (
        ["app.good"],
        [
            {"table": "app.good", "readable": True},
            {"table": "app.denied", "readable": False},
            {"table": "app.unknown", "readable": "unknown"},
            {"table": "a.b.c", "readable": "unknown"},
        ],
        True,
        ["app.unknown: timeout", "invalid table name returned by server: a.b.c"],
    )
    assert check.call_count == 3


def _actions(session: ch._ChSession, **overrides: Any) -> dict[str, Any]:
    options: dict[str, Any] = dict(
        database="app",
        show_databases=False,
        show_tables=False,
        show_columns=False,
        table_targets=[],
        table_columns=[],
        dump_table_rows=False,
        dump_row_limit=2,
        execute_command=None,
        sql_command=None,
        limited_session=True,
    )
    options.update(overrides)
    return ch._run_clickhouse_actions_on_session(session, **options)


def test_mixed_actions_keep_successful_data_and_each_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ch, "_query_database_names", Mock(return_value=(["app", "other"], None)))
    monkeypatch.setattr(
        ch,
        "_query_readable_tables",
        Mock(
            return_value=(
                ["app.good"],
                [{"table": "app.good", "readable": True}, {"table": "app.bad", "readable": "unknown"}],
                False,
                ["app.bad: timeout"],
            )
        ),
    )
    monkeypatch.setattr(
        ch,
        "_query_table_columns",
        Mock(side_effect=[(["id"], None), (None, "columns denied"), (["id"], None), (None, "columns denied")]),
    )
    monkeypatch.setattr(ch, "_query_table_rows", Mock(side_effect=[(["[1]"], None), (None, "rows denied")]))
    monkeypatch.setattr(ch, "_run_sql_query", Mock(return_value=(["retained sql"], None)))
    monkeypatch.setattr(
        ch,
        "_run_execute_command_bytes",
        Mock(return_value=CommandResult(stdout=b"kept\x00", stderr=b"err\x00", exit_code=7)),
    )
    result = _actions(
        _session(),
        show_databases=True,
        show_databases_limit=1,
        show_tables=True,
        show_columns=True,
        table_targets=["app.good", "app.bad"],
        dump_table_rows=True,
        sql_command="SELECT 1",
        execute_command="whoami",
    )
    assert result["database_names"] == ["app"] and result["database_count"] is None
    assert result["table_names"] == ["app.good"] and result["read_capability"] is True
    assert result["table_dumps"] == [
        {"table": "app.good", "columns": ["id"], "rows": ["[1]"], "error": None},
        {"table": "app.bad", "columns": [], "rows": [], "error": "rows denied; columns: columns denied"},
    ]
    assert result["action_statuses"] == dict(
        databases="partial",
        tables="partial",
        columns="partial",
        dump="partial",
        sql="ok",
        execute="error",
        discover="not_requested",
    )
    assert result["partial"] is True and result["requested_operation_failure"] is True
    assert result["sql_output"] == ["retained sql"] and result["sql_ok"] is True
    assert result["execute_ok"] is False and result["execute_error"] == "exit code 7"
    assert result["execute_stdout_base64"] == "a2VwdAA=" and result["execute_stderr_base64"] == "ZXJyAA=="
    assert result["partial_reasons"] == [
        "databases: result truncated by requested limit",
        "tables: app.bad: timeout",
        "columns app.bad: columns denied",
        "dump app.bad: rows denied; columns: columns denied",
        "execute: exit code 7",
    ]


@pytest.mark.parametrize(
    ("access", "errors", "truncated", "expected"),
    [
        ([{"table": "app.a", "readable": False}], [], False, False),
        ([{"table": "app.a", "readable": False}], [], True, None),
        ([{"table": "app.a", "readable": "unknown"}], ["timeout"], False, None),
        ([], ["inventory denied"], False, None),
    ],
)
def test_table_denials_only_prove_unreadable_when_inventory_is_complete(
    monkeypatch: pytest.MonkeyPatch,
    access: list[dict[str, Any]],
    errors: list[str],
    truncated: bool,
    expected: bool | None,
) -> None:
    monkeypatch.setattr(ch, "_query_readable_tables", Mock(return_value=([], access, truncated, errors)))
    result = _actions(_session(), show_tables=True)
    assert result["read_capability"] is expected
    assert result["table_access"] == access
    assert result["action_statuses"]["tables"] == (
        "error" if errors and not access else "partial" if errors or truncated else "ok"
    )


def test_selected_columns_skip_metadata_but_still_dump_selected_table(monkeypatch: pytest.MonkeyPatch) -> None:
    metadata = Mock(side_effect=AssertionError("unrequested metadata"))
    rows = Mock(return_value=(["[3]"], None))
    monkeypatch.setattr(ch, "_query_table_columns", metadata)
    monkeypatch.setattr(ch, "_query_table_rows", rows)
    result = _actions(_session(), table_targets=["app.Events"], table_columns=["CaseSensitive"], dump_table_rows=True)
    assert result["table_dumps"] == [
        {"table": "app.Events", "columns": ["CaseSensitive"], "rows": ["[3]"], "error": None}
    ]
    assert rows.call_args.kwargs == {"columns": ["CaseSensitive"], "max_rows": 2}
    metadata.assert_not_called()


class _Stream:
    def __init__(self, rows: list[Any], *, failure: bool = False):
        self.rows = rows
        self.closed = 0
        self.failure = failure

    def __iter__(self):
        yield from self.rows
        if self.failure:
            raise OSError("stream interrupted")

    def close(self) -> None:
        self.closed += 1


@pytest.mark.parametrize("protocol", ["native", "http", "fallback"])
def test_sql_output_limit_closes_each_transport_stream(monkeypatch: pytest.MonkeyPatch, protocol: str) -> None:
    stream = _Stream([[b"one"], (2,), "scalar"])
    client = Mock(
        spec=["execute_iter"] if protocol == "native" else ["query_rows_stream"] if protocol == "http" else []
    )
    owner = None
    if protocol == "native":
        client.execute_iter.return_value = stream
    elif protocol == "http":
        owner = Mock(__enter__=Mock(return_value=stream), __exit__=Mock(return_value=None))
        client.query_rows_stream.return_value = owner
    else:
        monkeypatch.setattr(ch, "_query_rows", Mock(return_value=(stream.rows, None)))
    output, error = ch._run_sql_query(
        _session("http" if protocol == "http" else "native", client), "SELECT v", max_lines=2
    )
    assert error is None
    assert output == ['["one"]', "[2]", "<output truncated at 2 lines>"]
    if owner is not None:
        owner.__exit__.assert_called_once_with(None, None, None)
    elif protocol == "native":
        assert stream.closed == 1


@pytest.mark.parametrize("protocol", ["native", "http"])
def test_sql_stream_error_retains_rows_already_received(protocol: str) -> None:
    stream = _Stream([["valuable row"]], failure=True)
    if protocol == "native":
        client = Mock(spec=["execute_iter"])
        client.execute_iter.return_value = stream
    else:
        client = Mock(spec=["query_rows_stream"])
        client.query_rows_stream.return_value = stream
    rows, error = ch._run_sql_query(_session(protocol, client), "SELECT v")
    assert error and "stream interrupted" in error
    assert stream.closed == 1
    assert [json.loads(row) for row in rows] == [["valuable row"]]


@pytest.mark.parametrize("rows", [[], [["one"], ["two"]]])
def test_sql_context_stream_failure_preserves_prefix_and_exits_owner_once(rows: list[Any]) -> None:
    stream = _Stream(rows, failure=True)
    owner = Mock(__enter__=Mock(return_value=stream), __exit__=Mock(return_value=None))
    client = Mock(spec=["query_rows_stream"])
    client.query_rows_stream.return_value = owner
    output, error = ch._run_sql_query(_session("http", client), "SELECT v")
    assert [json.loads(row) for row in output] == rows
    assert error and "stream interrupted" in error
    owner.__exit__.assert_called_once_with(None, None, None)
    assert stream.closed == 0  # the context owns cleanup, rather than both paths
