from __future__ import annotations

import base64

from redposture_core.stage_postgres import (
    _audit_postgres_host,
    _caps_suffix,
    _format_table_dump_detail_records,
    _PgSession,
    _scram_client_final,
    _scram_client_first,
    audit_postgres_targets,
)


class _DummySocket:
    def __enter__(self) -> _DummySocket:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        return False

    def settimeout(self, timeout: float) -> None:
        _ = timeout

    def close(self) -> None:
        return


def test_dump_without_table_uses_all_readable_tables(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    dumped_tables: list[str] = []
    dumped_columns_queries: list[str] = []

    monkeypatch.setattr(
        "redposture_core.stage_postgres.socket.create_connection", lambda *_args, **_kwargs: _DummySocket()
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_startup_and_auth",
        lambda *_args, **_kwargs: _PgSession(auth_required=True, auth_method="cleartext", server_version="16.0"),
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._collect_postgres_privileges",
        lambda *_args, **_kwargs: (False, False, True, 2, None),
    )
    monkeypatch.setattr("redposture_core.stage_postgres._pg_query_databases", lambda *_args, **_kwargs: ([], None))
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_query_readable_tables",
        lambda *_args, **_kwargs: (["public.users", "public.audit_events"], None),
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_query_table_columns",
        lambda _sock, table_name, **_kwargs: (
            dumped_columns_queries.append(table_name) or table_name,
            ["id", "payload"],
            None,
        ),
    )
    monkeypatch.setattr("redposture_core.stage_postgres._pg_send_terminate", lambda *_args, **_kwargs: None)

    def fake_query_table_rows(
        _sock: object,
        table_name: str,
        *,
        columns: list[str] | None = None,
        max_rows: int = 100,
    ) -> tuple[str, list[str] | None, str | None]:
        _ = max_rows
        assert columns is None
        dumped_tables.append(table_name)
        return table_name, ['{"ok":true}'], None

    monkeypatch.setattr("redposture_core.stage_postgres._pg_query_table_rows", fake_query_table_rows)

    record = _audit_postgres_host(
        host="127.0.0.1",
        port=5432,
        timeout=1.0,
        retries=0,
        username=None,
        password=None,
        defcreds=True,
        database="postgres",
        show_databases=False,
        show_tables=False,
        show_columns=False,
        table_targets=[],
        table_columns=[],
        dump_table_rows=True,
        execute_command=None,
        sql_command=None,
    )

    assert dumped_tables == ["public.users", "public.audit_events"]
    assert dumped_columns_queries == ["public.users", "public.audit_events"]
    assert record["table_targets"] == ["public.users", "public.audit_events"]
    assert isinstance(record["table_dumps"], list) and len(record["table_dumps"]) == 2
    assert record["table_dumps"][0]["columns"] == ["id", "payload"]


def test_dump_with_table_and_columns_uses_only_selected(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    dumped: list[tuple[str, list[str] | None]] = []
    column_targets: list[str] = []

    monkeypatch.setattr(
        "redposture_core.stage_postgres.socket.create_connection", lambda *_args, **_kwargs: _DummySocket()
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_startup_and_auth",
        lambda *_args, **_kwargs: _PgSession(auth_required=True, auth_method="cleartext", server_version="16.0"),
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._collect_postgres_privileges",
        lambda *_args, **_kwargs: (False, False, True, 1, None),
    )
    monkeypatch.setattr("redposture_core.stage_postgres._pg_query_databases", lambda *_args, **_kwargs: ([], None))
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_query_readable_tables",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("unexpected")),
    )
    monkeypatch.setattr("redposture_core.stage_postgres._pg_send_terminate", lambda *_args, **_kwargs: None)

    def fake_query_table_columns(
        _sock: object,
        table_name: str,
        *,
        only_columns: list[str] | None = None,
    ) -> tuple[str, list[str] | None, str | None]:
        _ = only_columns
        column_targets.append(table_name)
        return table_name, ["id"], None

    def fake_query_table_rows(
        _sock: object,
        table_name: str,
        *,
        columns: list[str] | None = None,
        max_rows: int = 100,
    ) -> tuple[str, list[str] | None, str | None]:
        _ = max_rows
        dumped.append((table_name, columns))
        return table_name, ['{"id":1}'], None

    monkeypatch.setattr("redposture_core.stage_postgres._pg_query_table_columns", fake_query_table_columns)
    monkeypatch.setattr("redposture_core.stage_postgres._pg_query_table_rows", fake_query_table_rows)

    record = _audit_postgres_host(
        host="127.0.0.1",
        port=5432,
        timeout=1.0,
        retries=0,
        username=None,
        password=None,
        defcreds=True,
        database="postgres",
        show_databases=False,
        show_tables=False,
        show_columns=False,
        table_targets=["public.users"],
        table_columns=["id"],
        dump_table_rows=True,
        execute_command=None,
        sql_command=None,
    )

    assert column_targets == []
    assert dumped == [("public.users", ["id"])]
    assert record["table_targets"] == ["public.users"]


def test_show_columns_with_dump_prints_columns_and_dump(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    dumped: list[tuple[str, list[str] | None]] = []
    column_targets: list[str] = []

    monkeypatch.setattr(
        "redposture_core.stage_postgres.socket.create_connection", lambda *_args, **_kwargs: _DummySocket()
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_startup_and_auth",
        lambda *_args, **_kwargs: _PgSession(auth_required=True, auth_method="cleartext", server_version="16.0"),
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._collect_postgres_privileges",
        lambda *_args, **_kwargs: (False, False, True, 1, None),
    )
    monkeypatch.setattr("redposture_core.stage_postgres._pg_query_databases", lambda *_args, **_kwargs: ([], None))
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_query_readable_tables",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("unexpected")),
    )
    monkeypatch.setattr("redposture_core.stage_postgres._pg_send_terminate", lambda *_args, **_kwargs: None)

    def fake_query_table_columns(
        _sock: object,
        table_name: str,
        *,
        only_columns: list[str] | None = None,
    ) -> tuple[str, list[str] | None, str | None]:
        _ = only_columns
        column_targets.append(table_name)
        return table_name, ["id"], None

    def fake_query_table_rows(
        _sock: object,
        table_name: str,
        *,
        columns: list[str] | None = None,
        max_rows: int = 100,
    ) -> tuple[str, list[str] | None, str | None]:
        _ = max_rows
        dumped.append((table_name, columns))
        return table_name, ['{"id":1}'], None

    monkeypatch.setattr("redposture_core.stage_postgres._pg_query_table_columns", fake_query_table_columns)
    monkeypatch.setattr("redposture_core.stage_postgres._pg_query_table_rows", fake_query_table_rows)

    record = _audit_postgres_host(
        host="127.0.0.1",
        port=5432,
        timeout=1.0,
        retries=0,
        username=None,
        password=None,
        defcreds=True,
        database="postgres",
        show_databases=False,
        show_tables=False,
        show_columns=True,
        table_targets=["public.users"],
        table_columns=["id"],
        dump_table_rows=True,
        execute_command=None,
        sql_command=None,
    )

    assert column_targets == ["public.users"]
    assert dumped == [("public.users", ["id"])]
    table_columns_info = record.get("table_columns_info")
    assert isinstance(table_columns_info, list) and len(table_columns_info) == 1


def test_table_dump_txt_renders_columns_header_line() -> None:
    record = {
        "timestamp": "2026-03-11T00:00:00Z",
        "host": "127.0.0.1",
        "port": 5432,
        "database": "postgres",
        "table_dump_enabled": True,
        "table_columns": [],
        "table_dumps": [
            {
                "table": "public.users",
                "columns": ["id", "email"],
                "rows": ['{"id":1,"email":"admin@example.com"}'],
                "error": None,
            }
        ],
    }

    lines = _format_table_dump_detail_records(record, "txt")

    assert any("(columns:auto)" in line for line in lines)
    assert any("[id, email]" in line for line in lines)
    assert any('{"id":1,"email":"admin@example.com"}' in line for line in lines)


def test_audit_postgres_suppresses_connection_refused_when_suppression_enabled(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_audit(*_args, **_kwargs):
        return {
            "timestamp": "2026-03-02T00:00:00Z",
            "host": "127.0.0.1",
            "port": 5432,
            "database": "postgres",
            "is_postgres": False,
            "status": "fail",
            "auth_required": None,
            "auth_method": None,
            "provided_credentials": False,
            "provided_username": None,
            "provided_password": None,
            "defcreds_enabled": False,
            "effective_username": "postgres",
            "show_databases": False,
            "database_names": None,
            "database_count": None,
            "show_tables": False,
            "show_columns": False,
            "table_names": None,
            "table_targets": [],
            "table_columns": [],
            "table_dump_enabled": False,
            "table_columns_info": [],
            "table_dumps": [],
            "execute_command": None,
            "execute_attempted": False,
            "execute_ok": None,
            "execute_output": None,
            "execute_error": None,
            "sql_command": None,
            "sql_attempted": False,
            "sql_ok": None,
            "sql_output": None,
            "sql_error": None,
            "server_version": None,
            "superuser": None,
            "can_execute_commands": None,
            "can_read_tables": None,
            "readable_tables": None,
            "elapsed_ms": None,
            "error": "[Errno 111] Connection refused",
        }

    monkeypatch.setattr("redposture_core.stage_postgres._audit_postgres_host", fake_audit)

    lines: list[str] = []
    total, open_no_auth, weak, valid, auth_required, failed = audit_postgres_targets(
        hosts=["127.0.0.1"],
        port=5432,
        timeout=0.2,
        retries=0,
        workers=1,
        username=None,
        password=None,
        defcreds=False,
        database="postgres",
        show_databases=False,
        show_tables=False,
        show_columns=False,
        table_targets=[],
        table_columns=[],
        dump_table_rows=False,
        execute_command=None,
        sql_command=None,
        output_path=None,
        output_format="txt",
        emit_line=lines.append,
        suppress_timeout_status_lines=True,
    )

    assert (total, open_no_auth, weak, valid, auth_required, failed) == (1, 0, 0, 0, 0, 1)
    assert lines == []


def test_caps_suffix_reports_database_count_and_not_tables() -> None:
    suffix = _caps_suffix(
        {
            "superuser": False,
            "can_execute_commands": False,
            "can_read_tables": True,
            "database_count": 7,
            "database_names": None,
            "readable_tables": 99,
        }
    )

    assert "(DBs:7)" in suffix
    assert "(tables:" not in suffix


def test_defcreds_is_reported_when_anonymous_access_is_allowed(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(
        "redposture_core.stage_postgres.socket.create_connection", lambda *_args, **_kwargs: _DummySocket()
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_startup_and_auth",
        lambda *_args, **_kwargs: _PgSession(auth_required=False, auth_method=None, server_version="16.0"),
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._collect_postgres_privileges",
        lambda *_args, **_kwargs: (False, False, False, None, None),
    )
    monkeypatch.setattr("redposture_core.stage_postgres._pg_query_databases", lambda *_args, **_kwargs: ([], None))
    monkeypatch.setattr("redposture_core.stage_postgres._pg_send_terminate", lambda *_args, **_kwargs: None)

    record = _audit_postgres_host(
        host="127.0.0.1",
        port=5432,
        timeout=1.0,
        retries=0,
        username=None,
        password=None,
        defcreds=True,
        database="postgres",
        show_databases=False,
        show_tables=False,
        show_columns=False,
        table_targets=[],
        table_columns=[],
        dump_table_rows=False,
        execute_command=None,
        sql_command=None,
    )

    assert record["auth_required"] is False
    assert record["status"] == "weak_default_creds"


def test_show_tables_without_database_walks_all_accessible_databases(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    remote_calls: list[str] = []

    monkeypatch.setattr(
        "redposture_core.stage_postgres.socket.create_connection", lambda *_args, **_kwargs: _DummySocket()
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_startup_and_auth",
        lambda *_args, **_kwargs: _PgSession(auth_required=True, auth_method="cleartext", server_version="16.0"),
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._collect_postgres_privileges",
        lambda *_args, **_kwargs: (False, False, False, None, None),
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_query_databases",
        lambda *_args, **_kwargs: (["postgres", "appdb"], None),
    )
    monkeypatch.setattr("redposture_core.stage_postgres._pg_send_terminate", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_collect_database_artifacts",
        lambda _sock, **_kwargs: (["postgres.public.users"], [], [], 1, None),
    )

    def fake_remote(
        _host: str,
        _port: int,
        _timeout: float,
        _retries: int,
        _username: str,
        _password: str | None,
        database_name: str,
        **_kwargs,
    ):
        remote_calls.append(database_name)
        return (["appdb.audit.events"], [], [], 1, None)

    monkeypatch.setattr("redposture_core.stage_postgres._pg_collect_database_artifacts_remote", fake_remote)

    record = _audit_postgres_host(
        host="127.0.0.1",
        port=5432,
        timeout=1.0,
        retries=0,
        username=None,
        password=None,
        defcreds=True,
        database=None,
        show_databases=False,
        show_tables=True,
        show_columns=False,
        table_targets=[],
        table_columns=[],
        dump_table_rows=False,
        execute_command=None,
        sql_command=None,
    )

    assert remote_calls == ["appdb"]
    assert record["table_names"] == ["postgres.public.users", "appdb.audit.events"]
    assert record["can_read_tables"] is True
    assert record["readable_tables"] == 2


def test_database_limits_table_enumeration_to_selected_database(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    current_calls: list[str] = []
    remote_calls: list[str] = []

    monkeypatch.setattr(
        "redposture_core.stage_postgres.socket.create_connection", lambda *_args, **_kwargs: _DummySocket()
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_startup_and_auth",
        lambda *_args, **_kwargs: _PgSession(auth_required=True, auth_method="cleartext", server_version="16.0"),
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._collect_postgres_privileges",
        lambda *_args, **_kwargs: (False, False, False, None, None),
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_query_databases",
        lambda *_args, **_kwargs: (["postgres", "appdb", "analytics"], None),
    )
    monkeypatch.setattr("redposture_core.stage_postgres._pg_send_terminate", lambda *_args, **_kwargs: None)

    def fake_current(_sock, *, database_name: str, **_kwargs):
        current_calls.append(database_name)
        return (["public.accounts"], [], [], 1, None)

    def fake_remote(
        _host: str,
        _port: int,
        _timeout: float,
        _retries: int,
        _username: str,
        _password: str | None,
        database_name: str,
        **_kwargs,
    ):
        remote_calls.append(database_name)
        return ([f"{database_name}.public.accounts"], [], [], 1, None)

    monkeypatch.setattr("redposture_core.stage_postgres._pg_collect_database_artifacts", fake_current)
    monkeypatch.setattr("redposture_core.stage_postgres._pg_collect_database_artifacts_remote", fake_remote)

    record = _audit_postgres_host(
        host="127.0.0.1",
        port=5432,
        timeout=1.0,
        retries=0,
        username=None,
        password=None,
        defcreds=True,
        database="appdb",
        show_databases=False,
        show_tables=True,
        show_columns=False,
        table_targets=[],
        table_columns=[],
        dump_table_rows=False,
        execute_command=None,
        sql_command=None,
    )

    assert current_calls == ["appdb"]
    assert remote_calls == []
    assert record["table_names"] == ["public.accounts"]
    assert record["database"] == "appdb"
    assert record["auth_database"] == "appdb"


def test_scram_client_final_avoids_zip_strict_for_py39_compat(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def forbidden_zip(*_args, **_kwargs):
        raise AssertionError("zip() should not be used in SCRAM proof generation")

    monkeypatch.setattr("redposture_core.stage_postgres.zip", forbidden_zip, raising=False)

    state, _ = _scram_client_first("postgres")
    salt_b64 = base64.b64encode(b"redposture-salt").decode("ascii")
    server_first = f"r={state.client_nonce}server,s={salt_b64},i=4096"

    final_message, server_signature = _scram_client_final(state, "postgres", server_first)

    assert final_message.startswith("c=biws,r=")
    assert ",p=" in final_message
    assert isinstance(server_signature, str) and server_signature != ""
