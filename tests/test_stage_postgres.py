from __future__ import annotations

from redposture_core.stage_postgres import _audit_postgres_host, _PgSession, audit_postgres_targets


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
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_query_readable_tables",
        lambda *_args, **_kwargs: (["public.users", "public.audit_events"], None),
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
    )

    assert dumped_tables == ["public.users", "public.audit_events"]
    assert record["table_targets"] == ["public.users", "public.audit_events"]
    assert isinstance(record["table_dumps"], list) and len(record["table_dumps"]) == 2


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
    )

    assert column_targets == ["public.users"]
    assert dumped == [("public.users", ["id"])]
    table_columns_info = record.get("table_columns_info")
    assert isinstance(table_columns_info, list) and len(table_columns_info) == 1


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
        output_path=None,
        output_format="txt",
        emit_line=lines.append,
        suppress_timeout_status_lines=True,
    )

    assert (total, open_no_auth, weak, valid, auth_required, failed) == (1, 0, 0, 0, 0, 1)
    assert lines == []
