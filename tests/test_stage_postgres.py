from __future__ import annotations

from redposture_core.stage_postgres import _audit_postgres_host, _PgSession


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
