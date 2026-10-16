"""NEXT_QA #6 — Oracle: чтение файлов сервера через bfilename (security-значимо).

`clients/oracle.py::OracleAuditClient._read_directory_file_chunk` (878-934) — read
файлов ОС сервера через PL/SQL bfilename/dbms_lob. Два пути:
  1) var-путь (877-915): cursor.var → execute пишет :data → getvalue();
  2) fallback-query (916-934): если cursor.var недоступен → select ... from dual.
resolve_server_path подменяется (не ходим в БД за списком директорий).

Покрывает оба пути + клампинг параметров + закрытие cursor в finally + проброс
исключения PL/SQL. Продукт не меняется.

Now part of the ordinary pytest suite.
"""

from __future__ import annotations

import pytest

from redposture_core.clients.oracle import OracleAuditClient

_RESOLVED = {"directory": "DATA_PUMP_DIR", "relative_path": "secret.txt"}


class _FakeVar:
    def __init__(self) -> None:
        self._value = None

    def setvalue(self, value) -> None:
        self._value = value

    def getvalue(self):
        return self._value


class _VarCursor:
    """Эмулирует oracledb-cursor с .var(): execute «выполняет» PL/SQL и пишет :data."""

    def __init__(self, content: str | None = "SECRET_FILE_CONTENT", raise_on_execute: bool = False) -> None:
        self.content = content
        self.raise_on_execute = raise_on_execute
        self.executed: list[tuple[str, dict]] = []
        self.closed = False

    def var(self, _typ):
        return _FakeVar()

    def execute(self, sql: str, params: dict) -> None:
        self.executed.append((sql, dict(params)))
        if self.raise_on_execute:
            raise RuntimeError("ORA-29283: invalid file operation")
        # симулируем, что PL/SQL записал прочитанные байты в :data
        params["data"].setvalue(self.content)

    def close(self) -> None:
        self.closed = True


class _PlainCursor:
    """Без .var() → активируется fallback-ветвь через self.query()."""

    def __init__(self, rows: list[tuple]) -> None:
        self.rows = rows
        self.description = [("DATA", None, None, None, None, None, None)]
        self.executed: list[tuple[str, dict]] = []
        self.closed = False

    # намеренно НЕТ атрибута var
    def execute(self, sql: str, params: dict) -> None:
        self.executed.append((sql, dict(params)))

    def fetchmany(self, n: int):
        return self.rows[:n]

    def fetchall(self):
        return self.rows

    def close(self) -> None:
        self.closed = True


class _Conn:
    def __init__(self, cursor) -> None:
        self._cursor = cursor

    def cursor(self):
        return self._cursor


def _client(cursor) -> OracleAuditClient:
    client = OracleAuditClient(_Conn(cursor))
    client.resolve_server_path = lambda _path: dict(_RESOLVED)  # type: ignore[assignment]
    return client


def test_var_path_reads_file_and_clamps_params() -> None:
    """var-путь: возвращает содержимое из getvalue(); параметры клампятся; cursor закрыт."""
    cur = _VarCursor(content="LINE1\nAWS_SECRET=wJalrXUtnFEMI")
    client = _client(cur)

    out = client._read_directory_file_chunk("/u01/app/secret.txt", offset=-5, amount=99999)

    assert out["method"] == "bfilename"
    assert out["ok"] is True
    assert out["data"] == "LINE1\nAWS_SECRET=wJalrXUtnFEMI"
    assert out["directory"] == "DATA_PUMP_DIR"
    assert out["relative_path"] == "secret.txt"
    assert out["error"] is None
    assert cur.closed is True
    # клампинг: amount<=32767, offset_value>=1
    _sql, params = cur.executed[0]
    assert params["amount"] == 32767
    assert params["offset_value"] == 1  # max(1, -5 + 1)
    assert params["directory_name"] == "DATA_PUMP_DIR"
    assert params["file_name"] == "secret.txt"


def test_var_path_offset_translated_to_one_based() -> None:
    cur = _VarCursor(content="X")
    client = _client(cur)
    client._read_directory_file_chunk("/u01/x", offset=10, amount=100)
    _sql, params = cur.executed[0]
    assert params["offset_value"] == 11  # offset + 1
    assert params["amount"] == 100


def test_var_path_execute_error_propagates_and_closes_cursor() -> None:
    """PL/SQL ошибка пробрасывается наружу, но cursor всё равно закрыт (finally)."""
    cur = _VarCursor(raise_on_execute=True)
    client = _client(cur)
    with pytest.raises(RuntimeError, match="ORA-29283"):
        client._read_directory_file_chunk("/u01/x", offset=0, amount=10)
    assert cur.closed is True


def test_fallback_query_path_returns_data() -> None:
    """Без cursor.var → fallback select from dual; данные берутся из строки результата."""
    cur = _PlainCursor(rows=[("FILE_VIA_QUERY",)])
    client = _client(cur)
    out = client._read_directory_file_chunk("/u01/x", offset=0, amount=50)
    assert out["method"] == "bfilename"
    assert out["ok"] is True
    assert out["data"] == "FILE_VIA_QUERY"
    assert out["relative_path"] == "secret.txt"


def test_fallback_query_path_empty_is_not_ok() -> None:
    """Fallback без строк → ok=False, data=None (пустой результат честно помечен)."""
    cur = _PlainCursor(rows=[])
    client = _client(cur)
    out = client._read_directory_file_chunk("/u01/x", offset=0, amount=50)
    assert out["ok"] is False
    assert out["data"] is None
