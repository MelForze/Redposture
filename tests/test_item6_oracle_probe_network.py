"""NEXT_QA #6 — Oracle: сетевая ветвь проверки листенера `_try_probe_target`.

Oracle не поддерживает анонимную сессию, поэтому detect-pass отдельно проверяет
досягаемость листенера сырым сокетом:
  - листенер доступен → (None, "authentication required")  [положительный исход]
  - соединение не удалось → (None, normalize_oracle_error(OSError))  [отрицательный]

Покрывает modules/oracle/actions.py::_try_probe_target (339-346).

Now part of the ordinary pytest suite.
"""

from __future__ import annotations

import socket

from redposture_core.modules.oracle import actions as oracle_actions

_KW = dict(
    protocol="tcp",
    service="XEPDB1",
    sid=None,
    wallet=None,
    ssl_server_dn=None,
    insecure=False,
)


def test_probe_listener_reachable_returns_auth_required() -> None:
    """Положительный: листенер слушает → клиент не создаётся, причина 'authentication required'."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        client, reason = oracle_actions._try_probe_target("127.0.0.1", port, 2.0, **_KW)
    finally:
        srv.close()

    assert client is None
    assert reason == "authentication required"


def test_probe_listener_unreachable_returns_normalized_error() -> None:
    """Отрицательный: порт закрыт → клиент None, причина — нормализованная ошибка сокета."""
    # забираем свободный порт и сразу закрываем — соединение будет отклонено
    tmp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tmp.bind(("127.0.0.1", 0))
    closed_port = tmp.getsockname()[1]
    tmp.close()

    client, reason = oracle_actions._try_probe_target("127.0.0.1", closed_port, 1.0, **_KW)

    assert client is None
    assert isinstance(reason, str) and reason
    assert reason != "authentication required"  # это именно ошибка соединения, не auth


def test_probe_normalizes_dns_failure(monkeypatch) -> None:
    """Отрицательный: неразрешимый хост → OSError ветвь, нормализованная строка без трейсбека."""

    def unavailable(_address, *, timeout):
        raise socket.gaierror(socket.EAI_NONAME, "name not known")

    monkeypatch.setattr(oracle_actions.socket, "create_connection", unavailable)
    client, reason = oracle_actions._try_probe_target("nonexistent.invalid.redposture.test", 1521, 1.0, **_KW)
    assert client is None
    assert isinstance(reason, str) and reason
    assert "Traceback" not in reason
