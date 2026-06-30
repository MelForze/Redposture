"""Regression guard for interactive shell paths (--sql-shell / --os-shell).

These paths call `_audit_<module>_host(...)` directly with an explicit kwarg
list, separate from the AuditCommandRunner lifecycle. A drift between that call
site and the function signature shipped a crash in the field:

    TypeError: _audit_clickhouse_host() got an unexpected keyword argument
    'show_databases_limit'

The other shell tests monkeypatch the host function with a ``**kwargs``-swallowing
fake, so they cannot catch such a mismatch. These tests run the real shell path
with a signature-checking proxy that binds against the genuine signature, so any
future drift fails here instead of for a user.
"""

from __future__ import annotations

import inspect
from typing import Any

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.modules.clickhouse import actions as ch_actions
from redposture_core.modules.clickhouse import stage as ch_stage
from redposture_core.modules.postgres import actions as pg_actions
from redposture_core.modules.postgres import stage as pg_stage


def _signature_checking_proxy(real_fn: Any, return_value: dict[str, Any]):
    signature = inspect.signature(real_fn)

    def proxy(*args: Any, **kwargs: Any) -> dict[str, Any]:
        signature.bind(*args, **kwargs)  # raises TypeError if the shell call drifts
        return dict(return_value)

    return proxy


def test_signature_checking_proxy_rejects_unknown_kwarg() -> None:
    proxy = _signature_checking_proxy(ch_actions._audit_clickhouse_host, {"is_clickhouse": False})
    with pytest.raises(TypeError):
        proxy(show_databases_limit=5)  # the exact kwarg that crashed in the field


@pytest.mark.parametrize("shell_flag", ["--sql-shell", "--os-shell"])
def test_clickhouse_shell_binds_real_host_audit_signature(monkeypatch: pytest.MonkeyPatch, shell_flag: str) -> None:
    monkeypatch.setattr(ch_actions, "_load_clickhouse_driver_client", lambda *_a, **_k: None)
    monkeypatch.setattr(ch_actions, "_load_clickhouse_connect_module", lambda *_a, **_k: None)
    monkeypatch.setattr(ch_stage, "_emit_clickhouse_record", lambda *_a, **_k: None)
    monkeypatch.setattr(
        ch_actions,
        "_audit_clickhouse_host",
        _signature_checking_proxy(ch_actions._audit_clickhouse_host, {"is_clickhouse": False, "status": "fail"}),
    )

    args = parse_args(["clickhouse", "-t", "127.0.0.1", "-u", "rteam", "-p", "secret", shell_flag])
    rc = ch_stage.run_clickhouse_stage(args, logger=object())

    assert rc == 1  # not detected -> returns before the interactive loop, no TypeError


@pytest.mark.parametrize("shell_flag", ["--sql-shell", "--os-shell"])
def test_postgres_shell_binds_real_host_audit_signature(monkeypatch: pytest.MonkeyPatch, shell_flag: str) -> None:
    monkeypatch.setattr(
        pg_actions,
        "_audit_postgres_host",
        _signature_checking_proxy(pg_actions._audit_postgres_host, {"is_postgres": False, "status": "fail"}),
    )

    args = parse_args(["postgres", "-t", "127.0.0.1", "-u", "postgres", "-p", "postgres", shell_flag])
    rc = pg_stage.run_postgres_stage(args, logger=object())

    assert rc == 1  # not detected -> returns before the interactive loop, no TypeError
