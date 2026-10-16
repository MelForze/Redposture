"""NEXT_QA #6 — ZooKeeper implementation: guard-ветви auth/collect/probe.

Покрывает engine.py 270/290/310 (TypeError при неверном типе lifecycle-state —
отрицательный контракт) и 273/293/314 (fingerprint is None → ранний возврат
записи без имплементационной декорации — сервис не отпечатан, глубокая работа
пропускается).

Now part of the ordinary pytest suite.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.modules.keeper import stage as keeper_stage
from redposture_core.modules.zookeeper import engine as impl
from redposture_core.stage_runtime import AuditCredentialRun, AuditHookContext


def _fresh_impl_state():
    args = parse_args(["keeper", "-t", "127.0.0.1", "--retries", "0"])
    spec = keeper_stage.build_keeper_spec(args)
    assert spec.lifecycle_state_factory is not None
    state = spec.lifecycle_state_factory(
        AuditHookContext(
            args=args,
            logger=None,
            host="127.0.0.1",
            port=9181,
            credential=AuditCredentialRun(source="anonymous"),
            lifecycle_state=None,
        )
    )
    assert state.fingerprint is None  # свежее состояние — отпечатка ещё нет
    return state


_FUNCS = [
    impl.authenticate_zookeeper_implementation,
    impl.collect_zookeeper_implementation_data,
    impl.probe_zookeeper_implementation_capabilities,
]


@pytest.mark.parametrize("func", _FUNCS)
def test_wrong_lifecycle_state_raises_type_error(func) -> None:
    """Отрицательный контракт: не тот тип lifecycle-state → TypeError (270/290/310)."""
    ctx = SimpleNamespace(lifecycle_state=object())  # не ZooKeeperImplementationLifecycleState
    with pytest.raises(TypeError):
        func(ctx, {"is_zookeeper": True}, {})


@pytest.mark.parametrize("func", _FUNCS[:2])  # auth(273)/collect(293): ранний возврат ДО работы
def test_fingerprint_none_returns_record_unchanged_dict(func) -> None:
    """fingerprint=None + запись-dict → возврат как есть, без имплементационной декорации."""
    state = _fresh_impl_state()
    ctx = SimpleNamespace(lifecycle_state=state)
    record = {"is_zookeeper": True, "status": "open_no_auth", "marker": "unchanged"}
    out = func(ctx, record, {})
    assert out["marker"] == "unchanged"
    assert out.get("implementation") is None


@pytest.mark.parametrize("func", _FUNCS[:2])  # auth/collect используют .to_dict()
def test_fingerprint_none_uses_to_dict_branch(func) -> None:
    """fingerprint=None + объект с to_dict() → срабатывает ветвь hasattr(to_dict) (273/293)."""
    state = _fresh_impl_state()
    ctx = SimpleNamespace(lifecycle_state=state)
    rec = SimpleNamespace(to_dict=lambda: {"is_zookeeper": True, "via": "to_dict"})
    out = func(ctx, rec, {})
    assert out["via"] == "to_dict"


def test_probe_fingerprint_none_returns_probe_result_without_decoration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """probe(314): результат probe_zookeeper_capabilities возвращается как есть при fingerprint=None."""
    state = _fresh_impl_state()
    ctx = AuditHookContext(
        args=parse_args(["keeper", "-t", "127.0.0.1", "--retries", "0"]),
        logger=None,
        host="127.0.0.1",
        port=9181,
        credential=AuditCredentialRun(source="anonymous"),
        lifecycle_state=state,
    )
    sentinel = {"is_zookeeper": True, "probe": "capabilities", "marker": "raw"}
    monkeypatch.setattr(impl.zookeeper_actions, "probe_zookeeper_capabilities", lambda *_a, **_k: dict(sentinel))
    out = impl.probe_zookeeper_implementation_capabilities(ctx, {"is_zookeeper": True}, {})
    assert out["marker"] == "raw"
    assert out.get("implementation") is None  # без декорации (fingerprint отсутствует)
