"""NEXT_QA #6 — ZooKeeper implementation: render-ветвь НЕ-обнаружения (отрицательный исход).

Покрывает `modules/zookeeper/engine.py::_implementation_detection_payload` +
негативную ветвь `detect_zookeeper_implementation` (is_zookeeper=False → payload
с detected=False/is_keeper=None/vendor=None/implementation_confidence=unconfirmed).
Эта ветвь вызывается ТОЛЬКО когда базовый detect_zookeeper не подтвердил сервис;
позитивный исход уже покрыт test_stage_keeper (vendor=clickhouse через _decorate).

Now part of the ordinary pytest suite.
"""

from __future__ import annotations

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.modules.keeper import stage as keeper_stage
from redposture_core.modules.zookeeper import engine as implementation_engine
from redposture_core.stage_runtime import AuditCredentialRun, AuditHookContext


def _build_ctx(monkeypatch: pytest.MonkeyPatch, negative_record: dict):
    args = parse_args(["keeper", "-t", "127.0.0.1", "--retries", "0"])
    spec = keeper_stage.build_keeper_spec(args)
    assert spec.lifecycle_state_factory is not None and spec.detect is not None
    state = spec.lifecycle_state_factory(None)

    def fake_detect(ctx, _options):
        # базовый zookeeper-детект не подтвердил сервис
        return dict(negative_record)

    monkeypatch.setattr(implementation_engine.zookeeper_actions, "detect_zookeeper", fake_detect)
    ctx = AuditHookContext(
        args=args,
        logger=None,
        host="127.0.0.1",
        port=9181,
        credential=AuditCredentialRun(source="anonymous"),
        lifecycle_state=state,
    )
    return spec, ctx


def test_implementation_not_detected_renders_negative_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    """Отрицательный исход: сервис не ZooKeeper → payload помечает не-обнаружение честно."""
    spec, ctx = _build_ctx(
        monkeypatch,
        {
            "host": "127.0.0.1",
            "port": 9181,
            "is_zookeeper": False,
            "status": "not_keeper",
            "auth_required": None,
            "error": "connection refused",
        },
    )
    payload = spec.detect(ctx).to_dict()

    # детект-негатив
    assert payload["is_zookeeper"] is False
    assert payload["is_zookeeper_compatible"] is False
    assert payload["status"] == "not_keeper"
    assert payload["error"] == "connection refused"
    # fingerprint отсутствует → всё неизвестно, vendor не выдумывается
    assert payload["is_keeper"] is None
    assert payload["vendor"] is None
    assert payload["implementation"] is None
    assert payload["implementation_confidence"] == "unconfirmed"
    assert payload["fingerprint_confidence"] == "unconfirmed"
    assert payload["quorum_status"] == "unknown"
    assert payload["version"] is None
    # не запускаются чтения/записи znode
    assert payload["znode_count"] is None
    assert payload["can_create_znode"] is None
    assert payload["provided_credentials"] is False


def test_negative_payload_passes_through_telemetry_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    """Телеметрия базового detect (attempts/stages/connect_error) пробрасывается в negative payload."""
    spec, ctx = _build_ctx(
        monkeypatch,
        {
            "host": "127.0.0.1",
            "port": 9181,
            "is_zookeeper": False,
            "status": "fail",
            "auth_required": None,
            "error": "timeout",
            "attempts": 3,
            "max_attempts": 3,
            "stages": ["connect", "fourletter"],
            "stage_failed_at": "connect",
            "connect_error": "timed out",
        },
    )
    payload = spec.detect(ctx).to_dict()

    # ветвь passthrough телеметрии (engine 195-197) сработала: базовые поля скопированы
    assert payload["status"] == "fail"
    assert payload["attempts"] == 3
    assert payload["max_attempts"] == 3
    # и при этом остаётся корректным негативом
    assert payload["is_zookeeper"] is False
    assert payload["vendor"] is None


def test_negative_payload_respects_discovery_options(monkeypatch: pytest.MonkeyPatch) -> None:
    """Опции show-znodes/dump/probe-write отражены в payload даже при не-обнаружении."""
    args = parse_args(["keeper", "-t", "127.0.0.1", "--retries", "0", "--show-znodes", "--dump", "--probe-write"])
    spec = keeper_stage.build_keeper_spec(args)
    assert spec.lifecycle_state_factory is not None and spec.detect is not None
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
    monkeypatch.setattr(
        implementation_engine.zookeeper_actions,
        "detect_zookeeper",
        lambda _ctx, _options: {
            "host": "127.0.0.1",
            "port": 9181,
            "is_zookeeper": False,
            "status": "not_keeper",
            "auth_required": None,
            "error": None,
        },
    )
    ctx = AuditHookContext(
        args=args,
        logger=None,
        host="127.0.0.1",
        port=9181,
        credential=AuditCredentialRun(source="anonymous"),
        lifecycle_state=state,
    )
    payload = spec.detect(ctx).to_dict()

    assert payload["show_znodes"] is True
    assert payload["dump"] is True
    assert payload["probe_write_requested"] is True
    assert payload["znode_capability_scope"] == "/"
    assert payload["is_zookeeper"] is False
