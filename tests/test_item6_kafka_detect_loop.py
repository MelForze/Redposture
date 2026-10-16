"""NEXT_QA #6 — Kafka broker: arc-ветви главного цикла detect_kafka.

Покрывает решающие ветви `modules/kafka/actions.py::_kafka_lifecycle_detection_record`
(1236-1268) с мок-KafkaSession:
  - api-probe ok + metadata → три статуса auth (open_no_auth / auth_required / unknown_auth);
  - api-probe НЕ ok, ошибка НЕ SASL-кандидат → is_kafka=False, fail-запись.
(TLS-fallback и SASL-handshake-success arc — в backlog, нужен фейк-сокет; см. REPORT.)

Now part of the ordinary pytest suite.
"""

from __future__ import annotations

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.clients.kafka import KafkaApiVersionsResult
from redposture_core.modules.kafka import actions as kafka_actions
from redposture_core.stage_runtime import AuditCredentialRun, AuditHookContext


class _FakeSession:
    def __init__(self, probe, metadata) -> None:
        self._probe = probe
        self._metadata = metadata  # (dict|None, error|None)
        self.transport_mode = "plaintext"
        self.correlation_id = 1
        self.closed = False

    def detect(self):
        return self._probe

    def fetch_metadata(self, *, topics=None):
        return self._metadata

    def close(self) -> None:
        self.closed = True


def _make_fake_session_cls(probe, metadata):
    class _FakeKafkaSession:
        @staticmethod
        def open(*_args, **_kwargs):
            return _FakeSession(probe, metadata)

    return _FakeKafkaSession


def _run(monkeypatch: pytest.MonkeyPatch, probe, metadata):
    monkeypatch.setattr(kafka_actions, "KafkaSession", _make_fake_session_cls(probe, metadata))
    state = kafka_actions.KafkaLifecycleState(requested_use_tls=False)
    ctx = AuditHookContext(
        args=parse_args(["kafka", "-t", "127.0.0.1", "--retries", "0"]),
        logger=None,
        host="127.0.0.1",
        port=9092,
        credential=AuditCredentialRun(source="anonymous"),
        lifecycle_state=state,
    )
    return kafka_actions.detect_kafka(ctx, {"max_messages": 10}), state


_OK_PROBE = KafkaApiVersionsResult(ok=True, error_code=None, error=None, versions={0: (0, 2)})


def test_detect_open_no_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    rec, state = _run(monkeypatch, _OK_PROBE, ({"auth_required": False, "topics": []}, None))
    assert rec["is_kafka"] is True
    assert rec["status"] == "open_no_auth"
    assert rec["auth_required"] is False
    assert state.anonymous_session is not None


def test_detect_auth_required(monkeypatch: pytest.MonkeyPatch) -> None:
    rec, _ = _run(monkeypatch, _OK_PROBE, ({"auth_required": True, "topics": []}, None))
    assert rec["is_kafka"] is True
    assert rec["status"] == "auth_required"
    assert rec["auth_required"] is True


def test_detect_unknown_auth_when_metadata_absent_non_auth_error(monkeypatch: pytest.MonkeyPatch) -> None:
    # metadata=None + ошибка НЕ похожа на auth → auth_required=None → unknown_auth
    rec, _ = _run(monkeypatch, _OK_PROBE, (None, "transient metadata hiccup"))
    assert rec["is_kafka"] is True
    assert rec["status"] == "unknown_auth"
    assert rec["auth_required"] is None


def test_detect_api_probe_not_ok_non_sasl_is_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    probe = KafkaApiVersionsResult(ok=False, error_code=None, error="not a kafka protocol response", versions={})
    rec, state = _run(monkeypatch, probe, (None, None))
    assert rec["is_kafka"] is False
    assert rec["status"] == "fail"
    assert "not a kafka protocol response" in (rec.get("error") or "")
    assert state.is_kafka is False
