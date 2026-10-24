"""A definitive SASL rejection must survive the default-credential sweep."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.cli_args import parse_args
from redposture_core.console import Console
from redposture_core.modules.airflow import render as airflow_render
from redposture_core.modules.kafka import actions
from redposture_core.modules.kafka.stage import build_kafka_spec
from redposture_core.stage_runtime import AuditCommandRunner, AuditCredentialRun


@pytest.fixture
def auth_context():
    state = actions.KafkaLifecycleState(is_kafka=True, auth_required=True, transport_mode="plaintext")
    messages: list[str] = []
    ctx = SimpleNamespace(
        host="localhost",
        port=9092,
        args=SimpleNamespace(timeout=1, retries=0, debug=True),
        lifecycle_state=state,
        credential=AuditCredentialRun(username="admin", password="qa-secret", source="default"),
        debug_emit=messages.append,
    )
    try:
        yield ctx, messages
    finally:
        state.close()


def install_session(monkeypatch, *, ok, error):
    class Session:
        transport_mode = "plaintext"

        def bootstrap(self, **kwargs):
            return ok, error

        def fetch_metadata(self, *, topics=None):
            return {"auth_required": False, "topic_map": {}}, None

        def close(self):
            pass

    monkeypatch.setattr(actions.KafkaSession, "open", lambda *args, **kwargs: Session())


@pytest.mark.parametrize("source", ["default", "provided"])
@pytest.mark.parametrize(
    "ok,error,marker",
    [
        (False, "SASL auth failed: Authentication failed: Invalid username or password", "[-]"),
        (None, "SASL handshake failed: UNSUPPORTED_SASL_MECHANISM", None),
        (True, None, "[+]"),
    ],
)
def test_protocol_verdict_survives_sweep_aggregation_and_rendering(
    monkeypatch, auth_context, source, ok, error, marker
):
    ctx, _messages = auth_context
    ctx.credential = AuditCredentialRun(username="admin", password="qa-secret", source=source)
    install_session(monkeypatch, ok=ok, error=error)
    record = actions.authenticate_kafka(
        ctx, {"host": "localhost", "port": 9092, "is_kafka": True, "status": "auth_required"}, {}
    )
    assert record["credential_attempts"][0]["ok"] is ok
    assert record["provided_credentials_ok"] is ok
    args = parse_args(["kafka", "-t", "localhost:9092", "--defcreds"])
    runner = AuditCommandRunner(args=args, spec=build_kafka_spec(args), emit_line=lambda line: None)
    audit = AuditRecord.from_mapping(record, module="kafka", service="kafka")
    merged = runner._with_attempted_credentials(audit, [(ctx.credential, audit)], force=True).to_dict()
    assert merged["attempted_credentials"][0]["provided_credentials_ok"] is ok
    lines = actions._format_credential_attempts_records(merged, "txt")
    if marker:
        assert len(lines) == 1 and f"{marker} admin:qa-secret" in lines[0]
        assert "inconclusive" not in lines[0]
    else:
        assert len(lines) == 1 and "1 credential check(s) inconclusive" in lines[0]
    assert "\x1b" not in json.dumps(merged) + "\n".join(lines)


@pytest.mark.parametrize(
    "error",
    [
        TimeoutError("connect timed out"),
        ConnectionError("connection reset"),
        ValueError("truncated bootstrap response"),
    ],
)
@pytest.mark.parametrize("source", ["default", "provided"])
def test_connection_or_bootstrap_failure_is_not_an_invalid_password(monkeypatch, auth_context, error, source):
    ctx, _messages = auth_context
    ctx.credential = AuditCredentialRun(username="admin", password="qa-secret", source=source)

    def failed_open(*args, **kwargs):
        raise error

    monkeypatch.setattr(actions.KafkaSession, "open", failed_open)
    record = actions.authenticate_kafka(ctx, {"status": "auth_required"}, {})
    assert record["credential_attempts"][0]["ok"] is None
    assert record["provided_credentials_ok"] is None


@pytest.mark.parametrize(
    "ok,error,verdict",
    [
        (False, "SASL auth failed: Invalid username or password", "invalid"),
        (None, "SASL handshake failed: UNSUPPORTED_SASL_MECHANISM", "inconclusive"),
        (True, None, "valid"),
    ],
)
def test_debug_exposes_actual_auth_reason(monkeypatch, auth_context, ok, error, verdict):
    ctx, messages = auth_context
    install_session(monkeypatch, ok=ok, error=error)
    actions.authenticate_kafka(ctx, {"status": "auth_required"}, {})
    assert len(messages) == 1
    assert f"verdict={verdict}" in messages[0] and "mechanism=PLAIN" in messages[0]
    if error:
        assert error in messages[0]
    assert "qa-secret" not in messages[0]


def test_debug_does_not_echo_reflected_secret_or_terminal_escapes(monkeypatch, auth_context):
    ctx, messages = auth_context
    install_session(monkeypatch, ok=False, error="SASL failure qa-secret\n\x1b[31m" + "x" * 3000)
    actions.authenticate_kafka(ctx, {"status": "auth_required"}, {})
    assert len(messages) == 1
    assert "qa-secret" not in messages[0] and "\n" not in messages[0] and "\x1b" not in messages[0]
    assert len(messages[0]) < 1000


def test_debug_off_keeps_auth_diagnostics_out_of_normal_output(monkeypatch, auth_context):
    ctx, messages = auth_context
    ctx.args.debug = False
    install_session(monkeypatch, ok=False, error="SASL auth failed")
    actions.authenticate_kafka(ctx, {"status": "auth_required"}, {})
    assert messages == []


@pytest.mark.parametrize("marker", ["[-]", "[+]"])
def test_pair_colors_follow_airflow_and_no_color_is_plain(capsys, marker):
    actions._render_colored_kafka_line(Console(no_color=False), f"KAFKA\tlocalhost\t9092\t {marker} admin:qa-secret")
    kafka = capsys.readouterr().out
    airflow_render._render_colored_airflow_line(
        Console(no_color=False), f"AIRFLOW\tlocalhost\t8080\t {marker} admin:qa-secret"
    )
    airflow = capsys.readouterr().out
    for text in (kafka, airflow):
        assert ("\x1b[1;38;5;196m[-]" if marker == "[-]" else "\x1b[1;92m[+]") in text
    actions._render_colored_kafka_line(Console(no_color=True), f"KAFKA\tlocalhost\t9092\t {marker} admin:qa-secret")
    assert "\x1b" not in capsys.readouterr().out
