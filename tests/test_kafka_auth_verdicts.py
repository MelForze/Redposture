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
        args=SimpleNamespace(timeout=1, retries=0, debug=True, probe_topic=True),
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


@pytest.mark.parametrize("ok", [False, None])
def test_unverified_identity_never_creates_or_deletes_a_topic(monkeypatch, auth_context, ok):
    ctx, _ = auth_context
    install_session(monkeypatch, ok=ok, error="not verified")
    monkeypatch.setattr(actions, "probe_topic_lifecycle", lambda *a, **kw: pytest.fail("unverified mutation"))
    result = actions.authenticate_kafka(ctx, {"status": "auth_required"}, {})
    assert "topic_lifecycle" not in result and "credential_capabilities" not in result


def test_verified_pair_evidence_survives_runtime_aggregation(monkeypatch, auth_context):
    ctx, _ = auth_context
    install_session(monkeypatch, ok=True, error=None)
    monkeypatch.setattr(
        actions,
        "probe_topic_lifecycle",
        lambda *a, **kw: {
            "create": kw["password"] == "one",
            "delete": True if kw["password"] == "one" else None,
            "cleanup_complete": True,
        },
    )
    attempts = []
    for password in ("one", "two"):
        ctx.credential = AuditCredentialRun(username="same", password=password, source="default")
        result = actions.authenticate_kafka(ctx, {"host": "broker", "port": 9092, "status": "auth_required"}, {})
        attempts.append((ctx.credential, AuditRecord.from_mapping(result, module="kafka", service="kafka")))
    args = parse_args(["kafka", "-t", "broker:9092", "--defcreds"])
    runner = AuditCommandRunner(args=args, spec=build_kafka_spec(args), emit_line=lambda line: None)
    record = runner._with_attempted_credentials(attempts[0][1], attempts, force=True).to_dict()
    rows = record["attempted_credentials"]
    assert rows[0]["credential_capabilities"]["topic_lifecycle"]["create"] is True
    assert rows[1]["credential_capabilities"]["topic_lifecycle"]["create"] is False
    lines = actions._format_credential_attempts_records(record, "txt")
    assert "Topic create:True" in lines[0] and "Topic delete:True" in lines[0]
    assert "Topic create:False" in lines[1] and "Topic delete:unknown" in lines[1]


def test_cancellation_closes_the_session_not_yet_registered_in_lifecycle(monkeypatch, auth_context):
    ctx, _ = auth_context

    class Session:
        transport_mode = "plaintext"
        closed = False

        def bootstrap(self, **kw):
            return True, None

        def fetch_metadata(self, **kw):
            return {"topic_map": {}}, None

        def close(self):
            self.closed = True

    session = Session()
    monkeypatch.setattr(actions.KafkaSession, "open", lambda *a, **kw: session)

    def interrupt(*a, **kw):
        raise KeyboardInterrupt

    monkeypatch.setattr(actions, "probe_topic_lifecycle", interrupt)
    with pytest.raises(KeyboardInterrupt):
        actions.authenticate_kafka(ctx, {"status": "auth_required"}, {})
    assert session.closed and ctx.lifecycle_state.authenticated_session is None


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
    messages = [message for message in messages if "kafka auth mechanism=" in message]
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


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("source", ["default", "provided"])
def test_real_topic_mutation_requires_explicit_opt_in(monkeypatch, auth_context, enabled, source):
    ctx, _ = auth_context
    ctx.args.probe_topic = enabled
    ctx.credential = AuditCredentialRun(username="admin", password="qa-secret", source=source)
    install_session(monkeypatch, ok=True, error=None)
    calls = []

    def probe(*args, **kwargs):
        calls.append(kwargs)
        return {"create": True, "delete": True, "cleanup_complete": True}

    monkeypatch.setattr(actions, "probe_topic_lifecycle", probe)
    args = parse_args(["kafka", "-t", "broker:9092", *(["--probe-topic"] if enabled else [])])
    from redposture_core.modules.kafka.stage import _build_kafka_lifecycle_options

    result = actions.authenticate_kafka(ctx, {"status": "auth_required"}, _build_kafka_lifecycle_options(args))
    assert len(calls) == int(enabled)
    assert ("topic_lifecycle" in result) is enabled
    assert ("topic_lifecycle" in result["credential_capabilities"]) is enabled
    line = actions._with_optional_topics(result, "[+] admin:qa-secret")
    assert ("Topic create:" in line) is enabled
    assert ("Topic delete:" in line) is enabled


def test_probe_topic_rejected_with_execute_or_os_shell(capsys):
    from redposture_core.modules.kafka.policy import validate_args

    for action in (["--execute", "id"], ["--os-shell"]):
        args = parse_args(["kafka", "-t", "broker:9092", "--probe-topic", *action])
        assert validate_args(args, Console(no_color=True)) == 2
    assert "probe-topic" in capsys.readouterr().err


@pytest.mark.parametrize("flag", ["--probe-write", "--show-topics", "--dump"])
def test_other_actions_do_not_opt_in_to_topic_lifecycle(monkeypatch, auth_context, flag):
    from redposture_core.modules.kafka.stage import _build_kafka_lifecycle_options

    ctx, _ = auth_context
    install_session(monkeypatch, ok=True, error=None)
    monkeypatch.setattr(actions, "probe_topic_lifecycle", lambda *a, **kw: pytest.fail("implicit mutation"))
    args = parse_args(["kafka", "-t", "broker:9092", flag])
    result = actions.authenticate_kafka(ctx, {"status": "auth_required"}, _build_kafka_lifecycle_options(args))
    assert result["provided_credentials_ok"] is True and "topic_lifecycle" not in result


@pytest.mark.parametrize("enabled", [False, True])
def test_anonymous_probe_requires_flag_and_confirmed_access(monkeypatch, auth_context, enabled):
    from redposture_core.modules.kafka.stage import _build_kafka_lifecycle_options

    ctx, _ = auth_context
    ctx.lifecycle_state.auth_required = False
    ctx.lifecycle_state.anonymous_metadata = {"topic_map": {"orders": 1}}
    ctx.credential = AuditCredentialRun(username=None, password=None, source="anonymous")
    calls = []

    def probe(*a, **kw):
        calls.append(kw)
        return {"create": True, "delete": True, "cleanup_complete": True}

    monkeypatch.setattr(actions, "probe_topic_lifecycle", probe)
    monkeypatch.setattr(actions, "_probe_kafka_acl_state", lambda **kw: ({}, {}))
    options = _build_kafka_lifecycle_options(
        parse_args(["kafka", "-t", "broker:9092", *(["--probe-topic"] if enabled else [])])
    )
    result = actions.collect_kafka_data(ctx, {"status": "open_no_auth", "topic_count": 1}, options)
    assert len(calls) == int(enabled)
    assert ("topic_lifecycle" in result) is enabled
    if enabled:
        assert calls[0]["username"] is None and calls[0]["password"] is None
