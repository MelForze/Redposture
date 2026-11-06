"""Independent startup observations survive errors and remain visible per pair."""

from __future__ import annotations

import json
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from redposture_core.modules.postgres import actions, stage
from tests.test_postgres_startup_evidence import Socket, error, frame


def test_startup_error_accepts_localized_severity_and_ignores_unknown_fields():
    body = "SОШИБКА\0".encode() + b"zextension\0C28000\0zfuture\0Mno such user\0\0"
    with pytest.raises(actions._PgAuditError) as caught:
        actions._pg_startup_and_auth(Socket(frame(b"E", body)), "alice", "candidate", "app")
    assert caught.value.detected is True
    assert caught.value.error_kind == "unknown_user"
    assert caught.value.credential_verified is None


@pytest.mark.parametrize("proof", [False, True])
def test_authentication_ok_only_verifies_an_exchanged_password(proof):
    response = frame(b"R", (3).to_bytes(4, "big")) if proof else b""
    response += frame(b"R", bytes(4)) + frame(b"Z", b"I")
    session = actions._pg_startup_and_auth(Socket(response), "alice", "candidate", "app")
    assert session.auth_required is proof
    assert session.password_sent is proof
    assert session.credential_verified is (True if proof else None)


@pytest.mark.parametrize(
    "ending", [error("3D000", "no such database: app"), error("28P01", "password authentication failed")]
)
def test_frontend_acceptance_is_preserved_when_backend_startup_fails(ending):
    response = frame(b"R", (3).to_bytes(4, "big")) + frame(b"R", bytes(4)) + ending
    with pytest.raises(actions._PgAuditError) as caught:
        actions._pg_startup_and_auth(Socket(response), "alice", "candidate", "app")
    assert caught.value.credential_verified is True
    assert caught.value.password_sent is True
    fields = actions._pg_startup_record_fields(caught.value)
    assert fields["startup_complete"] is False
    assert fields["startup_username"] == "alice"
    assert fields["startup_database"] == "app"


def test_frontend_password_acceptance_does_not_allow_deep_checks_before_ready(monkeypatch):
    response = frame(b"R", (3).to_bytes(4, "big")) + frame(b"R", bytes(4)) + error("3D000", "no such database: app")
    monkeypatch.setattr(actions, "_pg_open_socket", lambda *_args, **_kwargs: nullcontext(Socket(response)))
    ctx = SimpleNamespace(
        host="127.0.0.1",
        port=6432,
        credential=SimpleNamespace(username="alice", password="candidate", source="provided"),
        args=SimpleNamespace(timeout=1, retries=0, database="app", sslmode="disable"),
    )
    record = stage._postgres_probe_credential(ctx)
    assert record.extra["credential_verified"] is True
    assert record.extra["credential_verification"] == "verified"
    assert stage._postgres_credential_gate(ctx.credential, record)[0] is False
    line = actions._format_record(record.to_dict(), "txt")
    assert "[+] alice:candidate" in line and "startup:failed" in line
    assert "[-]" not in line


@pytest.mark.parametrize("ending", [b"", frame(b"E", b"noise\0"), frame(b"S", b"bad")])
def test_valid_version_and_policy_survive_transport_or_malformed_response(ending):
    response = frame(b"R", (3).to_bytes(4, "big"))
    response += frame(b"S", b"server_version\x0016.4\0") + ending
    with pytest.raises(actions._PgAuditError) as caught:
        actions._pg_startup_and_auth(Socket(response), "alice", "candidate", "app")
    assert caught.value.detected is True
    assert caught.value.auth_required is True
    assert caught.value.server_version == "16.4"
    assert caught.value.password_sent is True
    assert caught.value.credential_verified is None


@pytest.mark.parametrize("mechanisms", [b"", b"SCRAM-SHA-256\0", b"SCRAM-SHA-256\0\0extra", b"\0\0"])
def test_malformed_sasl_list_does_not_confirm_a_listener(mechanisms):
    response = frame(b"R", (10).to_bytes(4, "big") + mechanisms)
    with pytest.raises(actions._PgAuditError) as caught:
        actions._pg_startup_and_auth(Socket(response), "alice", "candidate", "app")
    assert caught.value.detected is False
    assert caught.value.credential_verified is None


def test_valid_unsupported_sasl_mechanism_is_unavailable_without_password_proof():
    response = frame(b"R", (10).to_bytes(4, "big") + b"PLAIN\0\0")
    with pytest.raises(actions._PgAuditError) as caught:
        actions._pg_startup_and_auth(Socket(response), "alice", "candidate", "app")
    assert caught.value.detected is True
    assert caught.value.auth_required is True
    assert caught.value.password_sent is False
    assert caught.value.credential_verified is None


def test_pre_password_password_error_is_not_a_pair_rejection():
    with pytest.raises(actions._PgAuditError) as caught:
        actions._pg_startup_and_auth(
            Socket(error("28P01", "password authentication failed")), "alice", "candidate", "app"
        )
    assert caught.value.auth_required is True
    assert caught.value.password_sent is False
    assert caught.value.credential_verified is None


def test_every_uncertain_credential_is_visible_with_reason_and_protocol_diagnostics():
    record = {
        "host": "127.0.0.1",
        "port": 6432,
        "attempted_credentials": [
            {
                "username": "alice",
                "password": "candidate",
                "status": "unknown_auth",
                "credential_verification": "unavailable",
                "error_kind": "unknown_user",
                "sqlstate": "28000",
                "startup_username": "alice",
                "startup_database": "app",
                "error": "no such user",
            },
            {
                "username": "bob",
                "password": "candidate",
                "status": "fail",
                "credential_verification": "error",
                "error_kind": "transport_error",
                "error": "connection reset",
            },
        ],
    }
    lines = actions._format_credential_attempts_records(record, "txt")
    assert len(lines) == 2
    assert lines[0].endswith("[*] alice:candidate (unverified: unknown user)")
    assert all(field not in lines[0] for field in ("reason:", "sqlstate:", "startup user:", "database:", "err="))
    assert lines[1].endswith("[*] bob:candidate (unverified: connection error)")
    assert all("[-]" not in line and "\x1b" not in line for line in lines)
    assert "\x1b" not in actions._format_record(record, "json")
    assert (
        json.loads(actions._format_record(record, "json"))["attempted_credentials"] == record["attempted_credentials"]
    )


def test_uncertain_credential_lines_are_orange():
    class Painter:
        def __init__(self):
            self.lines = []

        def _paint(self, text, color, _stream):
            return f"<{color}>{text}</{color}>"

        def plain(self, line):
            self.lines.append(line)

    painter = Painter()
    line = "POSTGRES\t127.0.0.1\t6432\t [*] unverified alice:candidate (reason:unknown_user)"
    assert actions._render_colored_postgres_line(painter, line)
    assert "<orange>unverified alice:candidate (reason:unknown_user)</orange>" in painter.lines[0]


def test_startup_diagnostics_escape_remote_control_sequences():
    record = {
        "host": "127.0.0.1",
        "port": 6432,
        "status": "unknown_auth",
        "provided_credentials": True,
        "credential_verification": "unavailable",
        "effective_username": "alice",
        "provided_password": "candidate",
        "error": "no such user\x1b[31m",
        "server_version": "16.4\x1b[31m",
    }
    assert "\x1b" not in actions._format_record(record, "txt")
    assert "\x1b" not in actions._format_detect_record(record, "txt")
    assert "\x1b" not in actions._format_record(record, "json")


def test_attempt_contract_retains_independent_startup_evidence():
    fields = stage.build_postgres_spec(SimpleNamespace()).credential_attempt_detail_fields
    assert {
        "sqlstate",
        "failure_phase",
        "error_kind",
        "password_sent",
        "credential_verified",
        "startup_username",
        "startup_database",
        "server_version",
        "startup_complete",
    }.issubset(fields)
