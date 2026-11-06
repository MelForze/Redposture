"""Concise uncertain credentials keep full evidence in debug and JSON."""

import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.modules.postgres import actions, stage
from redposture_core.stage_runtime import AuditCommandPlan, AuditCommandRunner, AuditCredentialRun


@pytest.mark.parametrize(
    "kind,reason",
    [
        ("unknown_user", "unknown user"),
        ("database_unavailable", "database unavailable"),
        ("auth_configuration_error", "authentication unavailable"),
        ("auth_policy_denied", "login restricted"),
        ("startup_rejected", "startup rejected"),
        ("transport_error", "connection error"),
        ("connection_error", "connection error"),
        ("future_kind", "verification unavailable"),
    ],
)
def test_uncertain_reason_is_short_and_never_a_password_rejection(kind, reason):
    attempt = {
        "username": "alice",
        "password": "candidate",
        "status": "unknown_auth",
        "credential_verification": "unavailable",
        "error_kind": kind,
        "sqlstate": "08P01",
        "startup_username": "alice",
        "startup_database": "app",
        "error": "long error " * 1000,
    }
    record = {
        "host": "127.0.0.1",
        "port": 6432,
        "provided_credentials": True,
        "credential_verification": "unavailable",
        "attempted_credentials": [attempt],
    }
    line = actions._format_record(record, "txt")
    assert line.endswith(f"[*] alice:candidate (unverified: {reason})")
    assert "[-]" not in line and "long error" not in line and "sqlstate" not in line
    assert json.loads(actions._format_record(record, "json"))["attempted_credentials"] == [attempt]


@pytest.mark.parametrize("exhaustive", [False, True])
@pytest.mark.parametrize("debug", [False, True])
@pytest.mark.parametrize("fmt", ["txt", "json"])
def test_saved_output_and_debug_keep_separate_contracts(monkeypatch, tmp_path, debug, fmt, exhaustive):
    error = "no such user " + "full-evidence-" * 1000 + "\x1b[31m\nend"
    diagnostics = []

    def probe(ctx):
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="postgres",
            service="postgres",
            status="unknown_auth",
            auth_required=None,
            extra={
                "is_postgres": True,
                "provided_credentials": True,
                "provided_username": "alice",
                "provided_password": "candidate",
                "effective_username": "alice",
                "credential_verified": None,
                "credential_verification": "unavailable",
                "error_kind": "unknown_user",
                "sqlstate": "08P01",
                "startup_username": "alice",
                "startup_database": "app",
                "error": error,
            },
        )

    monkeypatch.setattr(stage, "_postgres_probe_credential", probe)
    args = SimpleNamespace(
        defcreds=exhaustive, debug=debug, debug_emit=diagnostics.append, no_color=True, timeout=1, retries=0
    )
    spec = replace(
        stage.build_postgres_spec(args),
        detect=lambda ctx: AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="postgres",
            service="postgres",
            status="auth_required",
            auth_required=True,
            extra={"is_postgres": True},
        ),
        detect_async=None,
    )
    path = tmp_path / f"output.{fmt}"
    plan = AuditCommandPlan(
        targets_by_port={6432: ("127.0.0.1",)},
        credential_runs=(
            AuditCredentialRun(username="alice", password="candidate", source="default" if exhaustive else "provided"),
        ),
        output_format=fmt,
        output_path=str(path),
    )
    result = AuditCommandRunner(args=args, spec=spec, emit_line=lambda _: None).run_plan(plan)
    saved = path.read_text()
    assert "\x1b" not in saved
    if fmt == "txt":
        assert "alice:candidate (unverified: unknown user)" in saved
        assert "startup user:" not in saved and "sqlstate:" not in saved and "full-evidence-" not in saved
    else:
        payload = json.loads(saved)
        assert isinstance(payload, dict)
        assert ("attempted_credentials" in payload) is exhaustive
        evidence = payload["attempted_credentials"][0] if exhaustive else payload
        assert evidence["error"] == error
        assert evidence["sqlstate"] == "08P01"
    credential_debug = [s for s in diagnostics if s.startswith("postgres credential verification ")]
    assert len(credential_debug) == int(debug)
    if debug:
        assert actions._pg_startup_text(error) in credential_debug[0]
        assert all(
            s in credential_debug[0]
            for s in ("sqlstate=08P01", "reason=unknown_user", "startup user=alice", "database=app")
        )
        assert "\x1b" not in credential_debug[0]
    assert ("attempted_credentials" in result.records[0]) is exhaustive
    evidence = result.records[0]["attempted_credentials"][0] if exhaustive else result.records[0]
    assert evidence["error"] == error


def test_unknown_pair_is_white_and_reason_orange():
    class Painter:
        def __init__(self):
            self.lines = []

        def _paint(self, text, color, _stream):
            return f"<{color}>{text}</{color}>"

        def plain(self, line):
            self.lines.append(line)

    painter = Painter()
    assert actions._render_colored_postgres_line(
        painter, "POSTGRES\t127.0.0.1\t6432\t [*] alice:candidate (unverified: unknown user)"
    )
    assert "<white>alice:candidate</white>" in painter.lines[0]
    assert "<orange> (unverified: unknown user)</orange>" in painter.lines[0]
