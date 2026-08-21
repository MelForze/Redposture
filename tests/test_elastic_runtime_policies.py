from __future__ import annotations

import json
from types import SimpleNamespace

from redposture_core.audit_models import AuditRecord
from redposture_core.modules.elastic.stage import (
    _build_elastic_credential_runs,
    _elastic_credential_gate,
    build_elastic_spec,
)
from redposture_core.stage_runtime import (
    AuditCommandPlan,
    AuditCommandRunner,
    AuditCredentialRun,
    ModuleAuditSpec,
)


def _elastic_record(ctx, *, status: str, auth_required: bool | None, auth_valid: bool | None) -> AuditRecord:
    return AuditRecord(
        host=ctx.host,
        port=ctx.port,
        module="elastic",
        service="elastic",
        status=status,
        auth_required=auth_required,
        extra={"is_elastic": True, "auth_valid": auth_valid},
    )


def _verified_credential_gate(
    _credential: AuditCredentialRun,
    record: AuditRecord,
) -> tuple[bool, str]:
    verified = record.extra.get("auth_valid") is True
    return verified, "verified" if verified else "unverified"


def test_elastic_runtime_records_failed_and_successful_credential_attempts() -> None:
    auth_calls: list[str | None] = []
    data_credentials: list[AuditCredentialRun] = []

    def detect(ctx) -> AuditRecord:
        return _elastic_record(ctx, status="auth_required", auth_required=True, auth_valid=None)

    def auth(ctx, _detect_record: AuditRecord) -> AuditRecord:
        auth_calls.append(ctx.credential.password)
        if ctx.credential.password == "works":
            return _elastic_record(ctx, status="weak_default_creds", auth_required=True, auth_valid=True)
        return _elastic_record(ctx, status="auth_required", auth_required=True, auth_valid=False)

    def data(ctx, record: AuditRecord) -> AuditRecord:
        data_credentials.append(ctx.credential)
        return record

    spec = ModuleAuditSpec(
        module="elastic",
        label="ELASTIC",
        default_port=9200,
        detect=detect,
        auth=auth,
        data=data,
        render=lambda record: [record.status],
        credential_gate=_verified_credential_gate,
        record_all_credential_attempts=True,
        fallback_to_anonymous_detect_record=True,
    )
    plan = AuditCommandPlan(
        targets_by_port={9200: ("127.0.0.1",)},
        credential_runs=(
            AuditCredentialRun(username="elastic", password="wrong", source="default"),
            AuditCredentialRun(username="elastic", password="works", source="default"),
            AuditCredentialRun(username="elastic", password="not-tried", source="default"),
        ),
    )

    result = AuditCommandRunner(args=SimpleNamespace(defcreds=True), spec=spec, emit_line=lambda _line: None).run_plan(
        plan
    )

    assert auth_calls == ["wrong", "works"]
    assert data_credentials == [AuditCredentialRun(username="elastic", password="works", source="default")]
    assert result.records[0]["attempted_credentials"] == [
        {
            "username": "elastic",
            "password": "wrong",
            "source": "default",
            "status": "auth_required",
            "error": None,
        },
        {
            "username": "elastic",
            "password": "works",
            "source": "default",
            "status": "weak_default_creds",
            "error": None,
        },
    ]


def test_elastic_runtime_falls_back_to_confirmed_anonymous_access_after_rejections() -> None:
    auth_calls: list[str | None] = []
    data_credentials: list[AuditCredentialRun] = []

    def detect(ctx) -> AuditRecord:
        return _elastic_record(ctx, status="open_no_auth", auth_required=False, auth_valid=None)

    def auth(ctx, _detect_record: AuditRecord) -> AuditRecord:
        auth_calls.append(ctx.credential.password)
        return _elastic_record(
            ctx,
            status="invalid_credentials_anonymous",
            auth_required=False,
            auth_valid=False,
        )

    def data(ctx, record: AuditRecord) -> AuditRecord:
        data_credentials.append(ctx.credential)
        return record

    spec = ModuleAuditSpec(
        module="elastic",
        label="ELASTIC",
        default_port=9200,
        detect=detect,
        auth=auth,
        data=data,
        render=lambda record: [record.status],
        credential_gate=_verified_credential_gate,
        record_all_credential_attempts=True,
        fallback_to_anonymous_detect_record=True,
    )
    credentials = (
        AuditCredentialRun(username="elastic", password="one", source="default"),
        AuditCredentialRun(username="elastic", password="two", source="default"),
    )
    plan = AuditCommandPlan(targets_by_port={9200: ("127.0.0.1",)}, credential_runs=credentials)

    result = AuditCommandRunner(args=SimpleNamespace(defcreds=True), spec=spec, emit_line=lambda _line: None).run_plan(
        plan
    )

    assert auth_calls == ["one", "two"]
    assert data_credentials == [AuditCredentialRun(source="anonymous")]
    assert result.records[0]["status"] == "open_no_auth"
    assert result.records[0]["attempted_credentials"] == [
        {
            "username": "elastic",
            "password": "one",
            "source": "default",
            "status": "invalid_credentials_anonymous",
            "error": None,
        },
        {
            "username": "elastic",
            "password": "two",
            "source": "default",
            "status": "invalid_credentials_anonymous",
            "error": None,
        },
    ]


def test_elastic_undetected_records_are_suppressed_only_in_normal_text() -> None:
    def detect(ctx) -> AuditRecord:
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="elastic",
            service="elastic",
            status="not_elastic",
            extra={"is_elastic": False, "error": "status=400", "api_token": "secret-token"},
        )

    spec = ModuleAuditSpec(
        module="elastic",
        label="ELASTIC",
        default_port=9200,
        detect=detect,
        render=lambda record: [f"{record.host} not elastic"],
        suppress_undetected_records_in_text=True,
        structured_output_redact_fields=("api_token",),
    )
    plan = AuditCommandPlan(targets_by_port={9200: ("127.0.0.1",)}, output_format="txt")
    normal_lines: list[str] = []

    normal = AuditCommandRunner(args=SimpleNamespace(debug=False), spec=spec, emit_line=normal_lines.append).run_plan(
        plan
    )

    assert normal_lines == ["[*] No ELASTIC service detected on target"]
    assert normal.suppressed_records == 1
    assert normal.records[0]["error"] == "status=400"

    debug_lines: list[str] = []
    debug = AuditCommandRunner(args=SimpleNamespace(debug=True), spec=spec, emit_line=debug_lines.append).run_plan(plan)
    assert debug_lines == ["127.0.0.1 not elastic"]
    assert debug.suppressed_records == 0

    json_lines: list[str] = []
    json_plan = AuditCommandPlan(targets_by_port={9200: ("127.0.0.1",)}, output_format="json")
    structured = AuditCommandRunner(
        args=SimpleNamespace(debug=False),
        spec=spec,
        emit_line=json_lines.append,
    ).run_plan(json_plan)
    json_payload = json.loads(json_lines[0])
    assert json_payload["error"] == "status=400"
    assert "api_token" not in json_payload
    assert structured.suppressed_records == 0


def test_elastic_credentials_merge_token_file_and_defaults_with_deduplication(tmp_path) -> None:
    credentials_file = tmp_path / "elastic-creds.txt"
    credentials_file.write_text("alice:one\nelastic:changeme\nalice:one\n", encoding="utf-8")
    args = SimpleNamespace(
        apitoken="secret-token",
        api_token=None,
        token=None,
        username=str(credentials_file),
        password=None,
        defcreds=True,
    )

    runs = _build_elastic_credential_runs(args)

    assert [(run.username, run.password, run.source) for run in runs] == [
        (None, None, "token"),
        ("alice", "one", "file"),
        ("elastic", "changeme", "file"),
        ("admin", "admin", "default"),
        ("admin", "changeme", "default"),
        ("admin", "password", "default"),
        ("elastic", "elastic", "default"),
        ("elastic", "password", "default"),
        ("kibana", "changeme", "default"),
        ("kibana", "kibana", "default"),
        ("logstash", "logstash", "default"),
        ("logstash_system", "changeme", "default"),
        ("opensearch", "opensearch", "default"),
        ("opensearch", "password", "default"),
    ]
    assert runs[0].token == "secret-token"


def test_elastic_credential_gate_requires_explicit_identity_verification() -> None:
    credential = AuditCredentialRun(username="elastic", password="secret", source="provided")
    unverified = AuditRecord(
        host="127.0.0.1",
        port=9200,
        module="elastic",
        service="elastic",
        status="valid_credentials",
        extra={"is_elastic": True, "auth_valid": None},
    )
    verified = AuditRecord(
        host="127.0.0.1",
        port=9200,
        module="elastic",
        service="elastic",
        status="valid_credentials",
        extra={"is_elastic": True, "auth_valid": True},
    )

    assert _elastic_credential_gate(credential, unverified)[0] is False
    assert _elastic_credential_gate(credential, verified)[0] is True


def test_elastic_structured_output_redacts_top_level_secrets() -> None:
    spec = build_elastic_spec(SimpleNamespace())

    assert set(spec.structured_output_redact_fields) == {"api_token", "provided_password"}


def test_default_runtime_does_not_add_attempt_history_after_late_success() -> None:
    calls = 0

    def detect(ctx) -> AuditRecord:
        return _elastic_record(ctx, status="auth_required", auth_required=True, auth_valid=None)

    def auth(ctx, _record: AuditRecord) -> AuditRecord:
        nonlocal calls
        calls += 1
        if calls == 2:
            return _elastic_record(ctx, status="valid_credentials", auth_required=True, auth_valid=True)
        return _elastic_record(ctx, status="auth_required", auth_required=True, auth_valid=False)

    spec = ModuleAuditSpec(
        module="other",
        label="OTHER",
        default_port=1234,
        detect=detect,
        auth=auth,
        data=lambda _ctx, record: record,
        render=lambda record: [record.status],
    )
    plan = AuditCommandPlan(
        targets_by_port={1234: ("127.0.0.1",)},
        credential_runs=(
            AuditCredentialRun(username="first", password="wrong"),
            AuditCredentialRun(username="second", password="right"),
        ),
    )

    result = AuditCommandRunner(args=SimpleNamespace(), spec=spec, emit_line=lambda _line: None).run_plan(plan)

    assert calls == 2
    assert "attempted_credentials" not in result.records[0]


def test_elastic_runtime_continues_after_one_credential_probe_exception() -> None:
    auth_calls: list[str | None] = []

    def detect(ctx) -> AuditRecord:
        return _elastic_record(ctx, status="auth_required", auth_required=True, auth_valid=None)

    def auth(ctx, _record: AuditRecord) -> AuditRecord:
        auth_calls.append(ctx.credential.password)
        if ctx.credential.password == "broken":
            raise OSError("temporary auth probe failure")
        return _elastic_record(ctx, status="valid_credentials", auth_required=True, auth_valid=True)

    spec = ModuleAuditSpec(
        module="elastic",
        label="ELASTIC",
        default_port=9200,
        detect=detect,
        auth=auth,
        data=lambda _ctx, record: record,
        render=lambda record: [record.status],
        credential_gate=_verified_credential_gate,
        record_all_credential_attempts=True,
        continue_after_credential_error=True,
    )
    plan = AuditCommandPlan(
        targets_by_port={9200: ("127.0.0.1",)},
        credential_runs=(
            AuditCredentialRun(username="elastic", password="broken", source="file"),
            AuditCredentialRun(username="elastic", password="works", source="default"),
        ),
    )

    result = AuditCommandRunner(args=SimpleNamespace(), spec=spec, emit_line=lambda _line: None).run_plan(plan)

    assert auth_calls == ["broken", "works"]
    assert result.records[0]["status"] == "valid_credentials"
    assert [attempt["status"] for attempt in result.records[0]["attempted_credentials"]] == [
        "fail",
        "valid_credentials",
    ]
