"""Runtime entrypoint for the rabbitmq audit module."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from ...audit_config import AuditConfig
from ...audit_models import AuditRecord
from ...console import Console
from ...stage_runtime import (
    AuditCommandPlan,
    AuditCredentialRun,
    ModuleAuditSpec,
    build_basic_audit_plan,
    merge_audit_credential_runs,
    run_basic_host_audit,
)
from . import actions, policy, render


def build_rabbitmq_plan(args: Any) -> AuditCommandPlan:
    plan = build_basic_audit_plan(args, default_port=15672, default_ports=(15672, 15671))
    defaults = (
        tuple(
            AuditCredentialRun(username=user, password=password, source="default")
            for user, password in actions.DEFAULT_CREDENTIALS
        )
        if getattr(args, "defcreds", False)
        else ()
    )
    return replace(plan, credential_runs=merge_audit_credential_runs(plan.credential_runs, defaults))


def _credential_gate(credential: Any, record: AuditRecord) -> tuple[bool, str]:
    valid = record.extra.get("provided_credentials_ok") is True
    return valid, "RabbitMQ identity verified" if valid else "RabbitMQ identity not verified"


def _deep_gate(record: AuditRecord) -> tuple[bool, str]:
    allowed = record.extra.get("provided_credentials_ok") is True or record.auth_required is False
    return allowed, "metadata accessible" if allowed else "no verified API access"


def build_rabbitmq_spec(args: Any) -> ModuleAuditSpec:
    def detect(ctx: Any) -> AuditRecord:
        return AuditRecord.from_mapping(actions.detect_record(ctx), module="rabbitmq", service="rabbitmq")

    def auth(ctx: Any, record: AuditRecord) -> AuditRecord:
        return AuditRecord.from_mapping(
            actions.auth_record(ctx, record.to_dict()), module="rabbitmq", service="rabbitmq"
        )

    def capabilities(ctx: Any, record: AuditRecord) -> AuditRecord:
        return AuditRecord.from_mapping(
            actions.capabilities_record(ctx, record.to_dict()), module="rabbitmq", service="rabbitmq"
        )

    def data(ctx: Any, record: AuditRecord) -> AuditRecord:
        return AuditRecord.from_mapping(
            actions.data_record(ctx, record.to_dict()), module="rabbitmq", service="rabbitmq"
        )

    return ModuleAuditSpec(
        module="rabbitmq",
        label="RABBITMQ",
        default_port=15672,
        detect=detect,
        auth=auth,
        capabilities=capabilities,
        data=data,
        lifecycle_state_factory=actions.RabbitMQLifecycleState,
        lifecycle_state_close=lambda state: state.close(),
        render=render.RabbitMQTextRenderer(debug=bool(getattr(args, "debug", False))),
        colorize=render._render_colored_rabbitmq_line,
        credential_gate=_credential_gate,
        deep_gate=_deep_gate,
        skip_credentials_without_verifier=True,
        fallback_to_anonymous_detect_record=True,
        record_all_credential_attempts=True,
        continue_after_credential_success=bool(getattr(args, "defcreds", False)),
        continue_after_credential_error=bool(getattr(args, "defcreds", False)),
        credential_attempt_detail_fields=(
            "credential_state",
            "credential_http_status",
            "tags",
            "admin",
            "admin_status",
            "admin_evidence",
        ),
        structured_output_redact_fields=("attempted_credentials",),
        suppress_undetected_records_in_text=True,
    )


def run_rabbitmq_stage(args: Any, logger: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    return run_basic_host_audit(
        args,
        logger,
        console=Console(debug=cfg.debug),
        label="RABBITMQ",
        validate=policy.validate_args,
        build_plan=build_rabbitmq_plan,
        build_spec=build_rabbitmq_spec,
    )
