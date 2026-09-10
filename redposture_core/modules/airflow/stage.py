"""Runtime entrypoint for the airflow audit module."""

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
    sort_default_audit_credential_runs,
)
from . import actions, policy, render

_DEFAULT_PORT = 8080
_DEFAULT_PORTS: tuple[int, ...] = (8080, 8081, 18080, 28080, 8443)


def build_airflow_plan(args: Any) -> AuditCommandPlan:
    plan = build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)
    default_runs = (
        sort_default_audit_credential_runs(
            AuditCredentialRun(username=user, password=pw, source=source)
            for user, pw, source in actions._build_credential_candidates(None, None, True)
        )
        if bool(getattr(args, "defcreds", False))
        else ()
    )
    return replace(
        plan,
        credential_runs=merge_audit_credential_runs(plan.credential_runs, default_runs),
    )


def _airflow_credential_gate(credential: Any, record: AuditRecord) -> tuple[bool, str]:
    ok = record.extra.get("provided_credentials_ok") is True
    return ok, "airflow credential verified" if ok else "airflow credential rejected"


def build_airflow_spec(args: Any) -> ModuleAuditSpec:
    def _detect(ctx: Any) -> AuditRecord:
        return AuditRecord.from_mapping(actions.detect_record(ctx), module="airflow", service="airflow")

    def _auth(ctx: Any, record: Any) -> AuditRecord:
        prior = record.to_dict() if hasattr(record, "to_dict") else dict(record)
        return AuditRecord.from_mapping(actions.auth_record(ctx, prior), module="airflow", service="airflow")

    def _capabilities(ctx: Any, record: Any) -> AuditRecord:
        prior = record.to_dict() if hasattr(record, "to_dict") else dict(record)
        return AuditRecord.from_mapping(actions.capabilities_record(ctx, prior), module="airflow", service="airflow")

    return ModuleAuditSpec(
        module="airflow",
        label="AIRFLOW",
        default_port=_DEFAULT_PORT,
        detect=_detect,
        auth=_auth,
        capabilities=_capabilities,
        lifecycle_state_factory=actions.airflow_lifecycle_state_factory,
        lifecycle_state_close=lambda state: state.close(),
        render_module=render,
        colorize=render._render_colored_airflow_line,
        credential_gate=_airflow_credential_gate,
        skip_credentials_without_verifier=True,
        structured_output_redact_fields=("attempted_credentials", "credential_password"),
        continue_after_credential_error=bool(getattr(args, "defcreds", False)),
        # `--defcreds` is exhaustive (house convention): try every default pair and
        # render each attempt, instead of stopping at the first accepted one.
        continue_after_credential_success=bool(getattr(args, "defcreds", False)),
        credential_attempt_detail_fields=("credential_state",),
    )


def run_airflow_stage(args: Any, logger: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    console = Console(debug=cfg.debug)
    return run_basic_host_audit(
        args,
        logger,
        console=console,
        label="AIRFLOW",
        validate=policy.validate_args,
        build_plan=build_airflow_plan,
        build_spec=build_airflow_spec,
    )


__all__ = ["build_airflow_plan", "build_airflow_spec", "run_airflow_stage"]
