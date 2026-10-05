"""Keycloak audit entrypoint."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from ...audit_config import AuditConfig
from ...audit_models import AuditRecord
from ...console import Console
from ...stage_runtime import AuditCommandPlan, ModuleAuditSpec, build_basic_audit_plan, run_basic_host_audit
from . import actions, policy, render

_DEFAULT_PORTS = (8080, 8443, 18080)


def build_keycloak_plan(args: Any) -> AuditCommandPlan:
    plan = build_basic_audit_plan(args, default_port=8080, default_ports=_DEFAULT_PORTS)
    explicit_port = getattr(args, "port", None) is not None or bool(str(getattr(args, "ports", "") or "").strip())
    if not explicit_port and plan.target_plan is not None:
        plan = replace(plan, target_plan=plan.target_plan.with_scheme_default_ports({"http": 80, "https": 443}))
    return plan


def build_keycloak_spec(args: Any) -> ModuleAuditSpec:
    def _detect(ctx: Any) -> AuditRecord:
        return AuditRecord.from_mapping(actions.detect_record(ctx), module="keycloak", service="keycloak")

    def _auth(ctx: Any, record: AuditRecord) -> AuditRecord:
        return AuditRecord.from_mapping(
            actions.auth_record(ctx, record.to_dict()), module="keycloak", service="keycloak"
        )

    def _data(ctx: Any, record: AuditRecord) -> AuditRecord:
        return AuditRecord.from_mapping(
            actions.data_record(ctx, record.to_dict()), module="keycloak", service="keycloak"
        )

    return ModuleAuditSpec(
        module="keycloak",
        label="KEYCLOAK",
        default_port=8080,
        detect=_detect,
        auth=_auth,
        data=_data,
        render_module=render,
        colorize=render._render_colored_keycloak_line,
        is_detected=lambda record: record.extra.get("is_keycloak") is True,
        credential_gate=lambda _credential, record: (
            record.extra.get("provided_credentials_ok") is True,
            "keycloak token verified" if record.extra.get("provided_credentials_ok") is True else "token not verified",
        ),
        structured_output_redact_fields=("attempted_credentials", "credential_results"),
        defer_detect_output_until_auth=True,
        live_phase_output=True,
    )


def run_keycloak_stage(args: Any, logger: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    console = Console(debug=cfg.debug)
    return run_basic_host_audit(
        args,
        logger,
        console=console,
        label="KEYCLOAK",
        validate=policy.validate_args,
        build_plan=build_keycloak_plan,
        build_spec=build_keycloak_spec,
    )


__all__ = ["build_keycloak_plan", "build_keycloak_spec", "run_keycloak_stage"]
