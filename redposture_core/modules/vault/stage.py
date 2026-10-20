"""HashiCorp Vault audit entrypoint and phase hooks."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from ...audit_config import AuditConfig
from ...audit_models import AuditRecord
from ...clients.http_api import http_target_context
from ...clients.http_session import HttpSessionPool
from ...clients.scoped_http import HttpLifecycleState
from ...console import Console
from ...stage_runtime import (
    AuditCommandPlan,
    AuditCredentialRun,
    ModuleAuditSpec,
    build_basic_audit_plan,
    run_basic_host_audit,
)
from . import actions, policy, render


def build_vault_plan(args: Any) -> AuditCommandPlan:
    plan = build_basic_audit_plan(args, default_port=8200, default_ports=(8200,))
    if plan.target_plan is not None and getattr(args, "port", None) is None and not getattr(args, "ports", None):
        plan = replace(plan, target_plan=plan.target_plan.with_scheme_default_ports({"http": 80, "https": 443}))
    token = getattr(args, "_vault_token", None)
    credentials = (
        (AuditCredentialRun(token=token, source="provided"),)
        if token
        else (AuditCredentialRun(token="root", source="default"),)
        if getattr(args, "defcreds", False)
        else ()
    )
    return replace(plan, credential_runs=credentials)


def build_vault_spec(args: Any) -> ModuleAuditSpec:
    def _state(ctx: Any) -> HttpLifecycleState:
        return HttpLifecycleState(
            HttpSessionPool(
                timeout=float(getattr(ctx.args, "timeout", 5.0) or 5.0),
                retries=int(getattr(ctx.args, "retries", 0) or 0),
                proxy=getattr(ctx.args, "_proxy_config", None),
                insecure=not bool(getattr(ctx.args, "tls_ca", None)),
                ca_file=getattr(ctx.args, "tls_ca", None),
                cert_file=getattr(ctx.args, "tls_cert", None),
                key_file=getattr(ctx.args, "tls_key", None),
            )
        )

    def _phase(ctx: Any, action: Any, record: AuditRecord | None = None) -> AuditRecord:
        with http_target_context(
            ctx.target,
            route_state=getattr(ctx, "lifecycle_state", None),
            api_prefixes=("/v1",),
        ):
            value = action(ctx) if record is None else action(ctx, record.to_dict())
        return AuditRecord.from_mapping(value, module="vault", service="vault")

    return ModuleAuditSpec(
        module="vault",
        label="VAULT",
        default_port=8200,
        lifecycle_state_factory=_state,
        lifecycle_state_close=lambda state: state.close(),
        detect=lambda ctx: _phase(ctx, actions.detect_record),
        auth=lambda ctx, record: _phase(ctx, actions.auth_record, record),
        data=lambda ctx, record: _phase(ctx, actions.data_record, record),
        render_module=render,
        colorize=render._render_colored_vault_line,
        is_detected=lambda record: record.extra.get("is_vault") is True,
        credential_gate=lambda _credential, record: (
            record.extra.get("provided_credentials_ok") is True,
            "Vault lookup-self verified"
            if record.extra.get("provided_credentials_ok") is True
            else "token not verified",
        ),
        structured_output_redact_fields=("attempted_credentials", "credential_results"),
        defer_detect_output_until_auth=True,
        live_phase_output=True,
    )


def run_vault_stage(args: Any, logger: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    return run_basic_host_audit(
        args,
        logger,
        console=Console(debug=cfg.debug),
        label="VAULT",
        validate=policy.validate_args,
        build_plan=build_vault_plan,
        build_spec=build_vault_spec,
    )


__all__ = ["build_vault_plan", "build_vault_spec", "run_vault_stage"]
