"""Jenkins audit entrypoint and phase-aware hooks."""

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
    merge_audit_credential_runs,
    run_basic_host_audit,
    sort_default_audit_credential_runs,
)
from . import actions, policy, render

_DEFAULT_PORTS = (8080, 8443, 18080)
_DEFAULT_CREDENTIALS = (
    ("admin", "admin"),
    ("admin", "changeme"),
    ("admin", "jenkins"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "12345678"),
    ("jenkins", "jenkins"),
    ("jenkins", "password"),
    ("jenkins", "changeme"),
    ("jenkins", "admin"),
    ("root", "root"),
    ("root", "password"),
    ("user", "user"),
    ("user", "password"),
    ("test", "test"),
    ("dev", "dev"),
    ("guest", "guest"),
    ("service", "service"),
)


def build_jenkins_plan(args: Any) -> AuditCommandPlan:
    plan = build_basic_audit_plan(args, default_port=8080, default_ports=_DEFAULT_PORTS)
    explicit_port = getattr(args, "port", None) is not None or bool(str(getattr(args, "ports", "") or "").strip())
    if not explicit_port and plan.target_plan is not None:
        plan = replace(plan, target_plan=plan.target_plan.with_scheme_default_ports({"http": 80, "https": 443}))
    token = getattr(args, "_jenkins_api_token", None)
    provided = (
        (AuditCredentialRun(username=args.username, password=token, source="api_token"),)
        if token
        else plan.credential_runs
    )
    defaults = (
        sort_default_audit_credential_runs(
            AuditCredentialRun(username=username, password=password, source="default")
            for username, password in _DEFAULT_CREDENTIALS
        )
        if getattr(args, "defcreds", False)
        else ()
    )
    return replace(plan, credential_runs=merge_audit_credential_runs(provided, defaults))


def build_jenkins_spec(args: Any) -> ModuleAuditSpec:
    def _state(ctx: Any) -> HttpLifecycleState:
        return HttpLifecycleState(
            HttpSessionPool(
                timeout=float(getattr(ctx.args, "timeout", 5.0) or 5.0),
                retries=int(getattr(ctx.args, "retries", 0) or 0),
                proxy=getattr(ctx.args, "_proxy_config", None),
                insecure=True,
            )
        )

    def _phase(ctx: Any, action: Any, record: AuditRecord | None = None) -> AuditRecord:
        with http_target_context(
            ctx.target,
            route_state=getattr(ctx, "lifecycle_state", None),
            api_prefixes=("/api", "/login", "/whoAmI", "/job", "/pluginManager", "/computer", "/queue"),
        ):
            value = action(ctx) if record is None else action(ctx, record.to_dict())
        return AuditRecord.from_mapping(value, module="jenkins", service="jenkins")

    return ModuleAuditSpec(
        module="jenkins",
        label="JENKINS",
        default_port=8080,
        lifecycle_state_factory=_state,
        lifecycle_state_close=lambda state: state.close(),
        detect=lambda ctx: _phase(ctx, actions.detect_record),
        auth=lambda ctx, record: _phase(ctx, actions.auth_record, record),
        data=lambda ctx, record: _phase(ctx, actions.data_record, record),
        render_module=render,
        colorize=render._render_colored_jenkins_line,
        is_detected=lambda record: record.extra.get("is_jenkins") is True,
        credential_gate=lambda _credential, record: (
            record.extra.get("provided_credentials_ok") is True,
            "Jenkins identity verified"
            if record.extra.get("provided_credentials_ok") is True
            else "identity not verified",
        ),
        structured_output_redact_fields=("attempted_credentials", "credential_results"),
        continue_after_credential_error=bool(getattr(args, "defcreds", False)),
        continue_after_credential_success=bool(getattr(args, "defcreds", False)),
        defer_detect_output_until_auth=True,
        live_phase_output=True,
    )


def run_jenkins_stage(args: Any, logger: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    return run_basic_host_audit(
        args,
        logger,
        console=Console(debug=cfg.debug),
        label="JENKINS",
        validate=policy.validate_args,
        build_plan=build_jenkins_plan,
        build_spec=build_jenkins_spec,
    )


__all__ = ["build_jenkins_plan", "build_jenkins_spec", "run_jenkins_stage"]
