"""Runtime entrypoint for the etcd audit module."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from ...audit_config import AuditConfig
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

_DEFAULT_PORT = 2379
_DEFAULT_PORTS: tuple[int, ...] | None = (2379, 12379)


def build_etcd_plan(args: Any) -> AuditCommandPlan:
    plan = build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)
    explicit_port = getattr(args, "port", None) is not None or bool(str(getattr(args, "ports", "") or "").strip())
    if not explicit_port and plan.target_plan is not None:
        plan = replace(plan, target_plan=plan.target_plan.with_scheme_default_ports({"http": 80, "https": 443}))
    default_runs = (
        sort_default_audit_credential_runs(
            AuditCredentialRun(username=username, password=password, source="default")
            for username, password in actions._ETCD_DEFAULT_CREDS
        )
        if bool(getattr(args, "defcreds", False))
        else ()
    )
    return replace(
        plan,
        credential_runs=merge_audit_credential_runs(plan.credential_runs, default_runs),
    )


def build_etcd_spec(args: Any) -> ModuleAuditSpec:
    return ModuleAuditSpec(
        module="etcd",
        label="ETCD",
        default_port=_DEFAULT_PORT,
        host_stage=actions.host_stage,
        render_module=render,
        colorize=render._render_colored_etcd_line,
        # E3 opt-in: etcd anon-open cluster (no --auth-enable) is confirmed
        # by the detect probe — v2 /keys or v3 /kv/range succeeded.
        keep_anonymous_open_no_auth=True,
        continue_after_credential_error=bool(getattr(args, "defcreds", False)),
        continue_after_credential_success=bool(getattr(args, "defcreds", False)),
    )


def run_etcd_stage(args: Any, logger: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    console = Console(debug=cfg.debug)
    return run_basic_host_audit(
        args,
        logger,
        console=console,
        label="ETCD",
        validate=policy.validate_args,
        build_plan=build_etcd_plan,
        build_spec=build_etcd_spec,
    )


__all__ = ["build_etcd_plan", "build_etcd_spec", "run_etcd_stage"]
