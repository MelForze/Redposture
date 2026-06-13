"""Runtime entrypoint for the gitlab audit module."""

from __future__ import annotations

from typing import Any

from ...audit_config import AuditConfig
from ...console import Console
from ...stage_runtime import (
    AuditCommandPlan,
    ModuleAuditSpec,
    build_basic_audit_plan,
    run_basic_host_audit,
)
from . import actions, policy, render

_DEFAULT_PORT = 80
_DEFAULT_PORTS = None


def build_gitlab_plan(args: Any) -> AuditCommandPlan:
    return build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)


def build_gitlab_spec(args: Any) -> ModuleAuditSpec:
    return ModuleAuditSpec(
        module="gitlab",
        label="GITLAB",
        default_port=_DEFAULT_PORT,
        host_stage=actions.host_stage,
        render_module=render,
        colorize=render._render_colored_gitlab_line,
    )


def run_gitlab_stage(args: Any, logger: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    console = Console(debug=cfg.debug)
    return run_basic_host_audit(
        args,
        logger,
        console=console,
        label="GITLAB",
        validate=policy.validate_args,
        build_plan=build_gitlab_plan,
        build_spec=build_gitlab_spec,
    )


__all__ = ["build_gitlab_plan", "build_gitlab_spec", "run_gitlab_stage"]
