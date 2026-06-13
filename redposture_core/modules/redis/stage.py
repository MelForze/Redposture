"""Runtime entrypoint for the redis audit module."""

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

_DEFAULT_PORT = 6379
_DEFAULT_PORTS = None


def build_redis_plan(args: Any) -> AuditCommandPlan:
    return build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)


def build_redis_spec(args: Any) -> ModuleAuditSpec:
    return ModuleAuditSpec(
        module="redis",
        label="REDIS",
        default_port=_DEFAULT_PORT,
        host_stage=actions.host_stage,
        render_module=render,
        colorize=render._render_colored_redis_line,
    )


def run_redis_stage(args: Any, logger: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    console = Console(debug=cfg.debug)
    return run_basic_host_audit(
        args,
        logger,
        console=console,
        label="REDIS",
        validate=policy.validate_args,
        build_plan=build_redis_plan,
        build_spec=build_redis_spec,
    )


__all__ = ["build_redis_plan", "build_redis_spec", "run_redis_stage"]
