"""Runtime entrypoint for the docker audit module."""

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

_DEFAULT_PORT = 2375
_DEFAULT_PORTS: tuple[int, ...] | None = (2375, 2376, 4243, 12375, 12376)


def build_docker_plan(args: Any) -> AuditCommandPlan:
    return build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)


def build_docker_spec(args: Any) -> ModuleAuditSpec:
    return ModuleAuditSpec(
        module="docker",
        label="DOCKER",
        default_port=_DEFAULT_PORT,
        host_stage=actions.host_stage,
        render_module=render,
        colorize=render._render_colored_docker_line,
    )


def run_docker_stage(args: Any, logger: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    console = Console(debug=cfg.debug)
    return run_basic_host_audit(
        args,
        logger,
        console=console,
        label="DOCKER",
        validate=policy.validate_args,
        build_plan=build_docker_plan,
        build_spec=build_docker_spec,
    )


__all__ = ["build_docker_plan", "build_docker_spec", "run_docker_stage"]
