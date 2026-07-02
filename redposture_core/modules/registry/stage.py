"""Runtime entrypoint for the registry audit module."""

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

_DEFAULT_PORT = 5000
_DEFAULT_PORTS: tuple[int, ...] | None = (5000, 15000)


def build_registry_plan(args: Any) -> AuditCommandPlan:
    return build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)


def build_registry_spec(args: Any) -> ModuleAuditSpec:
    return ModuleAuditSpec(
        module="registry",
        label="REGISTRY",
        default_port=_DEFAULT_PORT,
        host_stage=actions.host_stage,
        render_module=render,
        colorize=render._render_colored_registry_line,
        # E3 opt-in: Docker Registry anon-open (public registries, no auth
        # required) is confirmed by the /v2/ probe returning 200.
        keep_anonymous_open_no_auth=True,
    )


def run_registry_stage(args: Any, logger: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    console = Console(debug=cfg.debug)
    return run_basic_host_audit(
        args,
        logger,
        console=console,
        label="REGISTRY",
        validate=policy.validate_args,
        build_plan=build_registry_plan,
        build_spec=build_registry_spec,
    )


__all__ = ["build_registry_plan", "build_registry_spec", "run_registry_stage"]
