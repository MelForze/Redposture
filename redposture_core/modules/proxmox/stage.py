"""Runtime entrypoint for the proxmox audit module."""

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

_DEFAULT_PORT = 8006
_DEFAULT_PORTS = None


def build_proxmox_plan(args: Any) -> AuditCommandPlan:
    return build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)


def build_proxmox_spec(args: Any) -> ModuleAuditSpec:
    return ModuleAuditSpec(
        module="proxmox",
        label="PROXMOX",
        default_port=_DEFAULT_PORT,
        host_stage=actions.host_stage,
        render_module=render,
        colorize=render._render_colored_proxmox_line,
    )


def run_proxmox_stage(args: Any, logger: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    console = Console(debug=cfg.debug)
    return run_basic_host_audit(
        args,
        logger,
        console=console,
        label="PROXMOX",
        validate=policy.validate_args,
        build_plan=build_proxmox_plan,
        build_spec=build_proxmox_spec,
    )


__all__ = ["build_proxmox_plan", "build_proxmox_spec", "run_proxmox_stage"]
