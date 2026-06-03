"""Runtime entrypoint for the proxmox audit module."""

from __future__ import annotations

from typing import Any

from ...audit_models import AuditRecord
from ...console import Console
from ...stage_runtime import (
    AuditCommandPlan,
    AuditCommandRunner,
    ModuleAuditSpec,
    build_basic_audit_plan,
    render_record_with_module,
)
from . import actions, policy, render

_DEFAULT_PORT = 8006
_DEFAULT_PORTS = None


def build_proxmox_plan(args: Any) -> AuditCommandPlan:
    return build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)


def build_proxmox_spec(args: Any) -> ModuleAuditSpec:
    def _render(record: AuditRecord) -> list[str]:
        return render_record_with_module(
            render,
            record,
            str(getattr(args, "output_format", "txt") or "txt"),
            debug=bool(getattr(args, "debug", False)),
        )

    return ModuleAuditSpec(
        module="proxmox",
        label="PROXMOX",
        default_port=_DEFAULT_PORT,
        detect=actions.detect,
        auth=actions.auth,
        capabilities=actions.capabilities,
        data=actions.data,
        render=_render,
    )


def run_proxmox_stage(args: Any, logger: Any) -> int:
    console = Console(debug=bool(getattr(args, "debug", False)))
    validation_rc = policy.validate_args(args, console)
    if validation_rc is not None:
        return int(validation_rc)
    try:
        plan = build_proxmox_plan(args)
    except ValueError as exc:
        console.error(str(exc))
        return 2
    if bool(getattr(args, "debug", False)) and not getattr(args, "debug_emit", None):
        args.debug_emit = console.info
    if bool(getattr(args, "debug", False)):
        suffix = f" format={getattr(args, 'output_format', 'txt') or 'txt'}"
        if getattr(args, "output", None):
            suffix += f" output={args.output}"
        console.info("proxmox audit started:" + suffix)
    runner = AuditCommandRunner(args=args, spec=build_proxmox_spec(args), logger=logger, emit_line=console.plain)
    try:
        result = runner.run_plan(plan)
    except OSError as exc:
        console.error(f"failed to process proxmox output: {exc}")
        return 2
    if result.detected_count == 0 and hasattr(console, "warn"):
        console.warn("all proxmox targets are unreachable")
    return 0


__all__ = ["build_proxmox_plan", "build_proxmox_spec", "run_proxmox_stage"]
