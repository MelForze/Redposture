"""Runtime entrypoint for the zookeeper audit module."""

from __future__ import annotations

from typing import Any

from ...console import Console
from ...stage_runtime import (
    AuditCommandPlan,
    AuditCommandRunner,
    ModuleAuditSpec,
    build_basic_audit_plan,
)
from . import actions, policy, render

_DEFAULT_PORT = 2181
_DEFAULT_PORTS = None


def build_zookeeper_plan(args: Any) -> AuditCommandPlan:
    return build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)


def build_zookeeper_spec(args: Any) -> ModuleAuditSpec:
    return ModuleAuditSpec(
        module="zookeeper",
        label="ZOOKEEPER",
        default_port=_DEFAULT_PORT,
        host_stage=actions.host_stage,
        render_module=render,
        colorize=render._render_colored_zookeeper_line,
    )


def run_zookeeper_stage(args: Any, logger: Any) -> int:
    console = Console(debug=bool(getattr(args, "debug", False)))
    if getattr(args, "username", None) is not None:
        args.username = str(args.username).strip()
        if args.username == "":
            args.username = None
    if getattr(args, "password", None) is not None:
        args.password = str(args.password).strip()
        if args.username is None and args.password == "":
            args.password = None
    validation_rc = policy.validate_args(args, console)
    if validation_rc is not None:
        return int(validation_rc)
    try:
        plan = build_zookeeper_plan(args)
    except ValueError as exc:
        console.error(str(exc))
        return 2
    if bool(getattr(args, "debug", False)) and not getattr(args, "debug_emit", None):
        args.debug_emit = console.info
    if bool(getattr(args, "debug", False)):
        suffix = f" format={getattr(args, 'output_format', 'txt') or 'txt'}"
        if getattr(args, "output", None):
            suffix += f" output={args.output}"
        console.info("zookeeper audit started:" + suffix)
    runner = AuditCommandRunner(args=args, spec=build_zookeeper_spec(args), logger=logger, console=console)
    try:
        result = runner.run_plan(plan)
    except OSError as exc:
        console.error(f"failed to process zookeeper output: {exc}")
        return 2
    if bool(getattr(args, "debug", False)) and result.detected_count == 0 and hasattr(console, "warn"):
        console.warn("all zookeeper targets are unreachable")
    return 0


__all__ = ["build_zookeeper_plan", "build_zookeeper_spec", "run_zookeeper_stage"]
