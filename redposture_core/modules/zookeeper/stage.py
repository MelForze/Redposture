"""Runtime entrypoint for the zookeeper audit module."""

from __future__ import annotations

from typing import Any

from ...audit_config import AuditConfig
from ...console import Console
from ...stage_runtime import (
    AuditCommandPlan,
    AuditCommandRunner,
    ModuleAuditSpec,
    build_basic_audit_plan,
)
from . import actions, policy, render

_DEFAULT_PORT = 2181
_DEFAULT_PORTS: tuple[int, ...] | None = (2181, 12181)


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
        # E3 opt-in: ZooKeeper anon-open (default ACLs, no digest ACL on /)
        # is confirmed by the anon probe listing /.
        keep_anonymous_open_no_auth=True,
    )


def run_zookeeper_stage(args: Any, logger: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    console = Console(debug=cfg.debug)
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
    if cfg.debug and not getattr(args, "debug_emit", None):
        args.debug_emit = console.info
    if cfg.debug:
        suffix = f" format={cfg.output_format}"
        if cfg.output:
            suffix += f" output={args.output}"
        console.info("zookeeper audit started:" + suffix)
    runner = AuditCommandRunner(args=args, spec=build_zookeeper_spec(args), logger=logger, console=console)
    try:
        result = runner.run_plan(plan)
    except OSError as exc:
        console.error(f"failed to process zookeeper output: {exc}")
        return 2
    if cfg.debug and result.detected_count == 0 and hasattr(console, "warn"):
        console.warn("all zookeeper targets are unreachable")
    return 0


__all__ = ["build_zookeeper_plan", "build_zookeeper_spec", "run_zookeeper_stage"]
