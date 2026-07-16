"""Runtime entrypoint for the keeper audit module."""

from __future__ import annotations

from typing import Any

from ...audit_config import AuditConfig
from ...audit_models import AuditRecord
from ...console import Console
from ...stage_runtime import AuditCommandPlan, AuditCommandRunner, ModuleAuditSpec, build_basic_audit_plan
from . import actions, policy, render
from .types import KeeperFingerprintCache

_DEFAULT_PORT = 9181
_DEFAULT_PORTS: tuple[int, ...] | None = (9181,)


def build_keeper_plan(args: Any) -> AuditCommandPlan:
    return build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)


def _is_keeper_detected(record: AuditRecord) -> bool:
    return bool(record.extra.get("is_zookeeper_compatible")) and record.extra.get("is_keeper") is not False


def build_keeper_spec(args: Any) -> ModuleAuditSpec:
    _ = args
    return ModuleAuditSpec(
        module="keeper",
        label="KEEPER",
        default_port=_DEFAULT_PORT,
        host_stage=actions.host_stage,
        render_module=render,
        colorize=render._render_colored_keeper_line,
        is_detected=_is_keeper_detected,
        keep_anonymous_open_no_auth=True,
    )


def run_keeper_stage(args: Any, logger: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    console = Console(debug=cfg.debug)
    if getattr(args, "username", None) is not None:
        args.username = str(args.username).strip() or None
    if getattr(args, "password", None) is not None:
        args.password = str(args.password).strip()
        if args.username is None and args.password == "":
            args.password = None
    validation_rc = policy.validate_args(args, console)
    if validation_rc is not None:
        return int(validation_rc)
    try:
        plan = build_keeper_plan(args)
    except ValueError as exc:
        console.error(str(exc))
        return 2
    args.keeper_probe_cache = KeeperFingerprintCache()
    if cfg.debug and not getattr(args, "debug_emit", None):
        args.debug_emit = console.info
    if cfg.debug:
        suffix = f" format={cfg.output_format}"
        if cfg.output:
            suffix += f" output={args.output}"
        console.info("keeper audit started:" + suffix)
    runner = AuditCommandRunner(args=args, spec=build_keeper_spec(args), logger=logger, console=console)
    try:
        result = runner.run_plan(plan)
    except OSError as exc:
        console.error(f"failed to process keeper output: {exc}")
        return 2
    if cfg.debug and result.detected_count == 0 and hasattr(console, "warn"):
        console.warn("all keeper targets are unreachable or not ClickHouse Keeper")
    return 0


__all__ = ["build_keeper_plan", "build_keeper_spec", "run_keeper_stage"]
