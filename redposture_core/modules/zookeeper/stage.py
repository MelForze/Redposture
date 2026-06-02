"""Runtime entrypoint for the zookeeper audit module."""

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

_DEFAULT_PORT = 2181
_DEFAULT_PORTS = None


def _dummy_detect(host: str, port: int) -> AuditRecord:
    return AuditRecord(
        host=str(host),
        port=int(port),
        service="zookeeper",
        status="not_run",
        module="zookeeper",
    )


def build_zookeeper_plan(args: Any) -> AuditCommandPlan:
    return build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)


def build_zookeeper_spec(args: Any) -> ModuleAuditSpec:
    def _render(record: dict[str, Any]) -> list[str]:
        return render_record_with_module(
            render,
            record,
            str(getattr(args, "output_format", "txt") or "txt"),
            debug=bool(getattr(args, "debug", False)),
        )

    return ModuleAuditSpec(
        module="zookeeper",
        label="ZOOKEEPER",
        default_port=_DEFAULT_PORT,
        detect=_dummy_detect,
        detect_context=actions.host_hook,
        render=_render,
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
    runner = AuditCommandRunner(args=args, spec=build_zookeeper_spec(args), logger=logger, emit_line=console.plain)
    try:
        result = runner.run_plan(plan)
    except OSError as exc:
        console.error(f"failed to process zookeeper output: {exc}")
        return 2
    if result.detected_count == 0 and hasattr(console, "warn"):
        console.warn("all zookeeper targets are unreachable")
    return 0


__all__ = ["build_zookeeper_plan", "build_zookeeper_spec", "run_zookeeper_stage"]
