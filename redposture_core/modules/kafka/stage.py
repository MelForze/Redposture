"""Runtime entrypoint for the kafka audit module."""

from __future__ import annotations

from typing import Any

from ...console import Console
from ...stage_runtime import (
    AuditCommandPlan,
    AuditCommandRunner,
    AuditCredentialRun,
    ModuleAuditSpec,
    build_basic_audit_plan,
    has_username_password_credential_file,
)
from . import actions, policy, render

_DEFAULT_PORT = 9092
_DEFAULT_PORTS = None


def build_kafka_plan(args: Any) -> AuditCommandPlan:
    return build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)


def build_kafka_spec(args: Any) -> ModuleAuditSpec:
    return ModuleAuditSpec(
        module="kafka",
        label="KAFKA",
        default_port=_DEFAULT_PORT,
        host_stage=actions.host_stage,
        render_module=render,
        colorize=render._render_colored_kafka_line,
    )


def run_kafka_stage(args: Any, logger: Any) -> int:
    console = Console(debug=bool(getattr(args, "debug", False)))
    validation_rc = policy.validate_args(args, console)
    if validation_rc is not None:
        return int(validation_rc)
    if not has_username_password_credential_file(args) and not (
        getattr(args, "username", None) is not None and getattr(args, "password", None) is None
    ):
        args._audit_credential_runs = tuple(
            AuditCredentialRun(username=user, password=password, source="default" if user else "anonymous")
            for user, password in actions._build_credential_runs(
                getattr(args, "username", None), getattr(args, "password", None), bool(getattr(args, "defcreds", False))
            )
        )
    try:
        plan = build_kafka_plan(args)
    except ValueError as exc:
        console.error(str(exc))
        return 2
    if bool(getattr(args, "debug", False)) and not getattr(args, "debug_emit", None):
        args.debug_emit = console.info
    if bool(getattr(args, "debug", False)):
        suffix = f" format={getattr(args, 'output_format', 'txt') or 'txt'}"
        if getattr(args, "output", None):
            suffix += f" output={args.output}"
        console.info("kafka audit started: mode=" + _kafka_mode(args) + suffix)
    runner = AuditCommandRunner(args=args, spec=build_kafka_spec(args), logger=logger, console=console)
    try:
        result = runner.run_plan(plan)
    except OSError as exc:
        console.error(f"failed to process kafka output: {exc}")
        return 2
    if bool(getattr(args, "debug", False)) and result.detected_count == 0 and hasattr(console, "warn"):
        console.warn("all kafka targets are unreachable")
    return 0


__all__ = ["build_kafka_plan", "build_kafka_spec", "run_kafka_stage"]


def _kafka_mode(args: Any) -> str:
    parts: list[str] = []
    if bool(getattr(args, "show_topics", False)):
        parts.append("show-topics")
    topic = getattr(args, "topic", None) or getattr(args, "query_topic", None)
    if topic:
        parts.append(f"topic={topic}")
    if bool(getattr(args, "dump", False)):
        parts.append("dump")
        max_messages = getattr(args, "max_messages", None)
        if max_messages is not None:
            parts.append(f"max={max_messages}")
    return ",".join(parts) if parts else "detect"
