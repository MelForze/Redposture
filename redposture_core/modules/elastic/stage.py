"""Runtime entrypoint for the elastic audit module."""

from __future__ import annotations

from typing import Any

from ...audit_models import AuditRecord
from ...console import Console
from ...stage_runtime import (
    AuditCommandPlan,
    AuditCommandRunner,
    AuditCredentialRun,
    ModuleAuditSpec,
    build_basic_audit_plan,
    has_username_password_credential_file,
    render_record_with_module,
)
from . import actions, policy, render

_DEFAULT_PORT = 9200
_DEFAULT_PORTS = None


def build_elastic_plan(args: Any) -> AuditCommandPlan:
    return build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)


def build_elastic_spec(args: Any) -> ModuleAuditSpec:
    def _render(record: AuditRecord) -> list[str]:
        return render_record_with_module(
            render,
            record,
            str(getattr(args, "output_format", "txt") or "txt"),
            debug=bool(getattr(args, "debug", False)),
        )

    return ModuleAuditSpec(
        module="elastic",
        label="ELASTIC",
        default_port=_DEFAULT_PORT,
        host_stage=actions.host_stage,
        render=_render,
    )


def run_elastic_stage(args: Any, logger: Any) -> int:
    console = Console(debug=bool(getattr(args, "debug", False)))
    validation_rc = policy.validate_args(args, console)
    if validation_rc is not None:
        return int(validation_rc)
    if getattr(args, "apitoken", None):
        args.api_token = args.apitoken
        args.token = args.apitoken
        args.username = None
        args.password = None
        args.defcreds = False
    if (
        not getattr(args, "api_token", None)
        and not has_username_password_credential_file(args)
        and not (getattr(args, "username", None) is not None and getattr(args, "password", None) is None)
    ):
        args._audit_credential_runs = tuple(
            AuditCredentialRun(username=user, password=password, source="default" if user else "anonymous")
            for user, password in actions._build_credential_runs(
                getattr(args, "username", None), getattr(args, "password", None), bool(getattr(args, "defcreds", False))
            )
        )
    try:
        plan = build_elastic_plan(args)
    except ValueError as exc:
        console.error(str(exc))
        return 2
    if bool(getattr(args, "debug", False)) and not getattr(args, "debug_emit", None):
        args.debug_emit = console.info
    if bool(getattr(args, "debug", False)):
        suffix = f" format={getattr(args, 'output_format', 'txt') or 'txt'}"
        if getattr(args, "output", None):
            suffix += f" output={args.output}"
        console.info("elastic audit started:" + suffix)
    runner = AuditCommandRunner(args=args, spec=build_elastic_spec(args), logger=logger, emit_line=console.plain)
    try:
        result = runner.run_plan(plan)
    except OSError as exc:
        console.error(f"failed to process elastic output: {exc}")
        return 2
    if bool(getattr(args, "debug", False)) and result.detected_count == 0 and hasattr(console, "warn"):
        console.warn("all elastic targets are unreachable")
    return 0


__all__ = ["build_elastic_plan", "build_elastic_spec", "run_elastic_stage"]
