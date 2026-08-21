"""Runtime entrypoint for the oracle audit module."""

from __future__ import annotations

from typing import Any

from ...audit_config import AuditConfig
from ...console import Console
from ...stage_runtime import (
    AuditCommandPlan,
    AuditCommandRunner,
    AuditCredentialRun,
    ModuleAuditSpec,
    build_basic_audit_plan,
    build_basic_credential_runs,
    command_result_exit_code,
    merge_audit_credential_runs,
    sort_default_audit_credential_runs,
)
from . import actions, policy, render

_DEFAULT_PORT = 1521
_DEFAULT_PORTS: tuple[int, ...] | None = (1521, 2484, 11521)


def build_oracle_plan(args: Any) -> AuditCommandPlan:
    return build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)


def build_oracle_spec(args: Any) -> ModuleAuditSpec:
    return ModuleAuditSpec(
        module="oracle",
        label="ORACLE",
        default_port=_DEFAULT_PORT,
        host_stage=actions.host_stage,
        render_module=render,
        colorize=render._render_colored_oracle_line,
        continue_after_credential_success=bool(getattr(args, "defcreds", False)),
        continue_after_credential_error=bool(getattr(args, "defcreds", False)),
    )


def run_oracle_stage(args: Any, logger: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    console = Console(debug=cfg.debug)
    if hasattr(console, "set_structured_output"):
        console.set_structured_output(cfg.output_format == "json")
    validation_rc = policy.validate_args(args, console)
    if validation_rc is not None:
        return int(validation_rc)
    try:
        supplied_runs = build_basic_credential_runs(args)
        module_runs = tuple(
            AuditCredentialRun(
                username=item.get("username"),
                password=item.get("password"),
                source=str(item.get("source") or "provided"),
            )
            for item in actions._credential_runs(
                None,
                None,
                defcreds=False,
                combo_list=getattr(args, "combo_list", None),
                user_list=getattr(args, "user_list", None),
                pass_list=getattr(args, "pass_list", None),
                spray_passwords=bool(getattr(args, "spray_passwords", False)),
            )
        )
    except ValueError as exc:
        console.error(str(exc))
        return 2
    default_runs = (
        sort_default_audit_credential_runs(
            AuditCredentialRun(username=username, password=password, source="default")
            for username, password in actions._ORACLE_DEFAULT_CREDS
        )
        if bool(getattr(args, "defcreds", False))
        else ()
    )
    args._audit_credential_runs = merge_audit_credential_runs(supplied_runs, module_runs, default_runs)
    try:
        plan = build_oracle_plan(args)
    except ValueError as exc:
        console.error(str(exc))
        return 2
    if cfg.debug and not getattr(args, "debug_emit", None):
        args.debug_emit = console.info
    if cfg.debug:
        suffix = f" format={cfg.output_format}"
        if cfg.output:
            suffix += f" output={cfg.output}"
        console.info("oracle audit started:" + suffix)
    runner = AuditCommandRunner(args=args, spec=build_oracle_spec(args), logger=logger, console=console)
    try:
        result = runner.run_plan(plan)
    except OSError as exc:
        console.error(f"failed to process oracle output: {exc}")
        return 2
    if cfg.debug and command_result_exit_code(result) != 0 and hasattr(console, "warn"):
        console.warn("all oracle targets are unreachable")
    return command_result_exit_code(result)


__all__ = ["build_oracle_plan", "build_oracle_spec", "run_oracle_stage"]
