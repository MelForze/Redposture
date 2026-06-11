"""Runtime entrypoint for the consul audit module."""

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

_DEFAULT_PORT = 8500
_DEFAULT_PORTS = None


def build_consul_plan(args: Any) -> AuditCommandPlan:
    return build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)


def build_consul_spec(args: Any) -> ModuleAuditSpec:
    def _render(record: AuditRecord) -> list[str]:
        return render_record_with_module(
            render,
            record,
            str(getattr(args, "output_format", "txt") or "txt"),
            debug=bool(getattr(args, "debug", False)),
        )

    return ModuleAuditSpec(
        module="consul",
        label="CONSUL",
        default_port=_DEFAULT_PORT,
        host_stage=actions.host_stage,
        render=_render,
    )


def run_consul_stage(args: Any, logger: Any) -> int:
    console = Console(debug=bool(getattr(args, "debug", False)))
    validation_rc = policy.validate_args(args, console)
    if validation_rc is not None:
        return int(validation_rc)
    _normalize_consul_command_args(args, console)
    try:
        plan = build_consul_plan(args)
    except ValueError as exc:
        console.error(str(exc))
        return 2
    listener_info: dict[str, Any] | None = None
    if bool(getattr(args, "revshell", False)) and bool(getattr(args, "revshell_listen", False)):
        console.warn("--listen starts one local listener for all selected targets/ports")
        listener_info = actions._start_local_nc_listener(int(getattr(args, "revshell_port", 0) or 0))
        if bool(listener_info.get("started")):
            console.info(f"local listener started: {listener_info.get('cmd') or '-'}")
        else:
            console.warn(f"local listener not started: {listener_info.get('error') or 'unknown error'}")
    runner = AuditCommandRunner(args=args, spec=build_consul_spec(args), logger=logger, emit_line=console.plain)
    try:
        result = runner.run_plan(plan)
    except OSError as exc:
        console.error(f"failed to process consul output: {exc}")
        return 2
    if bool(getattr(args, "debug", False)) and result.detected_count == 0:
        console.warn("all consul targets are unreachable")
    if listener_info is not None:
        registered = any(bool(record.get("script_revshell")) for record in result.records)
        if not registered:
            console.warn("local listener not started: revshell check was not registered")
    return 0


def _normalize_consul_command_args(args: Any, console: Any) -> None:
    if getattr(args, "token", None) and (
        getattr(args, "username", None) is not None or getattr(args, "password", None) is not None
    ):
        console.warn("--token is set; Basic auth credentials are ignored")
        args.username = None
        args.password = None

    if bool(getattr(args, "dump", False)):
        specific = any(
            bool(getattr(args, name, None))
            for name in ("kv_key", "service_dump_name", "agent_name", "node_name", "revshell_check_id")
        )
        args.dump_all_requested = not specific
        args.show_services = True
        args.show_agents = True
        args.show_checks = True
        args.show_nodes = True
    check_id = str(getattr(args, "revshell_check_id", "") or "")
    if check_id.startswith("id:"):
        args.revshell_check_id = check_id[3:]

    if bool(getattr(args, "revshell", False)) and getattr(args, "revshell_payload", None):
        if getattr(args, "delete_revshell", False):
            console.warn("--lhost/--lport ignored with --revshell --delete")
            console.warn("--payload ignored with --revshell --delete")
        else:
            console.warn("--lhost/--lport ignored when --payload is set")
    if bool(getattr(args, "delete_revshell", False)) and not bool(getattr(args, "revshell", False)):
        if getattr(args, "revshell_host", None) or getattr(args, "revshell_port", None):
            console.warn("--lhost/--lport ignored with --delete --check-id")
        if getattr(args, "revshell_payload", None):
            console.warn("--payload ignored with --delete --check-id")


__all__ = ["build_consul_plan", "build_consul_spec", "run_consul_stage"]
