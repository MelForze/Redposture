"""Runtime entrypoint for the consul audit module."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from ...audit_config import AuditConfig
from ...audit_models import AuditRecord
from ...clients.http_session import HttpSessionPool
from ...console import Console
from ...show_limits import dump_flag_enabled, dump_flag_limit
from ...stage_runtime import (
    AuditCommandPlan,
    AuditCommandRunner,
    ModuleAuditSpec,
    build_basic_audit_plan,
    command_result_exit_code,
    install_record_callback,
)
from . import actions, policy, render

_DEFAULT_PORT = 8500
_DEFAULT_PORTS = (8500, 8501, 18500, 18501, 28500, 28501)
_PRODUCTION_HOST_STAGE = actions.host_stage
_PRODUCTION_AUDIT_HOST = actions._audit_consul_host


def build_consul_plan(args: Any) -> AuditCommandPlan:
    plan = build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)
    if plan.target_plan is not None:
        plan = replace(
            plan,
            target_plan=plan.target_plan.with_scheme_default_ports({"http": 8500, "https": 8501}),
        )
    return plan


def _build_consul_host_stage_options(args: Any) -> dict[str, Any]:
    return {
        "do_ssrf": bool(getattr(args, "ssrf_urls", None)),
        "ssrf_urls": list(getattr(args, "ssrf_urls", None) or []),
        "show_keys": bool(getattr(args, "show_keys", False)),
        "kv_key": str(getattr(args, "kv_key", "") or "").strip() or None,
        "dump_requested": dump_flag_enabled(getattr(args, "dump", False)),
        "dump_all_requested": bool(getattr(args, "dump_all_requested", False)),
        "show_services": bool(getattr(args, "show_services", False)),
        "show_agents": bool(getattr(args, "show_agents", False)),
        "show_checks": bool(getattr(args, "show_checks", False)),
        "check_dump_id": getattr(args, "check_dump_id", None),
        "show_nodes": bool(getattr(args, "show_nodes", False)),
        "service_name": None,
        "service_dump_name": str(getattr(args, "service_dump_name", "") or "").strip() or None,
        "agent_dump_name": getattr(args, "agent_dump_name", None),
        "node_dump_name": getattr(args, "node_dump_name", None),
        "delete_service": False,
        "service_args": None,
        "revshell_enabled": bool(getattr(args, "revshell", False)),
        "delete_revshell": bool(getattr(args, "delete_revshell", False)),
        "revshell_listen": bool(getattr(args, "revshell_listen", False)),
        "revshell_host": str(getattr(args, "revshell_host", "") or "").strip() or None,
        "revshell_port": getattr(args, "revshell_port", None),
        "revshell_payload": str(getattr(args, "revshell_payload", "") or "").strip() or None,
        "revshell_check_id": str(getattr(args, "revshell_check_id", "") or "").strip() or None,
        "dump_limit": dump_flag_limit(getattr(args, "dump", False)),
    }


def build_consul_spec(args: Any) -> ModuleAuditSpec:
    options = _build_consul_host_stage_options(args)
    resolved_host_stage = getattr(actions, _PRODUCTION_HOST_STAGE.__name__, _PRODUCTION_HOST_STAGE)
    use_lifecycle_hooks = (
        actions.host_stage is _PRODUCTION_HOST_STAGE
        and resolved_host_stage is _PRODUCTION_HOST_STAGE
        and actions._audit_consul_host is _PRODUCTION_AUDIT_HOST
    )

    def _detect(ctx: Any) -> AuditRecord:
        return AuditRecord.from_mapping(actions.detect_consul(ctx, options), module="consul", service="consul")

    def _auth(ctx: Any, record: Any) -> AuditRecord:
        return AuditRecord.from_mapping(
            actions.authenticate_consul(ctx, record, options),
            module="consul",
            service="consul",
        )

    def _data(ctx: Any, record: Any) -> AuditRecord:
        return AuditRecord.from_mapping(
            actions.collect_consul_data(ctx, record, options),
            module="consul",
            service="consul",
        )

    def _state_factory(ctx: Any) -> actions.ConsulLifecycleState:
        target_scheme = str(getattr(getattr(ctx, "target", None), "scheme", "") or "").lower()
        tls_material = any(
            (
                bool(getattr(args, "insecure", False)),
                bool(getattr(args, "tls_ca", None)),
                bool(getattr(args, "tls_cert", None)),
            )
        )
        if bool(getattr(args, "plaintext", False)):
            preferred_scheme = "http"
            strict_scheme = True
        elif bool(getattr(args, "tls", False)) or tls_material:
            preferred_scheme = "https"
            strict_scheme = True
        elif target_scheme in {"http", "https"}:
            preferred_scheme = target_scheme
            strict_scheme = True
        else:
            preferred_scheme = None
            strict_scheme = False
        return actions.ConsulLifecycleState(
            insecure=bool(getattr(args, "insecure", False)),
            ca_file=getattr(args, "tls_ca", None),
            client_cert=getattr(args, "tls_cert", None),
            client_key=getattr(args, "tls_key", None),
            preferred_scheme=preferred_scheme,
            strict_scheme=strict_scheme,
            http=HttpSessionPool(
                timeout=float(getattr(args, "timeout", 1.0)),
                insecure=bool(getattr(args, "insecure", False)),
                ca_file=getattr(args, "tls_ca", None),
                cert_file=getattr(args, "tls_cert", None),
                key_file=getattr(args, "tls_key", None),
                proxy=getattr(args, "_proxy_config", None),
            ),
        )

    return ModuleAuditSpec(
        module="consul",
        label="CONSUL",
        default_port=_DEFAULT_PORT,
        host_stage=actions.host_stage,
        host_stage_options=options,
        detect=_detect if use_lifecycle_hooks else None,
        auth=_auth if use_lifecycle_hooks else None,
        data=_data if use_lifecycle_hooks else None,
        lifecycle_state_factory=_state_factory if use_lifecycle_hooks else None,
        lifecycle_state_close=(lambda state: state.close()) if use_lifecycle_hooks else None,
        render_module=render,
        colorize=render._render_colored_consul_line,
    )


def run_consul_stage(args: Any, logger: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    console = Console(debug=cfg.debug)
    if hasattr(console, "set_structured_output"):
        console.set_structured_output(cfg.output_format == "json")
    validation_rc = policy.validate_args(args, console)
    if validation_rc is not None:
        return int(validation_rc)
    _normalize_consul_command_args(args, console)
    try:
        plan = build_consul_plan(args)
    except ValueError as exc:
        console.error(str(exc))
        return 2
    try:
        runner = AuditCommandRunner(args=args, spec=build_consul_spec(args), logger=logger, console=console)
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
    revshell_registered = False
    previous_record_callback = getattr(args, "_record_callback", None)

    def _capture_revshell_record(record: dict[str, Any]) -> None:
        nonlocal revshell_registered
        if callable(previous_record_callback):
            previous_record_callback(record)
        if bool(record.get("script_revshell")):
            revshell_registered = True

    try:
        if listener_info is not None:
            with install_record_callback(args, _capture_revshell_record):
                result = runner.run_plan(plan)
        else:
            result = runner.run_plan(plan)
    except ValueError as exc:
        console.error(str(exc))
        return 2
    except OSError as exc:
        console.error(f"failed to process consul output: {exc}")
        return 2
    if cfg.debug and result.detected_count == 0:
        console.warn("all consul targets are unreachable")
    if listener_info is not None:
        if not revshell_registered:
            console.warn("local listener not started: revshell check was not registered")
    return command_result_exit_code(result)


def _normalize_consul_command_args(args: Any, console: Any) -> None:
    if getattr(args, "token", None) and (
        getattr(args, "username", None) is not None or getattr(args, "password", None) is not None
    ):
        console.warn("--token is set; Basic auth credentials are ignored")
        args.username = None
        args.password = None

    dump_requested = dump_flag_enabled(getattr(args, "dump", False))
    args.kv_key = str(getattr(args, "kv_key", "") or "").strip() or None
    args.service_dump_name = str(getattr(args, "service_dump_name", "") or "").strip() or None
    args.agent_dump_name = str(getattr(args, "agent_name", "") or "").strip() or None
    args.node_dump_name = str(getattr(args, "node_name", "") or "").strip() or None
    check_id = str(getattr(args, "revshell_check_id", "") or "").strip()
    if check_id.lower().startswith("id:"):
        check_id = check_id[3:].strip()
    args.revshell_check_id = check_id or None
    args.check_dump_id = args.revshell_check_id if dump_requested else None

    if dump_requested and args.service_dump_name:
        args.show_services = True
    if dump_requested and args.agent_dump_name:
        args.show_agents = True
    if dump_requested and args.node_dump_name:
        args.show_nodes = True
    if dump_requested and args.check_dump_id:
        args.show_checks = True

    dump_scope_selected = any(
        (
            bool(getattr(args, "show_keys", False)),
            bool(args.kv_key),
            bool(getattr(args, "show_services", False)),
            bool(args.service_dump_name),
            bool(getattr(args, "show_agents", False)),
            bool(args.agent_dump_name),
            bool(getattr(args, "show_checks", False)),
            bool(args.check_dump_id),
            bool(getattr(args, "show_nodes", False)),
            bool(args.node_dump_name),
        )
    )
    args.dump_all_requested = bool(dump_requested and not dump_scope_selected)
    if args.dump_all_requested:
        args.show_services = True
        args.show_agents = True
        args.show_checks = True
        args.show_nodes = True

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


__all__ = [
    "_build_consul_host_stage_options",
    "build_consul_plan",
    "build_consul_spec",
    "run_consul_stage",
]
