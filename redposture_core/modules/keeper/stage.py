"""Runtime entrypoint for the keeper audit module."""

from __future__ import annotations

from typing import Any

from ...audit_config import AuditConfig
from ...audit_models import AuditRecord
from ...console import Console
from ...show_limits import dump_flag_enabled, dump_flag_limit, show_flag_enabled, show_flag_limit
from ...stage_runtime import AuditCommandPlan, AuditCommandRunner, ModuleAuditSpec, build_basic_audit_plan
from . import actions, policy, render
from .types import KeeperFingerprintCache

_DEFAULT_PORT = 9181
_DEFAULT_PORTS: tuple[int, ...] | None = (9181,)
_PRODUCTION_HOST_STAGE = actions.host_stage
_PRODUCTION_AUDIT_HOST = actions._audit_keeper_host


def build_keeper_plan(args: Any) -> AuditCommandPlan:
    return build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)


def _is_keeper_detected(record: AuditRecord) -> bool:
    return bool(record.extra.get("is_zookeeper_compatible")) and record.extra.get("is_keeper") is not False


def build_keeper_spec(args: Any) -> ModuleAuditSpec:
    options: dict[str, Any] = {
        "show_znodes": show_flag_enabled(getattr(args, "show_znodes", False)),
        "show_znodes_limit": show_flag_limit(getattr(args, "show_znodes", False)),
        "dump": dump_flag_enabled(getattr(args, "dump", False)),
        "dump_limit": dump_flag_limit(getattr(args, "dump", False)),
        "query_znode": str(getattr(args, "znode", "") or "").strip() or None,
        "max_znodes": int(getattr(args, "max_znodes", 2000) or 2000),
        "enum_workers": int(getattr(args, "enum_workers", 3) or 3),
        "keeper_probe_cache": getattr(args, "keeper_probe_cache", None) or KeeperFingerprintCache(),
        "insecure": bool(getattr(args, "insecure", False)),
        "ca_file": getattr(args, "ca_file", None),
        "tls_cert": getattr(args, "tls_cert", None),
        "tls_key": getattr(args, "tls_key", None),
    }
    resolved_host_stage = getattr(actions, _PRODUCTION_HOST_STAGE.__name__, _PRODUCTION_HOST_STAGE)
    use_lifecycle_hooks = (
        actions.host_stage is _PRODUCTION_HOST_STAGE
        and resolved_host_stage is _PRODUCTION_HOST_STAGE
        and actions._audit_keeper_host is _PRODUCTION_AUDIT_HOST
    )

    def _state_factory(_ctx: Any) -> actions.KeeperLifecycleState:
        return actions.KeeperLifecycleState(
            requested_config=actions._transport_config(
                insecure=bool(options["insecure"]),
                ca_file=options["ca_file"],
                tls_cert=options["tls_cert"],
                tls_key=options["tls_key"],
            )
        )

    def _detect(ctx: Any) -> AuditRecord:
        return AuditRecord.from_mapping(
            actions.detect_keeper(ctx, options),
            module="keeper",
            service="keeper",
        )

    def _auth(ctx: Any, record: AuditRecord) -> AuditRecord:
        return AuditRecord.from_mapping(
            actions.authenticate_keeper(ctx, record, options),
            module="keeper",
            service="keeper",
        )

    def _data(ctx: Any, record: AuditRecord) -> AuditRecord:
        return AuditRecord.from_mapping(
            actions.collect_keeper_data(ctx, record, options),
            module="keeper",
            service="keeper",
        )

    return ModuleAuditSpec(
        module="keeper",
        label="KEEPER",
        default_port=_DEFAULT_PORT,
        host_stage=actions.host_stage,
        detect=_detect if use_lifecycle_hooks else None,
        auth=_auth if use_lifecycle_hooks else None,
        data=_data if use_lifecycle_hooks else None,
        lifecycle_state_factory=_state_factory if use_lifecycle_hooks else None,
        lifecycle_state_close=(lambda state: state.close()) if use_lifecycle_hooks else None,
        render_module=render,
        colorize=render._render_colored_keeper_line,
        is_detected=_is_keeper_detected,
        keep_anonymous_open_no_auth=True,
    )


def run_keeper_stage(args: Any, logger: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    console = Console(debug=cfg.debug)
    if hasattr(console, "set_structured_output"):
        console.set_structured_output(cfg.output_format == "json")
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
