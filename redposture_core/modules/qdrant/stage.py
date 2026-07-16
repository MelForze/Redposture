"""Runtime entrypoint for the qdrant audit module."""

from __future__ import annotations

from typing import Any

from ...audit_config import AuditConfig
from ...audit_models import AuditRecord
from ...console import Console
from ...show_limits import dump_flag_enabled, dump_flag_limit
from ...stage_runtime import (
    AuditCommandPlan,
    AuditCommandRunner,
    ModuleAuditSpec,
    build_basic_audit_plan,
)
from . import actions, policy, render

_DEFAULT_PORT = 6333
_DEFAULT_PORTS = None
_PRODUCTION_HOST_STAGE = actions.host_stage
_PRODUCTION_AUDIT_HOST = actions._audit_qdrant_host


def build_qdrant_plan(args: Any) -> AuditCommandPlan:
    return build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)


def build_qdrant_spec(args: Any) -> ModuleAuditSpec:
    options = {
        "show_collections": bool(getattr(args, "show_collections", False)),
        "dump_requested": dump_flag_enabled(getattr(args, "dump", False)),
        "dump_limit": dump_flag_limit(getattr(args, "dump", False)),
        "collection_name": str(getattr(args, "collection", "") or "").strip() or None,
        "ssrf_urls": list(getattr(args, "ssrf_urls", None) or []),
    }
    resolved_host_stage = getattr(actions, _PRODUCTION_HOST_STAGE.__name__, _PRODUCTION_HOST_STAGE)
    use_lifecycle_hooks = (
        actions.host_stage is _PRODUCTION_HOST_STAGE
        and resolved_host_stage is _PRODUCTION_HOST_STAGE
        and actions._audit_qdrant_host is _PRODUCTION_AUDIT_HOST
    )

    def _detect(ctx: Any) -> AuditRecord:
        return AuditRecord.from_mapping(actions.detect_qdrant(ctx, options), module="qdrant", service="qdrant")

    def _auth(ctx: Any, record: Any) -> AuditRecord:
        return AuditRecord.from_mapping(
            actions.authenticate_qdrant(ctx, record, options),
            module="qdrant",
            service="qdrant",
        )

    def _data(ctx: Any, record: Any) -> AuditRecord:
        return AuditRecord.from_mapping(
            actions.collect_qdrant_data(ctx, record, options),
            module="qdrant",
            service="qdrant",
        )

    return ModuleAuditSpec(
        module="qdrant",
        label="QDRANT",
        default_port=_DEFAULT_PORT,
        host_stage=actions.host_stage,
        detect=_detect if use_lifecycle_hooks else None,
        auth=_auth if use_lifecycle_hooks else None,
        data=_data if use_lifecycle_hooks else None,
        lifecycle_state_factory=(lambda _ctx: actions.QdrantLifecycleState()) if use_lifecycle_hooks else None,
        deep_gate=(
            lambda record: (
                str(record.status or "") in actions._QDRANT_DEEP_STATUSES,
                f"status={record.status}",
            )
        )
        if use_lifecycle_hooks
        else None,
        render_module=render,
        colorize=render._render_colored_qdrant_line,
        # E3 opt-in: Qdrant anon-open (no --api-key-set config) is confirmed
        # by the detect probe.
        keep_anonymous_open_no_auth=True,
    )


def run_qdrant_stage(args: Any, logger: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    console = Console(debug=cfg.debug)
    if hasattr(console, "set_structured_output"):
        console.set_structured_output(cfg.output_format == "json")
    validation_rc = policy.validate_args(args, console)
    if validation_rc is not None:
        return int(validation_rc)
    try:
        plan = build_qdrant_plan(args)
    except ValueError as exc:
        console.error(str(exc))
        return 2
    listener = None
    if bool(getattr(args, "ssrf_listen", False)):
        try:
            listen_port = int(str(getattr(args, "ssrf_port", None) or "0").split(",", 1)[0])
        except ValueError:
            listen_port = 0
        listener = actions._start_qdrant_ssrf_capture_listener(listen_port)
        if listener.get("started"):
            console.info(f"local SSRF listener started on 127.0.0.1:{listener.get('port')}")
        else:
            console.warn(f"local SSRF listener failed: {listener.get('error') or 'unknown'}")
    args.ssrf_capture = listener
    try:
        runner = AuditCommandRunner(args=args, spec=build_qdrant_spec(args), logger=logger, console=console)
        try:
            runner.run_plan(plan)
        except OSError as exc:
            console.error(str(exc))
            return 2
    finally:
        try:
            delattr(args, "ssrf_capture")
        except AttributeError:
            pass
        if listener is not None:
            hits = actions._qdrant_ssrf_capture_hits(listener)
            actions._stop_qdrant_ssrf_capture_listener(listener)
            console.info(f"qdrant audit complete: ssrf_hits={len(hits)}")
    return 0


__all__ = ["build_qdrant_plan", "build_qdrant_spec", "run_qdrant_stage"]
