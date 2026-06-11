"""Runtime entrypoint for the qdrant audit module."""

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

_DEFAULT_PORT = 6333
_DEFAULT_PORTS = None


def build_qdrant_plan(args: Any) -> AuditCommandPlan:
    return build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)


def build_qdrant_spec(args: Any) -> ModuleAuditSpec:
    def _render(record: AuditRecord) -> list[str]:
        return render_record_with_module(
            render,
            record,
            str(getattr(args, "output_format", "txt") or "txt"),
            debug=bool(getattr(args, "debug", False)),
        )

    return ModuleAuditSpec(
        module="qdrant",
        label="QDRANT",
        default_port=_DEFAULT_PORT,
        host_stage=actions.host_stage,
        render=_render,
    )


def run_qdrant_stage(args: Any, logger: Any) -> int:
    console = Console(debug=bool(getattr(args, "debug", False)))
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
    try:
        runner = AuditCommandRunner(args=args, spec=build_qdrant_spec(args), logger=logger, emit_line=console.plain)
        try:
            runner.run_plan(plan)
        except OSError as exc:
            console.error(str(exc))
            return 2
    finally:
        if listener is not None:
            hits = actions._qdrant_ssrf_capture_hits(listener)
            actions._stop_qdrant_ssrf_capture_listener(listener)
            console.info(f"qdrant audit complete: ssrf_hits={len(hits)}")
    return 0


__all__ = ["build_qdrant_plan", "build_qdrant_spec", "run_qdrant_stage"]
