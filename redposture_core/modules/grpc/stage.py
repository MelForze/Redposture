"""Runtime entrypoint for the grpc audit module."""

from __future__ import annotations

import base64
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

_DEFAULT_PORT = 50051
_DEFAULT_PORTS = None


def build_grpc_plan(args: Any) -> AuditCommandPlan:
    return build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)


def build_grpc_spec(args: Any) -> ModuleAuditSpec:
    def _render(record: AuditRecord) -> list[str]:
        return render_record_with_module(
            render,
            record,
            str(getattr(args, "output_format", "txt") or "txt"),
            debug=bool(getattr(args, "debug", False)),
        )

    return ModuleAuditSpec(
        module="grpc",
        label="GRPC",
        default_port=_DEFAULT_PORT,
        detect=actions.detect,
        auth=actions.auth,
        capabilities=actions.capabilities,
        data=actions.data,
        render=_render,
    )


def run_grpc_stage(args: Any, logger: Any) -> int:
    console = Console(debug=bool(getattr(args, "debug", False)))
    if getattr(args, "token", None):
        args.username = None
        args.password = None
    validation_rc = policy.validate_args(args, console)
    if validation_rc is not None:
        return int(validation_rc)
    try:
        plan = build_grpc_plan(args)
    except ValueError as exc:
        console.error(str(exc))
        return 2
    if bool(getattr(args, "debug", False)) and not getattr(args, "debug_emit", None):
        args.debug_emit = console.info
    if bool(getattr(args, "debug", False)):
        suffix = f" format={getattr(args, 'output_format', 'txt') or 'txt'}"
        if getattr(args, "output", None):
            suffix += f" output={args.output}"
        console.info("grpc audit started:" + suffix)
    runner = AuditCommandRunner(args=args, spec=build_grpc_spec(args), logger=logger, emit_line=console.plain)
    try:
        result = runner.run_plan(plan)
    except OSError as exc:
        console.error(f"failed to process grpc output: {exc}")
        return 2
    openapi_path = str(getattr(args, "openapi", "") or "").strip()
    if openapi_path:
        descriptor_bytes: list[bytes] = []
        for record in result.records:
            raw_items = record.get("descriptor_protos_b64")
            if not isinstance(raw_items, list):
                continue
            for item in raw_items:
                if not isinstance(item, str) or not item.strip():
                    continue
                try:
                    descriptor_bytes.append(base64.b64decode(item))
                except (ValueError, OSError):
                    continue
            if descriptor_bytes:
                break
        if descriptor_bytes:
            try:
                actions._write_openapi_document(openapi_path, descriptor_bytes)
            except OSError as exc:
                console.error(f"failed to write grpc OpenAPI artifact: {exc}")
                return 2
    if result.detected_count == 0 and hasattr(console, "warn"):
        console.warn("all grpc targets are unreachable")
    return 0


__all__ = ["build_grpc_plan", "build_grpc_spec", "run_grpc_stage"]
