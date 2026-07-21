"""Runtime entrypoint for the grpc audit module."""

from __future__ import annotations

import base64
from dataclasses import replace
from typing import Any

from ...audit_config import AuditConfig
from ...audit_models import AuditRecord
from ...console import Console
from ...stage_runtime import (
    AuditCommandPlan,
    AuditCommandRunner,
    AuditCredentialRun,
    ModuleAuditSpec,
    build_basic_audit_plan,
    has_username_password_credential_file,
    install_record_callback,
)
from . import actions, policy, render

_DEFAULT_PORT = 50051
_DEFAULT_PORTS = None
_PRODUCTION_HOST_STAGE = actions.host_stage
_PRODUCTION_AUDIT_HOST = actions._audit_grpc_host


def build_grpc_plan(args: Any) -> AuditCommandPlan:
    plan = build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)
    if not bool(getattr(args, "defcreds", False)) or has_username_password_credential_file(args):
        return plan
    candidates = actions._auth_attempt_entries(
        token=getattr(args, "token", None),
        username=getattr(args, "username", None),
        password=getattr(args, "password", None),
        defcreds=True,
    )
    runs = tuple(
        AuditCredentialRun(
            token=str(item.get("token") or "") or None if item.get("type") == "token" else None,
            username=str(item.get("username") or "") if item.get("type") == "basic" else None,
            password=str(item.get("password") or "") if item.get("type") == "basic" else None,
            source="default" if item.get("source") == "defcreds" else "provided",
        )
        for item in candidates
    )
    return replace(plan, credential_runs=runs or (AuditCredentialRun(source="anonymous"),))


def _build_grpc_host_stage_options(args: Any) -> dict[str, Any]:
    invoke_path = str(getattr(args, "invoke", "") or "").strip() or None
    openapi_path = str(getattr(args, "openapi", "") or "").strip()
    if invoke_path is not None:
        actions._split_grpc_method_path(invoke_path)
    metadata = getattr(args, "_grpc_metadata", None)
    if metadata is None:
        metadata = actions._parse_metadata_items(getattr(args, "meta", None))
    invoke_request_json = (
        actions._parse_json_payload_source(getattr(args, "data", None)) if invoke_path is not None else None
    )
    return {
        "analyze": bool(getattr(args, "analyze", False) or invoke_path is not None or openapi_path),
        "schema_descriptor_bytes": actions._load_explicit_descriptor_bytes(
            getattr(args, "proto", None),
            getattr(args, "proto_path", None),
            getattr(args, "protoset", None),
        ),
        "invoke_path": invoke_path,
        "invoke_request_json": invoke_request_json,
        "metadata": metadata,
    }


def build_grpc_spec(args: Any) -> ModuleAuditSpec:
    options = getattr(args, "_grpc_host_stage_options", None)
    if options is None:
        options = _build_grpc_host_stage_options(args)
    resolved_host_stage = getattr(actions, _PRODUCTION_HOST_STAGE.__name__, _PRODUCTION_HOST_STAGE)
    use_lifecycle_hooks = (
        actions.host_stage is _PRODUCTION_HOST_STAGE
        and resolved_host_stage is _PRODUCTION_HOST_STAGE
        and actions._audit_grpc_host is _PRODUCTION_AUDIT_HOST
    )

    def _detect(ctx: Any) -> AuditRecord:
        return AuditRecord.from_mapping(actions.detect_grpc(ctx, options), module="grpc", service="grpc")

    def _auth(ctx: Any, record: Any) -> AuditRecord:
        return AuditRecord.from_mapping(
            actions.authenticate_grpc(ctx, record, options),
            module="grpc",
            service="grpc",
        )

    def _data(ctx: Any, record: Any) -> AuditRecord:
        return AuditRecord.from_mapping(
            actions.collect_grpc_data(ctx, record, options),
            module="grpc",
            service="grpc",
        )

    return ModuleAuditSpec(
        module="grpc",
        label="GRPC",
        default_port=_DEFAULT_PORT,
        host_stage=actions.host_stage,
        host_stage_options=options,
        detect=_detect if use_lifecycle_hooks else None,
        auth=_auth if use_lifecycle_hooks else None,
        data=_data if use_lifecycle_hooks else None,
        lifecycle_state_factory=(lambda _ctx: actions.GrpcLifecycleState()) if use_lifecycle_hooks else None,
        lifecycle_state_close=(lambda state: state.close()) if use_lifecycle_hooks else None,
        deep_gate=actions.grpc_deep_gate,
        render_module=render,
        colorize=render._render_colored_grpc_line,
    )


def run_grpc_stage(args: Any, logger: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    console = Console(debug=cfg.debug)
    if hasattr(console, "set_structured_output"):
        console.set_structured_output(cfg.output_format == "json")
    if getattr(args, "token", None):
        args.username = None
        args.password = None
    validation_rc = policy.validate_args(args, console)
    if validation_rc is not None:
        return int(validation_rc)
    try:
        args._grpc_host_stage_options = _build_grpc_host_stage_options(args)
    except (OSError, RuntimeError, ValueError) as exc:
        console.error(str(exc))
        return 2
    try:
        plan = build_grpc_plan(args)
    except ValueError as exc:
        console.error(str(exc))
        return 2
    if cfg.debug and not getattr(args, "debug_emit", None):
        args.debug_emit = console.info
    if cfg.debug:
        suffix = f" format={cfg.output_format}"
        if cfg.output:
            suffix += f" output={args.output}"
        console.info("grpc audit started:" + suffix)
    openapi_path = str(getattr(args, "openapi", "") or "").strip()
    descriptor_bytes = list(args._grpc_host_stage_options.get("schema_descriptor_bytes") or [])
    descriptor_targets: dict[str, bool] = {}
    previous_record_callback = getattr(args, "_record_callback", None)

    def _target_label(record: dict[str, Any]) -> str | None:
        host = str(record.get("host") or "").strip()
        if not host:
            return None
        if ":" in host and not (host.startswith("[") and host.endswith("]")):
            host = f"[{host}]"
        port = record.get("port")
        return f"{host}:{port}" if port is not None else host

    def _collect_openapi_descriptor(record: dict[str, Any]) -> None:
        raw_items = record.get("descriptor_protos_b64")
        decoded_items: list[bytes] = []
        if isinstance(raw_items, list):
            for item in raw_items:
                if not isinstance(item, str) or not item.strip():
                    continue
                try:
                    decoded_items.append(base64.b64decode(item, validate=True))
                except (ValueError, OSError):
                    continue
        valid_items = actions._dedup_descriptor_bytes(decoded_items)
        # Preserve parse errors and conflicting same-name variants for the
        # OpenAPI diagnostics.  Exact duplicates are removed later by the
        # document generator.
        descriptor_bytes.extend(decoded_items)
        obtained = bool(valid_items)
        target = _target_label(record)
        if target is not None:
            descriptor_targets[target] = descriptor_targets.get(target, False) or obtained

    def _capture_openapi_descriptor(record: dict[str, Any]) -> None:
        if callable(previous_record_callback):
            previous_record_callback(record)
        _collect_openapi_descriptor(record)

    try:
        runner = AuditCommandRunner(args=args, spec=build_grpc_spec(args), logger=logger, console=console)
        if openapi_path:
            with install_record_callback(args, _capture_openapi_descriptor):
                result = runner.run_plan(plan)
        else:
            result = runner.run_plan(plan)
    except ValueError as exc:
        console.error(str(exc))
        return 2
    except OSError as exc:
        console.error(f"failed to process grpc output: {exc}")
        return 2
    if openapi_path:
        for record in result.records:
            _collect_openapi_descriptor(record)
        # Keep every valid variant until document generation.  The generator
        # performs normal deduplication itself and also needs the original
        # variants to report same-name descriptor conflicts accurately.
        unique_descriptor_bytes = actions._dedup_descriptor_bytes(descriptor_bytes)
        missing_targets = sorted(target for target, obtained in descriptor_targets.items() if not obtained)
        if not unique_descriptor_bytes:
            console.warn("grpc OpenAPI export contains no operations: descriptors were not obtained from any target")
        elif missing_targets:
            console.warn(
                "grpc OpenAPI export is partial: descriptors were not obtained for targets: "
                + ", ".join(missing_targets)
            )
        try:
            if descriptor_targets:
                actions._write_openapi_document(
                    openapi_path,
                    descriptor_bytes,
                    descriptor_targets=descriptor_targets,
                )
            else:
                actions._write_openapi_document(openapi_path, descriptor_bytes)
        except OSError as exc:
            console.error(f"failed to write grpc OpenAPI artifact: {exc}")
            return 2
    if cfg.debug and result.detected_count == 0 and hasattr(console, "warn"):
        console.warn("all grpc targets are unreachable")
    return 0


__all__ = [
    "_build_grpc_host_stage_options",
    "build_grpc_plan",
    "build_grpc_spec",
    "run_grpc_stage",
]
