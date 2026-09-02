"""Runtime entrypoint for the qdrant audit module."""

from __future__ import annotations

import urllib.parse
from dataclasses import replace
from typing import Any

from ...audit_config import AuditConfig
from ...audit_models import AuditRecord
from ...clients.http_api import http_target_context
from ...console import Console
from ...show_limits import dump_flag_enabled, dump_flag_limit
from ...stage_runtime import (
    AuditCommandPlan,
    AuditCommandRunner,
    ModuleAuditSpec,
    build_basic_audit_plan,
    command_result_exit_code,
)
from . import actions, policy, render

_DEFAULT_PORT = 6333
_DEFAULT_PORTS: tuple[int, ...] = (6333, 16333, 26333)
_PRODUCTION_HOST_STAGE = actions.host_stage
_PRODUCTION_AUDIT_HOST = actions._audit_qdrant_host


def _rewrite_ssrf_urls_port(urls: list[str], port: int) -> list[str]:
    """Point every callback URL at the port the local listener actually bound."""
    if port <= 0:
        return list(urls)
    rewritten_urls: list[str] = []
    for raw_url in urls:
        parsed = urllib.parse.urlsplit(str(raw_url))
        host = str(parsed.hostname or "")
        if not host:
            continue
        authority = f"[{host}]" if ":" in host else host
        rewritten_urls.append(
            urllib.parse.urlunsplit(
                (
                    parsed.scheme,
                    f"{authority}:{port}",
                    parsed.path,
                    parsed.query,
                    "",
                )
            )
        )
    return rewritten_urls


def build_qdrant_plan(args: Any) -> AuditCommandPlan:
    plan = build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)
    explicit_port = getattr(args, "port", None) is not None or bool(str(getattr(args, "ports", "") or "").strip())
    if not explicit_port and plan.target_plan is not None:
        plan = replace(plan, target_plan=plan.target_plan.with_scheme_default_ports({"http": 80, "https": 443}))
    return plan


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
        with http_target_context(ctx.target, api_prefixes=("/collections", "/service/info")):
            result = actions.detect_qdrant(ctx, options)
        return AuditRecord.from_mapping(result, module="qdrant", service="qdrant")

    def _auth(ctx: Any, record: Any) -> AuditRecord:
        with http_target_context(ctx.target, api_prefixes=("/collections", "/service/info")):
            result = actions.authenticate_qdrant(ctx, record, options)
        return AuditRecord.from_mapping(result, module="qdrant", service="qdrant")

    def _data(ctx: Any, record: Any) -> AuditRecord:
        with http_target_context(ctx.target, api_prefixes=("/collections", "/service/info")):
            result = actions.collect_qdrant_data(ctx, record, options)
        return AuditRecord.from_mapping(result, module="qdrant", service="qdrant")

    return ModuleAuditSpec(
        module="qdrant",
        label="QDRANT",
        default_port=_DEFAULT_PORT,
        host_stage=actions.host_stage,
        detect=_detect if use_lifecycle_hooks else None,
        auth=_auth if use_lifecycle_hooks else None,
        data=_data if use_lifecycle_hooks else None,
        lifecycle_state_factory=actions.qdrant_lifecycle_state_factory if use_lifecycle_hooks else None,
        lifecycle_state_close=(lambda state: state.close()) if use_lifecycle_hooks else None,
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
            actual_port = int(listener.get("port") or 0)
            if actual_port > 0:
                args.ssrf_urls = _rewrite_ssrf_urls_port(
                    list(getattr(args, "ssrf_urls", None) or []),
                    actual_port,
                )
            console.info(f"local SSRF listener started on 127.0.0.1:{listener.get('port')}")
        else:
            console.warn(f"local SSRF listener failed: {listener.get('error') or 'unknown'}")
    args.ssrf_capture = listener
    try:
        runner = AuditCommandRunner(args=args, spec=build_qdrant_spec(args), logger=logger, console=console)
        try:
            result = runner.run_plan(plan)
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
    return command_result_exit_code(result)


__all__ = ["build_qdrant_plan", "build_qdrant_spec", "run_qdrant_stage"]
