"""Runtime entrypoint for the registry audit module."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from ...audit_config import AuditConfig
from ...audit_models import AuditRecord
from ...clients.http_api import http_target_context
from ...console import Console
from ...stage_runtime import (
    AuditCommandPlan,
    ModuleAuditSpec,
    build_basic_audit_plan,
    run_basic_host_audit,
)
from . import actions, policy, render

_DEFAULT_PORT = 5000
_DEFAULT_PORTS: tuple[int, ...] | None = (5000, 15000)
_PRODUCTION_HOST_STAGE = actions.host_stage
_PRODUCTION_AUDIT_HOST = actions._audit_registry_host


def build_registry_plan(args: Any) -> AuditCommandPlan:
    plan = build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)
    explicit_port = getattr(args, "port", None) is not None or bool(str(getattr(args, "ports", "") or "").strip())
    if not explicit_port and plan.target_plan is not None:
        plan = replace(plan, target_plan=plan.target_plan.with_scheme_default_ports({"http": 80, "https": 443}))
    return plan


def build_registry_spec(args: Any) -> ModuleAuditSpec:
    options = {
        "docker": bool(getattr(args, "docker", False)),
        "show_images": bool(getattr(args, "images", False)),
        "show_tags": bool(getattr(args, "show_tags", False)),
        "repository": str(getattr(args, "repository", "") or "").strip() or None,
        "tag": str(getattr(args, "tag", "") or "").strip() or None,
        "metadata": bool(getattr(args, "metadata", False)),
        "harbor": bool(getattr(args, "harbor", False)),
        "gitlab": bool(getattr(args, "gitlab", False)),
        "nexus": bool(getattr(args, "nexus", False)),
        "assets": bool(getattr(args, "assets", False)),
        "inspect": bool(getattr(args, "inspect", False)),
        "image": str(getattr(args, "image", "") or "").strip() or None,
        "download": bool(getattr(args, "download", False)),
        "download_dir": str(getattr(args, "download_dir", ".") or "."),
        "console": getattr(args, "_registry_console", None) or Console(debug=bool(getattr(args, "debug", False))),
    }
    resolved_host_stage = getattr(actions, _PRODUCTION_HOST_STAGE.__name__, _PRODUCTION_HOST_STAGE)
    use_lifecycle_hooks = (
        actions.host_stage is _PRODUCTION_HOST_STAGE
        and resolved_host_stage is _PRODUCTION_HOST_STAGE
        and actions._audit_registry_host is _PRODUCTION_AUDIT_HOST
    )

    def _state_factory(_ctx: Any) -> actions.RegistryLifecycleState:
        return actions.RegistryLifecycleState()

    def _detect(ctx: Any) -> AuditRecord:
        with http_target_context(ctx.target, api_prefixes=("/v2", "/service/rest", "/api/v2.0", "/jwt/auth")):
            result = actions.detect_registry(ctx, options)
        return AuditRecord.from_mapping(result, module="registry", service="registry")

    def _auth(ctx: Any, record: Any) -> AuditRecord:
        with http_target_context(ctx.target, api_prefixes=("/v2", "/service/rest", "/api/v2.0", "/jwt/auth")):
            result = actions.authenticate_registry(ctx, record, options)
        return AuditRecord.from_mapping(result, module="registry", service="registry")

    def _data(ctx: Any, record: Any) -> AuditRecord:
        with http_target_context(ctx.target, api_prefixes=("/v2", "/service/rest", "/api/v2.0", "/jwt/auth")):
            result = actions.collect_registry_data(ctx, record, options)
        return AuditRecord.from_mapping(result, module="registry", service="registry")

    return ModuleAuditSpec(
        module="registry",
        label="REGISTRY",
        default_port=_DEFAULT_PORT,
        host_stage=actions.host_stage,
        detect=_detect if use_lifecycle_hooks else None,
        auth=_auth if use_lifecycle_hooks else None,
        data=_data if use_lifecycle_hooks else None,
        lifecycle_state_factory=_state_factory if use_lifecycle_hooks else None,
        render_module=render,
        colorize=render._render_colored_registry_line,
        # E3 opt-in: Docker Registry anon-open (public registries, no auth
        # required) is confirmed by the /v2/ probe returning 200.
        keep_anonymous_open_no_auth=True,
    )


def run_registry_stage(args: Any, logger: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    console = Console(debug=cfg.debug)
    args._registry_console = console
    return run_basic_host_audit(
        args,
        logger,
        console=console,
        label="REGISTRY",
        validate=policy.validate_args,
        build_plan=build_registry_plan,
        build_spec=build_registry_spec,
    )


__all__ = ["build_registry_plan", "build_registry_spec", "run_registry_stage"]
