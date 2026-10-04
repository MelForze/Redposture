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
    AuditCredentialRun,
    ModuleAuditSpec,
    build_basic_audit_plan,
    merge_audit_credential_runs,
    run_basic_host_audit,
)
from . import actions, policy, product_render, render

_DEFAULT_PORT = 5000
_DEFAULT_PORTS: tuple[int, ...] | None = (5000, 15000, 25000)
_PRODUCTION_HOST_STAGE = actions.host_stage
_PRODUCTION_AUDIT_HOST = actions._audit_registry_host
_PORTS_BY_PRODUCT: dict[str, tuple[int, ...]] = {
    "docker-registry": (5000, 15000, 25000),
    "harbor": (80, 443),
    "nexus": (8081,),
}
_WEAK_BASIC_PAIRS: tuple[tuple[str, str], ...] = (
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "changeme"),
    ("admin", "admin123"),
    ("admin", "123456"),
    ("admin", "12345678"),
    ("root", "root"),
    ("root", "password"),
    ("root", "admin"),
    ("root", "changeme"),
    ("user", "user"),
    ("user", "password"),
    ("test", "test"),
    ("guest", "guest"),
    ("dev", "dev"),
    ("service", "service"),
)
_PRODUCT_BASIC_PAIRS: dict[str, tuple[tuple[str, str], ...]] = {
    "docker-registry": (
        ("registry", "registry"),
        ("registry", "password"),
        ("registry", "admin"),
        ("registry", "changeme"),
        ("registry", "registry123"),
        ("docker", "docker"),
        ("docker", "password"),
    ),
    "harbor": (
        ("admin", "Harbor12345"),
        ("admin", "harbor"),
        ("admin", "harbor123"),
        ("admin", "Harbor123"),
        ("harbor", "harbor"),
        ("harbor", "password"),
    ),
    "nexus": (
        ("admin", "admin123"),
        ("nexus", "nexus"),
        ("admin", "nexus"),
        ("admin", "nexus123"),
        ("admin", "sonatype"),
        ("nexus", "password"),
        ("nexus", "admin"),
    ),
}


def build_registry_plan(args: Any, *, product: str = "registry") -> AuditCommandPlan:
    ports = _PORTS_BY_PRODUCT.get(product) or (_DEFAULT_PORT,)
    plan = build_basic_audit_plan(args, default_port=ports[0], default_ports=ports)
    explicit_port = getattr(args, "port", None) is not None or bool(str(getattr(args, "ports", "") or "").strip())
    if not explicit_port and plan.target_plan is not None:
        plan = replace(plan, target_plan=plan.target_plan.with_scheme_default_ports({"http": 80, "https": 443}))
    if bool(getattr(args, "defcreds", False)):
        pairs = (*_PRODUCT_BASIC_PAIRS.get(product, ()), *_WEAK_BASIC_PAIRS)
        defaults = tuple(
            AuditCredentialRun(username=user, password=password, source="default") for user, password in pairs
        )
        plan = replace(plan, credential_runs=merge_audit_credential_runs(plan.credential_runs, defaults))
    return plan


def build_registry_spec(args: Any, *, product: str = "registry") -> ModuleAuditSpec:
    enum_cve = bool(getattr(args, "enum_cve", False))
    options = {
        "docker": product == "docker-registry" or bool(getattr(args, "docker", False)),
        "show_images": bool(getattr(args, "images", False)),
        "show_tags": bool(getattr(args, "show_tags", False)),
        "repository": str(getattr(args, "repository", "") or "").strip() or None,
        "tag": str(getattr(args, "tag", "") or "").strip() or None,
        "metadata": bool(getattr(args, "metadata", False)),
        "harbor": product == "harbor" or bool(getattr(args, "harbor", False)) or enum_cve,
        "gitlab": product == "gitlab" or bool(getattr(args, "gitlab", False)) or enum_cve,
        "nexus": product == "nexus" or bool(getattr(args, "nexus", False)) or enum_cve,
        "product": product,
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

    def _state_factory(ctx: Any) -> actions.RegistryLifecycleState:
        return actions.registry_lifecycle_state_factory(ctx)

    def _detect(ctx: Any) -> AuditRecord:
        with http_target_context(
            ctx.target,
            route_state=getattr(ctx, "lifecycle_state", None),
            api_prefixes=("/v2", "/service/rest", "/api/v2.0", "/jwt/auth"),
        ):
            result = actions.detect_registry(ctx, options)
        return AuditRecord.from_mapping(result, module=product, service=product)

    def _auth(ctx: Any, record: Any) -> AuditRecord:
        with http_target_context(
            ctx.target,
            route_state=getattr(ctx, "lifecycle_state", None),
            api_prefixes=("/v2", "/service/rest", "/api/v2.0", "/jwt/auth"),
        ):
            result = actions.authenticate_registry(ctx, record, options)
        return AuditRecord.from_mapping(result, module=product, service=product)

    def _data(ctx: Any, record: Any) -> AuditRecord:
        with http_target_context(
            ctx.target,
            route_state=getattr(ctx, "lifecycle_state", None),
            api_prefixes=("/v2", "/service/rest", "/api/v2.0", "/jwt/auth"),
        ):
            result = actions.collect_registry_data(ctx, record, options)
        return AuditRecord.from_mapping(result, module=product, service=product)

    return ModuleAuditSpec(
        module=product,
        label=product.upper(),
        default_port=(_PORTS_BY_PRODUCT.get(product) or (_DEFAULT_PORT,))[0],
        host_stage=actions.host_stage,
        detect=_detect if use_lifecycle_hooks else None,
        auth=_auth if use_lifecycle_hooks else None,
        data=_data if use_lifecycle_hooks else None,
        lifecycle_state_factory=_state_factory if use_lifecycle_hooks else None,
        lifecycle_state_close=(lambda state: state.close()) if use_lifecycle_hooks else None,
        render_module=render if product == "registry" else product_render,
        defer_detect_output_until_auth=product == "nexus",
        structured_output_redact_fields=("provided_password",),
        colorize=(render if product == "registry" else product_render)._render_colored_registry_line,
        is_detected=lambda record: (
            record.extra.get("is_registry") is True
            and (
                (
                    product == "docker-registry"
                    and not any(record.extra.get(f"is_{vendor}") is True for vendor in ("harbor", "nexus", "gitlab"))
                )
                or (product in {"harbor", "nexus", "gitlab"} and record.extra.get(f"is_{product}") is True)
                or product == "registry"
            )
        ),
        # E3 opt-in: Docker Registry anon-open (public registries, no auth
        # required) is confirmed by the /v2/ probe returning 200.
        keep_anonymous_open_no_auth=product == "docker-registry",
        skip_credentials_without_verifier=bool(getattr(args, "defcreds", False)),
        continue_after_credential_error=bool(getattr(args, "defcreds", False)),
        continue_after_credential_success=bool(getattr(args, "defcreds", False)),
    )


def run_registry_stage(args: Any, logger: Any, *, product: str = "registry") -> int:
    cfg = AuditConfig.from_namespace(args)
    console = Console(debug=cfg.debug)
    args._registry_console = console
    return run_basic_host_audit(
        args,
        logger,
        console=console,
        label=product.upper(),
        validate=lambda value, output: policy.validate_args(value, output, product=product),
        build_plan=lambda value: build_registry_plan(value, product=product),
        build_spec=lambda value: build_registry_spec(value, product=product),
    )


def run_docker_registry_stage(args: Any, logger: Any) -> int:
    return run_registry_stage(args, logger, product="docker-registry")


def run_harbor_stage(args: Any, logger: Any) -> int:
    return run_registry_stage(args, logger, product="harbor")


def run_nexus_stage(args: Any, logger: Any) -> int:
    return run_registry_stage(args, logger, product="nexus")


__all__ = [
    "build_registry_plan",
    "build_registry_spec",
    "run_registry_stage",
    "run_docker_registry_stage",
    "run_harbor_stage",
    "run_nexus_stage",
]
