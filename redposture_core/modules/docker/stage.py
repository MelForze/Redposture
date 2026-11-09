"""Runtime entrypoint for the docker audit module."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from ...audit_config import AuditConfig
from ...audit_models import AuditRecord
from ...console import Console
from ...stage_runtime import (
    AuditCommandPlan,
    ModuleAuditSpec,
    _invoke_host_stage,
    build_basic_audit_plan,
    run_basic_host_audit,
)
from . import actions, policy, render

_DEFAULT_PORT = 2375
_DEFAULT_PORTS: tuple[int, ...] | None = (2375, 2376, 4243, 12375, 12376)


def build_docker_plan(args: Any) -> AuditCommandPlan:
    plan = build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)
    explicit_port = getattr(args, "port", None) is not None or bool(str(getattr(args, "ports", "") or "").strip())
    if not explicit_port and plan.target_plan is not None:
        plan = replace(plan, target_plan=plan.target_plan.with_scheme_default_ports({"http": 80, "https": 443}))
    return plan


def build_docker_spec(args: Any) -> ModuleAuditSpec:
    def data(ctx: Any, _prior: AuditRecord) -> AuditRecord:
        payload = _invoke_host_stage(actions.host_stage, module="docker", ctx=ctx, run_deep_checks=True).to_dict()
        ready = getattr(ctx, "emit_ready_inventory", None)
        if callable(ready):
            ready(payload)
        from .discover import discover

        payload["content_discovery"] = discover(ctx, payload)
        return AuditRecord.from_mapping(payload, module="docker", service="docker")

    spec = ModuleAuditSpec(
        module="docker",
        label="DOCKER",
        default_port=_DEFAULT_PORT,
        host_stage=actions.host_stage,
        render_module=render,
        colorize=render._render_colored_docker_line,
        is_detected=lambda record: record.extra.get("is_docker") is True,
        # E3 opt-in: Docker Engine anon-open API needs no credentials.
        keep_anonymous_open_no_auth=True,
        data=data if bool(getattr(args, "discover", False)) else None,
    )

    from .async_detect import bind

    return bind(spec)


def run_docker_stage(args: Any, logger: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    console = Console(debug=cfg.debug)
    return run_basic_host_audit(
        args,
        logger,
        console=console,
        label="DOCKER",
        validate=policy.validate_args,
        build_plan=build_docker_plan,
        build_spec=build_docker_spec,
    )


__all__ = ["build_docker_plan", "build_docker_spec", "run_docker_stage"]
