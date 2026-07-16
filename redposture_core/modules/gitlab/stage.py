"""Runtime entrypoint for the gitlab audit module."""

from __future__ import annotations

import os
from dataclasses import replace
from typing import Any

from ...audit_config import AuditConfig
from ...audit_models import AuditRecord
from ...console import Console
from ...stage_runtime import (
    AuditCommandPlan,
    ModuleAuditSpec,
    build_basic_audit_plan,
    run_basic_host_audit,
)
from . import actions, policy, render

_DEFAULT_PORT = 80
_DEFAULT_PORTS = None
_PRODUCTION_HOST_STAGE = actions.host_stage
_PRODUCTION_AUDIT_HOST = actions._audit_gitlab_host


def build_gitlab_plan(args: Any) -> AuditCommandPlan:
    explicit_port = getattr(args, "port", None) is not None or bool(str(getattr(args, "ports", "") or "").strip())
    default_port = 443 if bool(getattr(args, "https", False)) else _DEFAULT_PORT
    plan = build_basic_audit_plan(args, default_port=default_port, default_ports=_DEFAULT_PORTS)
    if not explicit_port and plan.target_plan is not None:
        plan = replace(
            plan,
            target_plan=plan.target_plan.with_scheme_default_ports(
                {
                    "http": 80,
                    "https": 443,
                }
            ),
        )
    return plan


def _build_gitlab_host_stage_options(args: Any) -> dict[str, Any]:
    clone_dir = str(getattr(args, "clone_dir", actions._DEFAULT_CLONE_DIR) or actions._DEFAULT_CLONE_DIR).strip()
    clone_dir = clone_dir or actions._DEFAULT_CLONE_DIR
    project_values = getattr(args, "project", None)
    if project_values is None:
        project_values = getattr(args, "project_filters", None)
    return {
        "project_filters": actions._normalize_project_filters(project_values),
        "clone": bool(getattr(args, "clone", False)),
        "clone_dir": os.path.abspath(os.path.expanduser(clone_dir)),
    }


def build_gitlab_spec(args: Any) -> ModuleAuditSpec:
    options = _build_gitlab_host_stage_options(args)
    resolved_host_stage = getattr(actions, _PRODUCTION_HOST_STAGE.__name__, _PRODUCTION_HOST_STAGE)
    use_lifecycle_hooks = (
        actions.host_stage is _PRODUCTION_HOST_STAGE
        and resolved_host_stage is _PRODUCTION_HOST_STAGE
        and actions._audit_gitlab_host is _PRODUCTION_AUDIT_HOST
    )

    def _detect(ctx: Any) -> AuditRecord:
        return AuditRecord.from_mapping(actions.detect_gitlab(ctx, options), module="gitlab", service="gitlab")

    def _auth(ctx: Any, record: Any) -> AuditRecord:
        return AuditRecord.from_mapping(
            actions.authenticate_gitlab(ctx, record, options),
            module="gitlab",
            service="gitlab",
        )

    def _data(ctx: Any, record: Any) -> AuditRecord:
        return AuditRecord.from_mapping(
            actions.collect_gitlab_data(ctx, record, options),
            module="gitlab",
            service="gitlab",
        )

    return ModuleAuditSpec(
        module="gitlab",
        label="GITLAB",
        default_port=_DEFAULT_PORT,
        host_stage=actions.host_stage,
        host_stage_options=options,
        detect=_detect if use_lifecycle_hooks else None,
        auth=_auth if use_lifecycle_hooks else None,
        data=_data if use_lifecycle_hooks else None,
        lifecycle_state_factory=(lambda _ctx: actions.GitLabLifecycleState()) if use_lifecycle_hooks else None,
        deep_gate=(
            lambda record: (
                str(record.status or "") in {"detected", "valid_credentials", "invalid_credentials"},
                f"status={record.status}",
            )
        )
        if use_lifecycle_hooks
        else None,
        render_module=render,
        colorize=render._render_colored_gitlab_line,
    )


def run_gitlab_stage(args: Any, logger: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    console = Console(debug=cfg.debug)
    return run_basic_host_audit(
        args,
        logger,
        console=console,
        label="GITLAB",
        validate=policy.validate_args,
        build_plan=build_gitlab_plan,
        build_spec=build_gitlab_spec,
    )


__all__ = [
    "_build_gitlab_host_stage_options",
    "build_gitlab_plan",
    "build_gitlab_spec",
    "run_gitlab_stage",
]
