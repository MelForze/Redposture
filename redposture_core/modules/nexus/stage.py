"""Nexus audit entrypoint backed by the shared OCI client."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from ...audit_config import AuditConfig
from ...audit_models import AuditRecord
from ...console import Console
from ...stage_runtime import run_basic_host_audit
from ..registry import policy as registry_policy
from ..registry.stage import build_registry_plan, build_registry_spec
from . import execution


def build_nexus_plan(args: Any):
    return build_registry_plan(args, product="nexus")


def build_nexus_spec(args: Any):
    spec = build_registry_spec(args, product="nexus")
    if getattr(args, "execute", None) is None or spec.data is None:
        return spec
    data = spec.data

    def _data(ctx: Any, record: AuditRecord) -> AuditRecord:
        current = data(ctx, record)
        return AuditRecord.from_mapping(
            execution.collect(ctx, current.to_dict(), ctx.lifecycle_state), module="nexus", service="nexus"
        )

    return replace(spec, data=_data)


def run_nexus_stage(args: Any, logger: Any) -> int:
    """Run Nexus through the Nexus-specific spec so ``--execute`` is wired."""

    cfg = AuditConfig.from_namespace(args)
    console = Console(debug=cfg.debug)
    args._registry_console = console
    return run_basic_host_audit(
        args,
        logger,
        console=console,
        label="NEXUS",
        validate=lambda value, output: registry_policy.validate_args(value, output, product="nexus"),
        build_plan=build_nexus_plan,
        build_spec=build_nexus_spec,
    )


__all__ = ["build_nexus_plan", "build_nexus_spec", "run_nexus_stage"]
