"""Spark audit on the shared target, HTTP lifecycle and output runner."""

from dataclasses import replace
from typing import Any

from ...audit_config import AuditConfig
from ...audit_models import AuditRecord
from ...console import Console
from ...stage_runtime import build_basic_audit_plan, run_basic_host_audit
from ..token_api import build_spec
from . import actions, execution, policy, render
from .types import DEFAULT_PORTS


def build_spark_plan(args: Any) -> Any:
    plan = build_basic_audit_plan(args, default_port=8080, default_ports=DEFAULT_PORTS)
    if plan.target_plan is not None and getattr(args, "port", None) is None and not getattr(args, "ports", None):
        plan = replace(plan, target_plan=plan.target_plan.with_scheme_default_ports({"http": 80, "https": 443}))
    # Spark's REST/UI APIs have no portable pair credential verifier. Do not
    # manufacture credential verdicts for proxy or standalone deployment ACLs.
    return replace(plan, credential_runs=())


def build_spark_spec(args: Any) -> Any:
    spec = build_spec(args, "spark", 8080, actions, render)
    if getattr(args, "execute", None) is None or spec.data is None:
        return spec
    data = spec.data

    def _data(ctx: Any, record: AuditRecord) -> AuditRecord:
        current = data(ctx, record)
        return AuditRecord.from_mapping(
            execution.collect(ctx, current.to_dict(), ctx.lifecycle_state), module="spark", service="spark"
        )

    return replace(spec, data=_data)


def run_spark_stage(args: Any, logger: Any) -> int:
    return run_basic_host_audit(
        args,
        logger,
        console=Console(debug=AuditConfig.from_namespace(args).debug),
        label="SPARK",
        validate=policy.validate_args,
        build_plan=build_spark_plan,
        build_spec=build_spark_spec,
    )
