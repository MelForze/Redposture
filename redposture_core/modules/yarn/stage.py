"""Hadoop YARN ResourceManager audit lifecycle."""

from dataclasses import replace
from typing import Any

from ...audit_config import AuditConfig
from ...audit_models import AuditRecord
from ...clients.http_api import http_target_context
from ...console import Console
from ...detection_steps import with_async_http_detection
from ...stage_runtime import run_basic_host_audit
from ..token_api import build_plan, build_spec
from . import actions, execution, policy, render


def build_yarn_plan(args: Any) -> Any:
    return build_plan(args, "yarn", 8088)


def build_yarn_spec(args: Any) -> Any:
    spec = build_spec(args, "yarn", 8088, actions, render)

    def phase(ctx: Any, action: Any, record: AuditRecord | None = None) -> AuditRecord:
        with http_target_context(ctx.target, route_state=ctx.lifecycle_state, api_prefixes=("/ws", "/cluster")):
            value = action(ctx) if record is None else action(ctx, record.to_dict())
        return AuditRecord.from_mapping(value, module="yarn", service="yarn")

    spec = replace(
        spec,
        detect=lambda ctx: phase(ctx, actions.detect_record),
        auth=lambda ctx, rec: phase(ctx, actions.auth_record, rec),
        data=lambda ctx, rec: phase(ctx, _data_record, rec),
        # An apps-list denial says nothing about nodes, metrics or the
        # explicitly requested allocation endpoint; report each independently.
        deep_gate=lambda rec: (rec.extra.get("is_yarn") is True, "confirmed ResourceManager"),
    )

    return with_async_http_detection(spec, actions, api_prefixes=("/ws", "/cluster"))


def _data_record(ctx: Any, record: dict[str, Any]) -> dict[str, Any]:
    current = actions.data_record(ctx, record)
    if getattr(ctx.args, "execute", None) is None:
        return current
    return execution.collect(ctx, current, ctx.lifecycle_state)


def run_yarn_stage(args: Any, logger: Any) -> int:
    return run_basic_host_audit(
        args,
        logger,
        console=Console(debug=AuditConfig.from_namespace(args).debug),
        label="YARN",
        validate=policy.validate_args,
        build_plan=build_yarn_plan,
        build_spec=build_yarn_spec,
    )
