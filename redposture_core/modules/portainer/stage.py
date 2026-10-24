"""Portainer audit lifecycle and command boundary."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from ...audit_config import AuditConfig
from ...audit_models import AuditRecord
from ...console import Console
from ...stage_runtime import (
    AuditCredentialRun,
    ModuleAuditSpec,
    build_basic_audit_plan,
    merge_audit_credential_runs,
    run_basic_host_audit,
)
from ...web_panels import default_pairs
from . import actions, execution, policy, render


def build_portainer_plan(args: Any) -> Any:
    plan = build_basic_audit_plan(args, default_port=9443, default_ports=(9443, 9000))
    if getattr(args, "port", None) is None and not getattr(args, "ports", None) and plan.target_plan is not None:
        plan = replace(plan, target_plan=plan.target_plan.with_scheme_default_ports({"http": 80, "https": 443}))
    defaults = (
        tuple(
            AuditCredentialRun(username=user, password=password, source="default")
            for user, password in default_pairs("portainer")
        )
        if getattr(args, "defcreds", False)
        else ()
    )
    return replace(plan, credential_runs=merge_audit_credential_runs(plan.credential_runs, defaults))


def build_portainer_spec(args: Any) -> ModuleAuditSpec:
    def detect(ctx: Any) -> AuditRecord:
        return AuditRecord.from_mapping(actions.detect_record(ctx), module="portainer", service="portainer")

    def auth(ctx: Any, record: AuditRecord) -> AuditRecord:
        return AuditRecord.from_mapping(
            actions.auth_record(ctx, record.to_dict()), module="portainer", service="portainer"
        )

    def data(ctx: Any, record: AuditRecord) -> AuditRecord:
        payload = execution.collect(ctx, record.to_dict(), ctx.lifecycle_state)
        if getattr(ctx.args, "execute", None) is not None and not payload.get("execute_verified"):
            return AuditRecord.from_mapping(payload, module="portainer", service="portainer")
        if getattr(ctx.args, "execute", None) is not None and not any(
            getattr(ctx.args, key, False)
            for key in ("endpoints", "containers", "images", "networks", "volumes", "system", "discover")
        ):
            return AuditRecord.from_mapping(payload, module="portainer", service="portainer")
        return AuditRecord.from_mapping(actions.data_record(ctx, payload), module="portainer", service="portainer")

    spec = ModuleAuditSpec(
        module="portainer",
        label="PORTAINER",
        default_port=9443,
        detect=detect,
        auth=auth,
        data=data,
        lifecycle_state_factory=actions.lifecycle_state_factory,
        render=render.render_record,
        colorize=render.colorize,
        is_detected=lambda record: record.extra.get("is_portainer") is True,
        credential_gate=lambda credential, record: (
            record.extra.get("provided_credentials_ok") is True,
            "Portainer identity verifier",
        ),
        record_all_credential_attempts=True,
        continue_after_credential_success=bool(getattr(args, "defcreds", False)),
        continue_after_credential_error=bool(getattr(args, "defcreds", False)),
        credential_attempt_detail_fields=("credential_state", "token_provided"),
        structured_output_redact_fields=("session_token", "session_api_key", "portainer_metadata"),
    )

    if actions.detect_record is not actions._SYNC_DETECT_RECORD:
        return spec
    original = actions.detect_record

    async def detect_async(ctx: Any, http: Any) -> AuditRecord:
        from ...clients.async_http_detect import AsyncHttpFallback
        from ...web_panels import detect_panel_async

        if actions.detect_record is not original:
            raise AsyncHttpFallback("Portainer detector override")
        panel = await detect_panel_async("portainer", ctx, http, report_failure=True)
        return AuditRecord.from_mapping(actions.panel_record(ctx, panel), module="portainer", service="portainer")

    return replace(spec, detect_async=detect_async, async_detect_sync_hook=spec.detect)


def run_portainer_stage(args: Any, logger: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    return run_basic_host_audit(
        args,
        logger,
        console=Console(debug=cfg.debug),
        label="PORTAINER",
        validate=policy.validate_args,
        build_plan=build_portainer_plan,
        build_spec=build_portainer_spec,
    )


__all__ = ["build_portainer_plan", "build_portainer_spec", "run_portainer_stage"]
