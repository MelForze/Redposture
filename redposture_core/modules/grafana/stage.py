"""Runtime entrypoint for the grafana audit module."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from ...audit_config import AuditConfig
from ...audit_models import AuditRecord
from ...console import Console
from ...stage_runtime import (
    AuditCommandPlan,
    AuditCredentialRun,
    ModuleAuditSpec,
    build_basic_audit_plan,
    merge_audit_credential_runs,
    run_basic_host_audit,
)
from . import actions, policy, render

_DEFAULT_PORT = 3000
_DEFAULT_PORTS = None
_PRODUCTION_HOST_STAGE = actions.host_stage
_PRODUCTION_AUDIT_HOST = actions._audit_grafana_host


def build_grafana_plan(args: Any) -> AuditCommandPlan:
    plan = build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)
    token = str(getattr(args, "apitoken", "") or "").strip() or None
    token_runs = (AuditCredentialRun(token=token, source="provided"),) if token is not None else ()
    default_runs = (
        tuple(
            AuditCredentialRun(username=username, password=password, source=source)
            for username, password, source in actions._build_credential_candidates(None, None, True)
        )
        if bool(getattr(args, "defcreds", False))
        else ()
    )
    return replace(
        plan,
        credential_runs=merge_audit_credential_runs(token_runs, plan.credential_runs, default_runs),
    )


def _grafana_credential_gate(credential: AuditCredentialRun, record: AuditRecord) -> tuple[bool, str]:
    """Only stop credential fallback after Grafana verified this candidate."""

    if credential.source == "default":
        verified = bool(record.extra.get("default_credentials"))
    else:
        verified = record.extra.get("provided_credentials_ok") is True
    return verified, "grafana credential verified" if verified else "grafana credential rejected"


def _build_grafana_host_stage_options(args: Any) -> dict[str, Any]:
    options = getattr(args, "_grafana_host_stage_options", None)
    if options is not None:
        return options
    check_urls = getattr(args, "check_urls", None)
    if check_urls is None:
        check_urls = actions._normalize_check_urls(
            getattr(args, "ssrf_target", None),
            getattr(args, "ssrf_port", None),
            getattr(args, "ssrf_path", None),
        )
    return {
        "check_urls": list(check_urls),
        "show_datasources": bool(getattr(args, "show_datasources", False)),
    }


def build_grafana_spec(args: Any) -> ModuleAuditSpec:
    options = _build_grafana_host_stage_options(args)
    resolved_host_stage = getattr(actions, _PRODUCTION_HOST_STAGE.__name__, _PRODUCTION_HOST_STAGE)
    use_lifecycle_hooks = (
        actions.host_stage is _PRODUCTION_HOST_STAGE
        and resolved_host_stage is _PRODUCTION_HOST_STAGE
        and actions._audit_grafana_host is _PRODUCTION_AUDIT_HOST
    )

    def _detect(ctx: Any) -> AuditRecord:
        return AuditRecord.from_mapping(actions.detect_grafana(ctx, options), module="grafana", service="grafana")

    def _auth(ctx: Any, record: Any) -> AuditRecord:
        return AuditRecord.from_mapping(
            actions.authenticate_grafana(ctx, record, options),
            module="grafana",
            service="grafana",
        )

    def _data(ctx: Any, record: Any) -> AuditRecord:
        return AuditRecord.from_mapping(
            actions.collect_grafana_data(ctx, record, options),
            module="grafana",
            service="grafana",
        )

    return ModuleAuditSpec(
        module="grafana",
        label="GRAFANA",
        default_port=_DEFAULT_PORT,
        host_stage=actions.host_stage,
        host_stage_options=options,
        detect=_detect if use_lifecycle_hooks else None,
        auth=_auth if use_lifecycle_hooks else None,
        data=_data if use_lifecycle_hooks else None,
        lifecycle_state_factory=(lambda _ctx: actions.GrafanaLifecycleState()) if use_lifecycle_hooks else None,
        render_module=render,
        colorize=render._render_colored_grafana_line,
        credential_gate=_grafana_credential_gate,
        continue_after_credential_error=bool(getattr(args, "defcreds", False)),
        continue_after_credential_success=bool(getattr(args, "defcreds", False)),
    )


def _validate_and_prepare_grafana_args(args: Any, console: Any) -> int | None:
    validation_rc = policy.validate_args(args, console)
    if validation_rc is not None:
        return int(validation_rc)
    try:
        options = _build_grafana_host_stage_options(args)
    except ValueError as exc:
        console.error(f"failed to parse Grafana SSRF targets/ports: {exc}")
        return 2
    if getattr(args, "ssrf_target", None) and not options["check_urls"]:
        console.error("no valid SSRF targets/ports after parsing")
        return 2
    args._grafana_host_stage_options = options
    return None


def run_grafana_stage(args: Any, logger: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    console = Console(debug=cfg.debug)
    return run_basic_host_audit(
        args,
        logger,
        console=console,
        label="GRAFANA",
        validate=_validate_and_prepare_grafana_args,
        build_plan=build_grafana_plan,
        build_spec=build_grafana_spec,
    )


__all__ = [
    "_build_grafana_host_stage_options",
    "build_grafana_plan",
    "build_grafana_spec",
    "run_grafana_stage",
]
