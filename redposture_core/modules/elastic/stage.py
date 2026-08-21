"""Runtime entrypoint for the elastic audit module."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from ...audit_config import AuditConfig
from ...audit_models import AuditRecord
from ...clients.http_api import http_target_context
from ...console import Console
from ...stage_runtime import (
    AuditCommandPlan,
    AuditCommandRunner,
    AuditCredentialRun,
    AuditHookContext,
    ModuleAuditSpec,
    build_basic_audit_plan,
    command_result_exit_code,
    merge_audit_credential_runs,
    sort_default_audit_credential_runs,
)
from ...utils import parse_username_password_credential_file
from . import actions, policy, render

_DEFAULT_PORT = 9200
_DEFAULT_PORTS: tuple[int, ...] | None = (9200, 19200, 29200)
_MASS_PROFILE_MIN_ENDPOINTS = 10_000
_MASS_PROFILE_MAX_WORKERS = 200
_MASS_PROFILE_PROXY_MAX_WORKERS = 64
_ELASTIC_RECORD_RETENTION_LIMIT = _MASS_PROFILE_MIN_ENDPOINTS - 1
_ELASTIC_PROGRESS_REFRESH_INTERVAL_S = 0.1
_PRODUCTION_HOST_STAGE = actions.host_stage
_PRODUCTION_AUDIT_HOST = actions._audit_elastic_host


def _build_elastic_credential_runs(args: Any) -> tuple[AuditCredentialRun, ...]:
    """Merge Elastic credentials in deterministic priority order."""

    api_token = getattr(args, "apitoken", None) or getattr(args, "api_token", None) or getattr(args, "token", None)
    token_runs = (AuditCredentialRun(token=str(api_token), source="token"),) if api_token else ()

    username = getattr(args, "username", None)
    password = getattr(args, "password", None)
    credential_file_entries = parse_username_password_credential_file(username, password)
    if credential_file_entries is not None:
        basic_runs = tuple(
            AuditCredentialRun(username=str(entry.username), password=str(entry.password), source="file")
            for entry in credential_file_entries
        )
    elif username is not None and password is not None:
        basic_runs = (
            AuditCredentialRun(
                username=str(username),
                password=str(password),
                source="provided",
            ),
        )
    else:
        basic_runs = ()

    default_runs = (
        sort_default_audit_credential_runs(
            AuditCredentialRun(
                username=default_username,
                password=default_password,
                source="default",
            )
            for default_username, default_password in actions._build_credential_runs(None, None, True)
            if default_username is not None and default_password is not None
        )
        if bool(getattr(args, "defcreds", False))
        else ()
    )
    return merge_audit_credential_runs(token_runs, basic_runs, default_runs)


def _safe_mass_worker_limit(max_workers: int) -> int:
    """Return a worker count that leaves headroom in the process FD limit."""

    requested = max(1, int(max_workers))
    try:
        import resource

        soft_limit, _hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft_limit == resource.RLIM_INFINITY or int(soft_limit) < 0:
            return requested
        # One active HTTP request normally consumes one socket. Budgeting two
        # descriptors per worker also covers TLS fallback/reconnect plus a
        # reserve for output files, logs, imports, and the surrounding shell.
        fd_budget = max(1, (int(soft_limit) - 64) // 2)
        return max(1, min(requested, fd_budget))
    except (AttributeError, ImportError, OSError, TypeError, ValueError):
        return requested


def _effective_plan_ports(plan: AuditCommandPlan) -> tuple[int, ...]:
    if plan.target_plan is None:
        return tuple(int(port) for port in plan.ports)
    target_plan = plan.target_plan
    ports: list[int] = []
    if target_plan.no_port_count > 0 or (
        target_plan.include_matrix_ports_for_bare_explicit_targets and target_plan.bare_explicit_port_counts
    ):
        ports.extend(int(port) for port in plan.ports)
    ports.extend(int(port) for port in target_plan.explicit_ports)
    return tuple(dict.fromkeys(ports))


def _apply_elastic_mass_profile(args: Any, plan: AuditCommandPlan) -> AuditCommandPlan:
    """Apply the automatic high-volume profile to CLI-originated arguments."""

    endpoint_count = int(plan.target_count)
    mass_plan = endpoint_count >= _MASS_PROFILE_MIN_ENDPOINTS
    auto_fields: list[str] = []
    effective_workers = int(plan.workers)

    if mass_plan and getattr(args, "_workers_option_provided", True) is False:
        ceiling = _MASS_PROFILE_PROXY_MAX_WORKERS if getattr(args, "proxy", None) else _MASS_PROFILE_MAX_WORKERS
        effective_workers = _safe_mass_worker_limit(ceiling)
        args.workers = effective_workers
        plan = replace(plan, workers=effective_workers)
        auto_fields.append("workers")

    # Elastic transport retries are opt-in even for smaller plans.  A failed
    # socket can otherwise multiply a large mostly-closed target list before
    # the mass-profile threshold is reached.  Programmatic callers without
    # CLI provenance keep their explicitly constructed value.
    if getattr(args, "_retries_option_provided", True) is False:
        args.retries = 0
        auto_fields.append("retries")

    if mass_plan and getattr(args, "_timeout_option_provided", True) is False:
        args.timeout = 1.0
        auto_fields.append("timeout")

    if mass_plan:
        reason = (
            f"mass plan >= {_MASS_PROFILE_MIN_ENDPOINTS} endpoints"
            if auto_fields
            else "mass plan detected; explicit CLI values preserved"
        )
    elif "retries" in auto_fields:
        reason = "standard Elastic profile; retries require explicit -r/--retries"
    else:
        reason = "standard profile"
    args._elastic_effective_profile = {
        "endpoint_count": endpoint_count,
        "ports": _effective_plan_ports(plan),
        "workers": int(plan.workers),
        "retries": int(getattr(args, "retries", 0) or 0),
        "timeout": float(getattr(args, "timeout", 1.0) or 1.0),
        "proxy": bool(getattr(args, "proxy", None)),
        "automatic_fields": tuple(auto_fields),
        "reason": reason,
    }
    return plan


def build_elastic_plan(args: Any) -> AuditCommandPlan:
    args._audit_credential_runs = _build_elastic_credential_runs(args)
    plan = build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)
    explicit_port = getattr(args, "port", None) is not None or bool(str(getattr(args, "ports", "") or "").strip())
    if not explicit_port and plan.target_plan is not None:
        plan = replace(plan, target_plan=plan.target_plan.with_scheme_default_ports({"http": 80, "https": 443}))
    return _apply_elastic_mass_profile(args, plan)


def _build_elastic_host_stage_options(args: Any) -> dict[str, Any]:
    return {
        "show_endpoints": bool(getattr(args, "endpoints", False)),
        "show_plugins": bool(getattr(args, "plugins", False)),
        "show_cluster": bool(getattr(args, "cluster", False)),
        "show_users": bool(getattr(args, "user", False)),
        "discover": bool(getattr(args, "discover", False)),
    }


def _elastic_credential_gate(
    credential: AuditCredentialRun,
    record: AuditRecord,
) -> tuple[bool, str]:
    if credential.username is None and credential.password is None and credential.token is None:
        status = str(record.status or "")
        return status == "open_no_auth", f"status={status}"
    auth_valid = record.extra.get("auth_valid")
    accepted = auth_valid is True
    return (
        accepted,
        "credential accepted" if accepted else "credential rejected or unverified",
    )


def build_elastic_spec(args: Any) -> ModuleAuditSpec:
    options = _build_elastic_host_stage_options(args)
    resolved_host_stage = getattr(actions, _PRODUCTION_HOST_STAGE.__name__, _PRODUCTION_HOST_STAGE)
    use_lifecycle_hooks = (
        actions.host_stage is _PRODUCTION_HOST_STAGE
        and resolved_host_stage is _PRODUCTION_HOST_STAGE
        and actions._audit_elastic_host is _PRODUCTION_AUDIT_HOST
    )

    def _state_factory(_ctx: AuditHookContext) -> actions.ElasticLifecycleState:
        return actions.ElasticLifecycleState()

    def _detect(ctx: AuditHookContext) -> AuditRecord:
        with http_target_context(
            ctx.target,
            api_prefixes=("/_security", "/_plugins", "/_cluster", "/_cat", "/_nodes"),
        ):
            result = actions.detect_elastic(ctx, options)
        return AuditRecord.from_mapping(result, module="elastic", service="elastic")

    def _auth(ctx: AuditHookContext, record: AuditRecord) -> AuditRecord:
        with http_target_context(
            ctx.target,
            api_prefixes=("/_security", "/_plugins", "/_cluster", "/_cat", "/_nodes"),
        ):
            result = actions.authenticate_elastic(ctx, record, options)
        return AuditRecord.from_mapping(result, module="elastic", service="elastic")

    def _data(ctx: AuditHookContext, record: AuditRecord) -> AuditRecord:
        with http_target_context(
            ctx.target,
            api_prefixes=("/_security", "/_plugins", "/_cluster", "/_cat", "/_nodes"),
        ):
            result = actions.collect_elastic_data(ctx, record, options)
        return AuditRecord.from_mapping(result, module="elastic", service="elastic")

    return ModuleAuditSpec(
        module="elastic",
        label="ELASTIC",
        default_port=_DEFAULT_PORT,
        host_stage=actions.host_stage,
        host_stage_options=options,
        detect=_detect if use_lifecycle_hooks else None,
        auth=_auth if use_lifecycle_hooks else None,
        data=_data if use_lifecycle_hooks else None,
        lifecycle_state_factory=_state_factory if use_lifecycle_hooks else None,
        lifecycle_state_close=actions.close_elastic_lifecycle_state if use_lifecycle_hooks else None,
        render_module=render,
        colorize=render._render_colored_elastic_line,
        suppress_undetected_records_in_text=True,
        credential_gate=_elastic_credential_gate,
        record_all_credential_attempts=True,
        fallback_to_anonymous_detect_record=True,
        continue_after_credential_error=bool(getattr(args, "defcreds", False)),
        continue_after_credential_success=bool(getattr(args, "defcreds", False)),
        structured_output_redact_fields=("api_token", "provided_password"),
        credential_attempt_detail_fields=(
            "auth_probe_status",
            "auth_probe_http_status",
            "auth_probe_endpoint",
            "auth_error_detail",
            "network_attempted",
            "verification_capability",
        ),
        record_retention_limit=_ELASTIC_RECORD_RETENTION_LIMIT,
        progress_refresh_interval_s=_ELASTIC_PROGRESS_REFRESH_INTERVAL_S,
    )


def run_elastic_stage(args: Any, logger: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    console = Console(debug=cfg.debug)
    if hasattr(console, "set_structured_output"):
        console.set_structured_output(cfg.output_format == "json")
    validation_rc = policy.validate_args(args, console)
    if validation_rc is not None:
        return int(validation_rc)
    api_token = getattr(args, "apitoken", None) or getattr(args, "api_token", None) or getattr(args, "token", None)
    if api_token:
        args.api_token = api_token
        args.token = api_token
    try:
        plan = build_elastic_plan(args)
    except ValueError as exc:
        console.error(str(exc))
        return 2
    if cfg.debug and not getattr(args, "debug_emit", None):
        args.debug_emit = console.info
    if cfg.debug:
        suffix = f" format={cfg.output_format}"
        if cfg.output:
            suffix += f" output={args.output}"
        console.info("elastic audit started:" + suffix)
        profile = getattr(args, "_elastic_effective_profile", {})
        ports = ",".join(str(port) for port in profile.get("ports", ())) or "-"
        automatic_fields = ",".join(str(field) for field in profile.get("automatic_fields", ())) or "none"
        console.info(
            "elastic effective profile: "
            f"endpoints={profile.get('endpoint_count', plan.target_count)} "
            f"ports={ports} "
            f"workers={profile.get('workers', plan.workers)} "
            f"retries={profile.get('retries', getattr(args, 'retries', 0))} "
            f"timeout={profile.get('timeout', getattr(args, 'timeout', 1.0)):g}s "
            f"proxy={'yes' if profile.get('proxy') else 'no'} "
            f"automatic={automatic_fields} "
            f"reason={profile.get('reason', 'standard profile')}"
        )
    try:
        runner = AuditCommandRunner(args=args, spec=build_elastic_spec(args), logger=logger, console=console)
        result = runner.run_plan(plan)
    except ValueError as exc:
        console.error(str(exc))
        return 2
    except OSError as exc:
        console.error(f"failed to process elastic output: {exc}")
        return 2
    if cfg.debug and result.detected_count == 0 and hasattr(console, "warn"):
        console.warn("all elastic targets are unreachable")
    return command_result_exit_code(result)


__all__ = [
    "_build_elastic_host_stage_options",
    "build_elastic_plan",
    "build_elastic_spec",
    "run_elastic_stage",
]
