"""Runtime entrypoint for the elastic audit module."""

from __future__ import annotations

from typing import Any

from ...audit_config import AuditConfig
from ...audit_models import AuditRecord
from ...console import Console
from ...stage_runtime import (
    AuditCommandPlan,
    AuditCommandRunner,
    AuditCredentialRun,
    AuditHookContext,
    ModuleAuditSpec,
    build_basic_audit_plan,
)
from ...utils import parse_username_password_credential_file
from . import actions, policy, render

_DEFAULT_PORT = 9200
_DEFAULT_PORTS: tuple[int, ...] | None = (9200, 19200)
_PRODUCTION_HOST_STAGE = actions.host_stage
_PRODUCTION_AUDIT_HOST = actions._audit_elastic_host


def _build_elastic_credential_runs(args: Any) -> tuple[AuditCredentialRun, ...]:
    """Merge Elastic credentials in deterministic priority order."""

    runs: list[AuditCredentialRun] = []
    seen_basic: set[tuple[str, str]] = set()

    api_token = getattr(args, "apitoken", None) or getattr(args, "api_token", None) or getattr(args, "token", None)
    if api_token:
        runs.append(AuditCredentialRun(token=str(api_token), source="token"))

    username = getattr(args, "username", None)
    password = getattr(args, "password", None)
    credential_file_entries = parse_username_password_credential_file(username, password)
    basic_candidates: list[tuple[str, str, str]] = []
    if credential_file_entries is not None:
        basic_candidates.extend((str(entry.username), str(entry.password), "file") for entry in credential_file_entries)
    elif username is not None and password is not None:
        basic_candidates.append((str(username), str(password), "provided"))

    for candidate_username, candidate_password, source in basic_candidates:
        pair = (candidate_username, candidate_password)
        if pair in seen_basic:
            continue
        seen_basic.add(pair)
        runs.append(
            AuditCredentialRun(
                username=candidate_username,
                password=candidate_password,
                source=source,
            )
        )

    if bool(getattr(args, "defcreds", False)):
        for default_username, default_password in actions._build_credential_runs(None, None, True):
            if default_username is None or default_password is None:
                continue
            pair = (default_username, default_password)
            if pair in seen_basic:
                continue
            seen_basic.add(pair)
            runs.append(
                AuditCredentialRun(
                    username=default_username,
                    password=default_password,
                    source="default",
                )
            )

    if not runs:
        runs.append(AuditCredentialRun(source="anonymous"))
    return tuple(runs)


def build_elastic_plan(args: Any) -> AuditCommandPlan:
    args._audit_credential_runs = _build_elastic_credential_runs(args)
    return build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)


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
    verified = auth_valid is True
    return (
        verified,
        "credential identity verified" if verified else "credential identity unverified",
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
        return AuditRecord.from_mapping(
            actions.detect_elastic(ctx, options),
            module="elastic",
            service="elastic",
        )

    def _auth(ctx: AuditHookContext, record: AuditRecord) -> AuditRecord:
        return AuditRecord.from_mapping(
            actions.authenticate_elastic(ctx, record, options),
            module="elastic",
            service="elastic",
        )

    def _data(ctx: AuditHookContext, record: AuditRecord) -> AuditRecord:
        return AuditRecord.from_mapping(
            actions.collect_elastic_data(ctx, record, options),
            module="elastic",
            service="elastic",
        )

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
        render_module=render,
        colorize=render._render_colored_elastic_line,
        suppress_undetected_records_in_text=True,
        credential_gate=_elastic_credential_gate,
        record_all_credential_attempts=True,
        fallback_to_anonymous_detect_record=True,
        continue_after_credential_error=True,
        structured_output_redact_fields=("api_token", "provided_password"),
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
    return 0


__all__ = [
    "_build_elastic_host_stage_options",
    "build_elastic_plan",
    "build_elastic_spec",
    "run_elastic_stage",
]
