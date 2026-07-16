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
    has_username_password_credential_file,
)
from . import actions, policy, render

_DEFAULT_PORT = 9200
_DEFAULT_PORTS: tuple[int, ...] | None = (9200, 19200)
_PRODUCTION_HOST_STAGE = actions.host_stage
_PRODUCTION_AUDIT_HOST = actions._audit_elastic_host


def build_elastic_plan(args: Any) -> AuditCommandPlan:
    return build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)


def _build_elastic_host_stage_options(args: Any) -> dict[str, Any]:
    return {
        "show_endpoints": bool(getattr(args, "endpoints", False)),
        "show_plugins": bool(getattr(args, "plugins", False)),
        "show_cluster": bool(getattr(args, "cluster", False)),
        "show_users": bool(getattr(args, "user", False)),
        "discover": bool(getattr(args, "discover", False)),
    }


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
        # E3 opt-in: Elastic anon-open cluster never needs a credential probe.
        keep_anonymous_open_no_auth=True,
    )


def run_elastic_stage(args: Any, logger: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    console = Console(debug=cfg.debug)
    if hasattr(console, "set_structured_output"):
        console.set_structured_output(cfg.output_format == "json")
    validation_rc = policy.validate_args(args, console)
    if validation_rc is not None:
        return int(validation_rc)
    if getattr(args, "apitoken", None):
        args.api_token = args.apitoken
        args.token = args.apitoken
        args.username = None
        args.password = None
        args.defcreds = False
    if (
        not getattr(args, "api_token", None)
        and not has_username_password_credential_file(args)
        and not (getattr(args, "username", None) is not None and getattr(args, "password", None) is None)
    ):
        provided_pair = (getattr(args, "username", None), getattr(args, "password", None))
        args._audit_credential_runs = tuple(
            AuditCredentialRun(
                username=user,
                password=password,
                source=(
                    "provided"
                    if (user, password) == provided_pair and provided_pair[0] is not None
                    else "default"
                    if user is not None
                    else "anonymous"
                ),
            )
            for user, password in actions._build_credential_runs(
                getattr(args, "username", None), getattr(args, "password", None), bool(getattr(args, "defcreds", False))
            )
        )
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
