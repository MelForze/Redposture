"""Runtime entrypoint for the redis audit module."""

from __future__ import annotations

from typing import Any

from ...audit_config import AuditConfig
from ...console import Console
from ...stage_runtime import (
    AuditCommandPlan,
    AuditCredentialRun,
    ModuleAuditSpec,
    build_basic_audit_plan,
    has_username_password_credential_file,
    run_basic_host_audit,
)
from . import actions, policy, render

_DEFAULT_PORT = 6379
_DEFAULT_PORTS: tuple[int, ...] | None = (6379, 16379, 26379)
_REDIS_HOST_STAGE = actions.host_stage
_REDIS_HOST_STAGE_NAME = actions.host_stage.__name__
_REDIS_HOST_STAGE_IMPL = getattr(actions, _REDIS_HOST_STAGE_NAME, actions.host_stage)
_REDIS_AUDIT_HOST_IMPL = actions._audit_redis_host


def build_redis_plan(args: Any) -> AuditCommandPlan:
    return build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)


def _redis_use_lifecycle_hooks() -> bool:
    resolved_host_stage = (
        actions.host_stage
        if actions.host_stage is not _REDIS_HOST_STAGE
        else getattr(actions, _REDIS_HOST_STAGE_NAME, actions.host_stage)
    )
    return (
        actions.host_stage is _REDIS_HOST_STAGE
        and resolved_host_stage is _REDIS_HOST_STAGE_IMPL
        and actions._audit_redis_host is _REDIS_AUDIT_HOST_IMPL
    )


def _prepare_redis_credential_runs(args: Any) -> None:
    if has_username_password_credential_file(args):
        return
    runs: list[AuditCredentialRun] = []
    username = getattr(args, "username", None)
    password = getattr(args, "password", None)
    if username is not None or password is not None:
        runs.append(AuditCredentialRun(username=username, password=password, source="provided"))
    if bool(getattr(args, "defcreds", False)):
        default_pair = ("redis", "redis")
        if all((run.username, run.password) != default_pair for run in runs):
            runs.append(AuditCredentialRun(username="redis", password="redis", source="default"))
    if runs:
        args._audit_credential_runs = tuple(runs)


def build_redis_spec(args: Any) -> ModuleAuditSpec:
    _ = args
    use_lifecycle_hooks = _redis_use_lifecycle_hooks()
    return ModuleAuditSpec(
        module="redis",
        label="REDIS",
        default_port=_DEFAULT_PORT,
        host_stage=actions.host_stage,
        detect=actions.redis_detect_hook if use_lifecycle_hooks else None,
        auth=actions.redis_auth_hook if use_lifecycle_hooks else None,
        data=actions.redis_data_hook if use_lifecycle_hooks else None,
        lifecycle_state_factory=actions.redis_lifecycle_state_factory if use_lifecycle_hooks else None,
        lifecycle_state_close=actions.close_redis_lifecycle_state if use_lifecycle_hooks else None,
        render_module=render,
        colorize=render._render_colored_redis_line,
        # E3 opt-in: Redis anon-open (no AUTH required) makes the defcreds
        # loop redundant — the audit already succeeded without credentials.
        keep_anonymous_open_no_auth=True,
    )


def _validate_and_prepare_redis_args(args: Any, console: Any) -> int | None:
    validation_rc = policy.validate_args(args, console)
    if validation_rc is not None:
        return int(validation_rc)
    _prepare_redis_credential_runs(args)
    return None


def run_redis_stage(args: Any, logger: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    console = Console(debug=cfg.debug)
    return run_basic_host_audit(
        args,
        logger,
        console=console,
        label="REDIS",
        validate=_validate_and_prepare_redis_args,
        build_plan=build_redis_plan,
        build_spec=build_redis_spec,
    )


__all__ = [
    "_prepare_redis_credential_runs",
    "build_redis_plan",
    "build_redis_spec",
    "run_redis_stage",
]
