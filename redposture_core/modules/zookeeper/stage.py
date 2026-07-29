"""Runtime entrypoint for the zookeeper audit module."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from ...audit_config import AuditConfig
from ...audit_models import AuditRecord
from ...console import Console
from ...show_limits import dump_flag_enabled, dump_flag_limit, show_flag_enabled, show_flag_limit
from ...stage_runtime import (
    AuditCommandPlan,
    AuditCommandRunner,
    AuditCredentialRun,
    AuditHookContext,
    ModuleAuditSpec,
    build_basic_audit_plan,
    merge_audit_credential_runs,
)
from . import actions, policy, render

_DEFAULT_PORT = 2181
_DEFAULT_PORTS: tuple[int, ...] | None = (2181, 12181)
_DEFAULT_CREDENTIALS: tuple[tuple[str, str], ...] = (
    ("zookeeper", "zookeeper"),
    ("zookeeper", "admin"),
    ("zookeeper", "password"),
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "zookeeper"),
    ("zk", "zk"),
    ("zk", "zookeeper"),
    ("zk", "password"),
    ("root", "root"),
    ("root", "password"),
    ("root", "zookeeper"),
    ("user", "user"),
    ("user", "password"),
    ("guest", "guest"),
    ("test", "test"),
    ("dev", "dev"),
    ("service", "service"),
    ("kafka", "kafka"),
    ("kafka", "zookeeper"),
    ("solr", "solr"),
    ("hadoop", "hadoop"),
    ("super", "super"),
    ("user1", "12345"),
    ("admin", "changeme"),
    ("admin", "kafka"),
    ("kafka", "password"),
    ("kafka", "changeme"),
    ("broker", "broker"),
    ("broker", "brokerpass"),
    ("client", "client"),
    ("service", "password"),
    ("root", "admin"),
    ("root", "rootpass"),
)
_PRODUCTION_HOST_STAGE = actions.host_stage
_PRODUCTION_AUDIT_HOST = actions._audit_zookeeper_host


def build_zookeeper_plan(args: Any) -> AuditCommandPlan:
    plan = build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)
    defaults: tuple[AuditCredentialRun, ...] = ()
    if bool(getattr(args, "defcreds", False)):
        defaults = tuple(
            AuditCredentialRun(username=username, password=password, source="default")
            for username, password in _DEFAULT_CREDENTIALS
        )
    return replace(
        plan,
        credential_runs=merge_audit_credential_runs(plan.credential_runs, defaults),
    )


def _build_zookeeper_lifecycle_options(args: Any) -> dict[str, Any]:
    show_limit = show_flag_limit(getattr(args, "show_znodes", False))
    configured_max = int(getattr(args, "max_znodes", 2000) or 2000)
    return {
        "show_znodes": show_flag_enabled(getattr(args, "show_znodes", False)),
        "dump": dump_flag_enabled(getattr(args, "dump", False)),
        "query_znode": actions._normalize_znode_path(getattr(args, "znode", None)),
        "max_znodes": int(show_limit) if isinstance(show_limit, int) else configured_max,
        "enum_workers": int(getattr(args, "enum_workers", 3) or 3),
        "dump_limit": dump_flag_limit(getattr(args, "dump", False)),
        "transport_config": getattr(args, "transport_config", None),
    }


def build_zookeeper_spec(args: Any) -> ModuleAuditSpec:
    options = _build_zookeeper_lifecycle_options(args)
    exhaustive_credentials = bool(getattr(args, "defcreds", False))
    resolved_host_stage = getattr(actions, _PRODUCTION_HOST_STAGE.__name__, _PRODUCTION_HOST_STAGE)
    use_lifecycle_hooks = (
        actions.host_stage is _PRODUCTION_HOST_STAGE
        and resolved_host_stage is _PRODUCTION_HOST_STAGE
        and actions._audit_zookeeper_host is _PRODUCTION_AUDIT_HOST
    )

    def _state_factory(_ctx: AuditHookContext) -> actions.ZooKeeperLifecycleState:
        return actions.ZooKeeperLifecycleState()

    def _detect(ctx: AuditHookContext) -> AuditRecord:
        return AuditRecord.from_mapping(
            actions.detect_zookeeper(ctx, options),
            module="zookeeper",
            service="zookeeper",
        )

    def _auth(ctx: AuditHookContext, record: AuditRecord) -> AuditRecord:
        return AuditRecord.from_mapping(
            actions.authenticate_zookeeper(ctx, record, options),
            module="zookeeper",
            service="zookeeper",
        )

    def _data(ctx: AuditHookContext, record: AuditRecord) -> AuditRecord:
        return AuditRecord.from_mapping(
            actions.collect_zookeeper_data(ctx, record, options),
            module="zookeeper",
            service="zookeeper",
        )

    def _credential_gate(credential: AuditCredentialRun, record: AuditRecord) -> tuple[bool, str]:
        supplied = credential.username is not None or credential.password is not None
        if supplied:
            verified = record.extra.get("provided_credentials_ok") is True
            return verified, "credential verified" if verified else "credential not verified"
        status = str(record.status or "")
        accepted = status in {"open_no_auth", "valid_credentials", "weak_default_creds"}
        return accepted, f"status={status}"

    return ModuleAuditSpec(
        module="zookeeper",
        label="ZOOKEEPER",
        default_port=_DEFAULT_PORT,
        host_stage=actions.host_stage,
        detect=_detect if use_lifecycle_hooks else None,
        auth=_auth if use_lifecycle_hooks else None,
        data=_data if use_lifecycle_hooks else None,
        lifecycle_state_factory=_state_factory if use_lifecycle_hooks else None,
        lifecycle_state_close=(lambda state: state.close()) if use_lifecycle_hooks else None,
        render_module=render,
        colorize=render._render_colored_zookeeper_line,
        # E3 opt-in: ZooKeeper anon-open (default ACLs, no digest ACL on /)
        # is confirmed by the anon probe listing /.
        keep_anonymous_open_no_auth=True,
        credential_gate=_credential_gate,
        continue_after_credential_success=exhaustive_credentials,
        continue_after_credential_error=exhaustive_credentials,
        fallback_to_anonymous_detect_record=exhaustive_credentials,
        credential_attempt_detail_fields=("provided_credentials_ok", "credential_verdict"),
    )


def run_zookeeper_stage(args: Any, logger: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    console = Console(debug=cfg.debug)
    if hasattr(console, "set_structured_output"):
        console.set_structured_output(cfg.output_format == "json")
    if getattr(args, "username", None) is not None:
        args.username = str(args.username).strip()
        if args.username == "":
            args.username = None
    if getattr(args, "password", None) is not None:
        args.password = str(args.password).strip()
        if args.username is None and args.password == "":
            args.password = None
    validation_rc = policy.validate_args(args, console)
    if validation_rc is not None:
        return int(validation_rc)
    try:
        plan = build_zookeeper_plan(args)
    except ValueError as exc:
        console.error(str(exc))
        return 2
    if cfg.debug and not getattr(args, "debug_emit", None):
        args.debug_emit = console.info
    if cfg.debug:
        suffix = f" format={cfg.output_format}"
        if cfg.output:
            suffix += f" output={args.output}"
        console.info("zookeeper audit started:" + suffix)
    runner = AuditCommandRunner(args=args, spec=build_zookeeper_spec(args), logger=logger, console=console)
    try:
        result = runner.run_plan(plan)
    except OSError as exc:
        console.error(f"failed to process zookeeper output: {exc}")
        return 2
    if cfg.debug and result.detected_count == 0 and hasattr(console, "warn"):
        console.warn("all zookeeper targets are unreachable")
    return 0


__all__ = ["build_zookeeper_plan", "build_zookeeper_spec", "run_zookeeper_stage"]
