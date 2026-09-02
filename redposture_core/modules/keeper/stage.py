"""Runtime entrypoint for the keeper audit module."""

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
    command_result_exit_code,
    merge_audit_credential_runs,
    sort_default_audit_credential_runs,
)
from ...zookeeper_defaults import KEEPER_DIGEST_DEFAULT_CREDENTIALS
from ..zookeeper import actions as protocol_actions
from ..zookeeper import engine
from . import policy, render
from .types import KeeperFingerprintCache

_DEFAULT_PORT = 9181
_DEFAULT_PORTS: tuple[int, ...] | None = (9181, 19181, 29181)
_DEFAULT_CREDENTIALS = KEEPER_DIGEST_DEFAULT_CREDENTIALS


def build_keeper_plan(args: Any) -> AuditCommandPlan:
    plan = build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)
    defaults: tuple[AuditCredentialRun, ...] = ()
    if bool(getattr(args, "defcreds", False)):
        defaults = sort_default_audit_credential_runs(
            AuditCredentialRun(username=username, password=password, source="default")
            for username, password in _DEFAULT_CREDENTIALS
        )
    return replace(
        plan,
        credential_runs=merge_audit_credential_runs(plan.credential_runs, defaults),
    )


def _build_keeper_lifecycle_options(args: Any) -> dict[str, Any]:
    show_limit = show_flag_limit(getattr(args, "show_znodes", False))
    configured_max = int(getattr(args, "max_znodes", 2000) or 2000)
    return {
        "show_znodes": show_flag_enabled(getattr(args, "show_znodes", False)),
        "dump": dump_flag_enabled(getattr(args, "dump", False)),
        "query_znode": protocol_actions._normalize_znode_path(getattr(args, "znode", None)),
        "probe_write": bool(getattr(args, "probe_write", False)),
        "max_znodes": int(show_limit) if isinstance(show_limit, int) else configured_max,
        "enum_workers": int(getattr(args, "enum_workers", 3) or 3),
        "dump_limit": dump_flag_limit(getattr(args, "dump", False)),
        "fingerprint_cache": getattr(args, "keeper_fingerprint_cache", None) or KeeperFingerprintCache(),
        "insecure": bool(getattr(args, "insecure", False)),
        "ca_file": getattr(args, "ca_file", None),
        "tls_cert": getattr(args, "tls_cert", None),
        "tls_key": getattr(args, "tls_key", None),
        "record_service": "keeper",
    }


def build_keeper_spec(args: Any) -> ModuleAuditSpec:
    options = _build_keeper_lifecycle_options(args)
    exhaustive_credentials = bool(getattr(args, "defcreds", False))

    def _state_factory(_ctx: AuditHookContext) -> engine.ZooKeeperImplementationLifecycleState:
        return engine.ZooKeeperImplementationLifecycleState(
            requested_config=engine._transport_config(
                insecure=bool(options["insecure"]),
                ca_file=options["ca_file"],
                tls_cert=options["tls_cert"],
                tls_key=options["tls_key"],
            )
        )

    def _detect(ctx: AuditHookContext) -> AuditRecord:
        payload = engine.enforce_expected_implementation(
            engine.detect_zookeeper_implementation(ctx, options),
            expected_is_keeper=True,
        )
        payload["module"] = "keeper"
        payload["service"] = "keeper"
        return AuditRecord.from_mapping(payload, module="keeper", service="keeper")

    def _auth(ctx: AuditHookContext, record: AuditRecord) -> AuditRecord:
        payload = engine.authenticate_zookeeper_implementation(ctx, record, options)
        payload["module"] = "keeper"
        payload["service"] = "keeper"
        return AuditRecord.from_mapping(payload, module="keeper", service="keeper")

    def _data(ctx: AuditHookContext, record: AuditRecord) -> AuditRecord:
        payload = engine.collect_zookeeper_implementation_data(ctx, record, options)
        payload["module"] = "keeper"
        payload["service"] = "keeper"
        return AuditRecord.from_mapping(payload, module="keeper", service="keeper")

    def _capabilities(ctx: AuditHookContext, record: AuditRecord) -> AuditRecord:
        payload = engine.probe_zookeeper_implementation_capabilities(ctx, record, options)
        payload["module"] = "keeper"
        payload["service"] = "keeper"
        return AuditRecord.from_mapping(payload, module="keeper", service="keeper")

    def _credential_gate(credential: AuditCredentialRun, record: AuditRecord) -> tuple[bool, str]:
        supplied = credential.username is not None or credential.password is not None
        if supplied:
            verified = record.extra.get("provided_credentials_ok") is True
            return verified, "credential verified" if verified else "credential not verified"
        status = str(record.status or "")
        accepted = status in {"open_no_auth", "valid_credentials", "weak_default_creds"}
        return accepted, f"status={status}"

    def _is_detected(record: AuditRecord) -> bool:
        return bool(record.extra.get("is_zookeeper")) and record.extra.get("is_keeper") is True

    return ModuleAuditSpec(
        module="keeper",
        label="KEEPER",
        default_port=_DEFAULT_PORT,
        detect=_detect,
        auth=_auth,
        capabilities=_capabilities,
        data=_data,
        lifecycle_state_factory=_state_factory,
        lifecycle_state_close=lambda state: state.close(),
        render_module=render,
        colorize=render._render_colored_keeper_line,
        is_detected=_is_detected,
        keep_anonymous_open_no_auth=True,
        skip_credentials_without_verifier=True,
        credential_gate=_credential_gate,
        continue_after_credential_success=exhaustive_credentials,
        continue_after_credential_error=exhaustive_credentials,
        fallback_to_anonymous_detect_record=exhaustive_credentials,
        credential_attempt_detail_fields=("provided_credentials_ok", "credential_verdict"),
        suppress_undetected_records_in_text=True,
    )


def run_keeper_stage(args: Any, logger: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    console = Console(debug=cfg.debug)
    if hasattr(console, "set_structured_output"):
        console.set_structured_output(cfg.output_format == "json")
    if getattr(args, "username", None) is not None:
        args.username = str(args.username).strip()
        if args.username == "":
            args.username = None
    if getattr(args, "password", None) is not None:
        raw_password = str(args.password)
        args.password = raw_password if raw_password or args.username is not None else None
    validation_rc = policy.validate_args(args, console)
    if validation_rc is not None:
        return int(validation_rc)
    try:
        plan = build_keeper_plan(args)
    except ValueError as exc:
        console.error(str(exc))
        return 2
    args.keeper_fingerprint_cache = KeeperFingerprintCache()
    if cfg.debug and not getattr(args, "debug_emit", None):
        args.debug_emit = console.info
    if cfg.debug:
        suffix = f" format={cfg.output_format}"
        if cfg.output:
            suffix += f" output={args.output}"
        console.info("keeper audit started:" + suffix)
    runner = AuditCommandRunner(args=args, spec=build_keeper_spec(args), logger=logger, console=console)
    try:
        result = runner.run_plan(plan)
    except OSError as exc:
        console.error(f"failed to process keeper output: {exc}")
        return 2
    if cfg.debug and result.detected_count == 0 and hasattr(console, "warn"):
        console.warn("no target confirmed as ClickHouse Keeper")
    return command_result_exit_code(result)


__all__ = ["build_keeper_plan", "build_keeper_spec", "run_keeper_stage"]
