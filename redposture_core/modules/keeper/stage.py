"""Runtime entrypoint for the keeper audit module."""

from __future__ import annotations

import sys
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
from . import actions, ddl, interactive, policy, render
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
        if payload.get("is_zookeeper") is True and payload.get("is_keeper") is True:
            state = ctx.lifecycle_state
            client = (
                state.zookeeper_state.anonymous_client
                if isinstance(state, engine.ZooKeeperImplementationLifecycleState)
                else None
            )
            access, detail = (
                actions.probe_ddl_access(client) if client is not None else ("Unknown", "no anonymous session")
            )
            payload.update(
                {
                    "ddl_access": access,
                    "ddl_access_scope": actions._DDL_QUEUE,
                    "ddl_access_identity": "anonymous",
                    "ddl_access_detail": detail,
                }
            )
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
        state = ctx.lifecycle_state
        client = (
            state.zookeeper_state.anonymous_client
            if isinstance(state, engine.ZooKeeperImplementationLifecycleState)
            else None
        )
        if getattr(args, "show_cluster", False) or getattr(args, "show_hosts", False):
            payload["ddl_topology"] = (
                ddl.read_ddl_topology(client)
                if client is not None
                else {"status": "unavailable", "clusters": {}, "reason": "anonymous Keeper session unavailable"}
            )
            payload["ddl_topology_requested"] = {
                "clusters": bool(getattr(args, "show_cluster", False)),
                "hosts": bool(getattr(args, "show_hosts", False)),
            }
        if getattr(args, "create_user", None):

            def _refresh_ddl_session() -> tuple[bool, str | None]:
                reset_error = actions._reset_probe_session(client)
                if reset_error:
                    return False, reset_error
                current_access, detail = actions.probe_ddl_access(client)
                if current_access != "Write":
                    return False, f"DDL access changed to {current_access}" + (f": {detail}" if detail else "")
                return True, None

            payload["ddl_user_creation"] = (
                (
                    interactive.run_user_creation(
                        client,
                        str(args.create_user),
                        str(args.create_userpass),
                        access=str(record.extra.get("ddl_access") or "Unknown"),
                        grant_admin=bool(getattr(args, "grant_admin", False)),
                        clickhouse_host=getattr(args, "clickhouse_host", None),
                        clickhouse_port=getattr(args, "clickhouse_port", 9000),
                        clickhouse_cluster=getattr(args, "clickhouse_cluster", None),
                        timeout=float(getattr(args, "timeout", 5.0) or 5.0),
                        input_stream=args._keeper_input_stream,
                        output_stream=args._keeper_output_stream,
                        refresh_session=_refresh_ddl_session,
                    )
                    if getattr(args, "_keeper_interactive_create", False)
                    else ddl.create_user_via_ddl(
                        client,
                        str(args.create_user),
                        str(args.create_userpass),
                        access=str(record.extra.get("ddl_access") or "Unknown"),
                        grant_admin=bool(getattr(args, "grant_admin", False)),
                        clickhouse_host=getattr(args, "clickhouse_host", None),
                        clickhouse_port=getattr(args, "clickhouse_port", 9000),
                        clickhouse_cluster=getattr(args, "clickhouse_cluster", None),
                        timeout=float(getattr(args, "timeout", 5.0) or 5.0),
                    )
                )
                if client is not None
                else {
                    "username": str(args.create_user),
                    "status": "unavailable",
                    "admin_status": "not_attempted" if getattr(args, "grant_admin", False) else "not_requested",
                    "reason": "anonymous Keeper session unavailable",
                }
            )
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
        queue_gate = _anonymous_ddl_gate(record)
        if queue_gate[0]:
            return queue_gate
        status = str(record.status or "")
        accepted = status in {"open_no_auth", "valid_credentials", "weak_default_creds"}
        return accepted, f"status={status}"

    def _anonymous_ddl_gate(record: AuditRecord) -> tuple[bool, str]:
        access = str(record.extra.get("ddl_access") or "")
        if getattr(args, "create_user", None) and access == "Write":
            return True, "anonymous DDL queue writable"
        if (getattr(args, "show_cluster", False) or getattr(args, "show_hosts", False)) and access in {
            "Write",
            "Read",
        }:
            return True, "anonymous DDL queue readable"
        return False, ""

    def _deep_gate(record: AuditRecord) -> tuple[bool, str]:
        queue_gate = _anonymous_ddl_gate(record)
        if queue_gate[0]:
            return queue_gate
        status = str(record.status or "unknown")
        allowed = {
            "ok",
            "open",
            "open_no_auth",
            "anonymous_access",
            "detected",
            "token_ok",
            "valid_credentials",
            "auth_valid",
            "weak_default_creds",
            "invalid_credentials_anonymous",
            "valid_token",
            "token_accepted",
            "insufficient_privileges",
        }
        return status in allowed, f"status={status}"

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
        live_phase_output=bool(getattr(args, "_keeper_interactive_create", False)),
        keep_anonymous_open_no_auth=True,
        skip_credentials_without_verifier=True,
        credential_gate=_credential_gate,
        deep_gate=_deep_gate,
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
    if getattr(args, "create_user", None) and not getattr(args, "yes", False):
        if plan.target_count != 1:
            console.error("interactive --create-user requires one target; use --yes for automation")
            return 2
        if not sys.stdin.isatty():
            console.error("interactive --create-user requires a terminal; use --yes for automation")
            return 2
        args._keeper_interactive_create = True
        args._keeper_input_stream = sys.stdin
        args._keeper_output_stream = sys.stderr
        plan = replace(plan, workers=1)
    else:
        args._keeper_interactive_create = False
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
