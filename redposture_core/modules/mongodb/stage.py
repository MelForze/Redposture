"""Runtime entrypoint for the mongodb audit module."""

from __future__ import annotations

from typing import Any

from ...audit_config import AuditConfig
from ...console import Console
from ...stage_runtime import (
    AuditCommandPlan,
    AuditCommandRunner,
    AuditCredentialRun,
    ModuleAuditSpec,
    build_basic_audit_plan,
    build_basic_credential_runs,
    command_result_exit_code,
    merge_audit_credential_runs,
    sort_default_audit_credential_runs,
)
from . import actions, policy, render

_DEFAULT_PORT = 27017
_DEFAULT_PORTS: tuple[int, ...] | None = (27017, 27018, 27019)


def build_mongodb_plan(args: Any) -> AuditCommandPlan:
    return build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)


def build_mongodb_spec(args: Any) -> ModuleAuditSpec:
    return ModuleAuditSpec(
        module="mongodb",
        label="MONGODB",
        default_port=_DEFAULT_PORT,
        host_stage=actions.host_stage,
        render_module=render,
        colorize=render._render_colored_mongodb_line,
        # E3 opt-in: MongoDB anon-open (no --auth flag on the server) means
        # the detect probe already listed databases; the defcreds loop only
        # adds redundant round-trips.
        keep_anonymous_open_no_auth=True,
        continue_after_credential_success=bool(getattr(args, "defcreds", False)),
        continue_after_credential_error=bool(getattr(args, "defcreds", False)),
    )


def run_mongodb_stage(args: Any, logger: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    console = Console(debug=cfg.debug)
    if hasattr(console, "set_structured_output"):
        console.set_structured_output(cfg.output_format == "json")
    validation_rc = policy.validate_args(args, console)
    if validation_rc is not None:
        return int(validation_rc)
    # D2 fix: surface parse errors from _group_collection_targets /
    # _parse_document_selector / _parse_json_object / etc. Previously these
    # were bound to a throwaway `_error` and dropped on the floor, so
    # `--collection foo.` or malformed --query silently produced an empty
    # target list and the audit ran as a clean no-op.
    normalize_errors = _normalize_mongodb_action_args(args)
    if normalize_errors:
        for err in normalize_errors:
            console.error(err)
        return 2
    if bool(getattr(args, "nosql_shell", False)):
        _force_single_default_port(args)
    try:
        supplied_runs = build_basic_credential_runs(args)
    except ValueError as exc:
        console.error(str(exc))
        return 2
    default_runs = (
        sort_default_audit_credential_runs(
            AuditCredentialRun(username=username, password=password, source="default")
            for username, password in actions._MONGODB_DEFAULT_CREDS
        )
        if bool(getattr(args, "defcreds", False))
        else ()
    )
    args._audit_credential_runs = merge_audit_credential_runs(supplied_runs, default_runs)
    try:
        plan = build_mongodb_plan(args)
    except ValueError as exc:
        console.error(str(exc))
        return 2
    if bool(getattr(args, "nosql_shell", False)):
        return _run_mongodb_nosql_shell(args, plan, console)
    if cfg.debug and not getattr(args, "debug_emit", None):
        args.debug_emit = console.info
    if cfg.debug:
        suffix = f" format={cfg.output_format}"
        if cfg.output:
            suffix += f" output={args.output}"
        console.info("mongodb audit started:" + suffix)
    runner = AuditCommandRunner(args=args, spec=build_mongodb_spec(args), logger=logger, console=console)
    try:
        result = runner.run_plan(plan)
    except OSError as exc:
        console.error(f"failed to process mongodb output: {exc}")
        return 2
    if cfg.debug and result.detected_count == 0 and hasattr(console, "warn"):
        console.warn("all mongodb targets are unreachable")
    return command_result_exit_code(result)


__all__ = ["build_mongodb_plan", "build_mongodb_spec", "run_mongodb_stage"]


def _force_single_default_port(args: Any) -> None:
    if getattr(args, "port", None) is None and getattr(args, "ports", None) is None:
        args.port = _DEFAULT_PORT


def _run_mongodb_nosql_shell(args: Any, plan: AuditCommandPlan, console: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    try:
        _idx, host, port, _target = plan.require_single_target_spec()
    except ValueError as exc:
        console.error(f"--nosql-shell {exc}")
        return 2
    return actions._run_mongodb_nosql_shell(
        host=str(host),
        port=int(port),
        timeout=cfg.timeout,
        retries=cfg.retries,
        credential_candidates=_mongodb_credential_candidates(plan),
        auth_db=str(getattr(args, "auth_db", None) or "admin"),
        database=getattr(args, "database", None),
        emit_line=console.plain,
        shell_emit_line=console.plain,
        tls=bool(getattr(args, "tls", False)),
        tls_ca=getattr(args, "tls_ca", None),
        tls_cert_key=getattr(args, "tls_cert_key", None),
        tls_insecure=bool(getattr(args, "tls_insecure", False)),
    )


def _mongodb_credential_candidates(plan: AuditCommandPlan) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for credential in plan.credential_runs:
        if credential.username is None:
            continue
        candidates.append(
            {
                "username": credential.username,
                "password": credential.password or "",
                "source": credential.source,
                "default": credential.source == "default",
            }
        )
    return candidates


def _normalize_mongodb_action_args(args: Any) -> list[str]:
    """Normalize CLI args into audit-ready shapes; return any parse errors."""
    errors: list[str] = []
    collections = actions._split_csv_values(
        list(getattr(args, "collections", None) or getattr(args, "collection", None) or [])
    )
    normalized, grouped, error = actions._group_collection_targets(collections, getattr(args, "database", None))
    if error:
        errors.append(error)
    args.collection_targets = normalized
    args.collection_targets_by_database = grouped
    query_raw = getattr(args, "query", None)
    if getattr(args, "document", None):
        selector, _safe, error = actions._parse_document_selector(str(args.document))
        if error:
            errors.append(error)
        args.document_selector = selector
        args.query_filter = {"_id": selector}
    elif query_raw:
        query_filter, error = actions._parse_json_object(str(query_raw), field_name="--query")
        if error:
            errors.append(error)
        args.query_filter = query_filter
    else:
        args.query_filter = None
    projection_raw = getattr(args, "projection", None)
    projection, error = actions._parse_json_object(str(projection_raw or ""), field_name="--projection")
    if error:
        errors.append(error)
    args.projection = projection or None
    args.index_filter = getattr(args, "index", None)
    nosql_raw = getattr(args, "nosql_cmd", None)
    if nosql_raw:
        command, error = actions._parse_json_object(str(nosql_raw), field_name="--nosql-cmd")
        if error:
            errors.append(error)
        args.nosql_command = command
    else:
        args.nosql_command = None
    return errors
