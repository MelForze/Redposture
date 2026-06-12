"""Runtime entrypoint for the mongodb audit module."""

from __future__ import annotations

from typing import Any

from ...console import Console
from ...stage_runtime import (
    AuditCommandPlan,
    AuditCommandRunner,
    ModuleAuditSpec,
    build_basic_audit_plan,
)
from . import actions, policy, render

_DEFAULT_PORT = 27017
_DEFAULT_PORTS = None


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
    )


def run_mongodb_stage(args: Any, logger: Any) -> int:
    console = Console(debug=bool(getattr(args, "debug", False)))
    validation_rc = policy.validate_args(args, console)
    if validation_rc is not None:
        return int(validation_rc)
    _normalize_mongodb_action_args(args)
    try:
        plan = build_mongodb_plan(args)
    except ValueError as exc:
        console.error(str(exc))
        return 2
    if bool(getattr(args, "debug", False)) and not getattr(args, "debug_emit", None):
        args.debug_emit = console.info
    if bool(getattr(args, "debug", False)):
        suffix = f" format={getattr(args, 'output_format', 'txt') or 'txt'}"
        if getattr(args, "output", None):
            suffix += f" output={args.output}"
        console.info("mongodb audit started:" + suffix)
    runner = AuditCommandRunner(args=args, spec=build_mongodb_spec(args), logger=logger, console=console)
    try:
        result = runner.run_plan(plan)
    except OSError as exc:
        console.error(f"failed to process mongodb output: {exc}")
        return 2
    if bool(getattr(args, "debug", False)) and result.detected_count == 0 and hasattr(console, "warn"):
        console.warn("all mongodb targets are unreachable")
    return 0


__all__ = ["build_mongodb_plan", "build_mongodb_spec", "run_mongodb_stage"]


def _normalize_mongodb_action_args(args: Any) -> None:
    collections = actions._split_csv_values(
        list(getattr(args, "collections", None) or getattr(args, "collection", None) or [])
    )
    normalized, grouped, _error = actions._group_collection_targets(collections, getattr(args, "database", None))
    args.collection_targets = normalized
    args.collection_targets_by_database = grouped
    query_raw = getattr(args, "query", None)
    if getattr(args, "document", None):
        selector, _safe, _error = actions._parse_document_selector(str(args.document))
        args.document_selector = selector
        args.query_filter = {"_id": selector}
    elif query_raw:
        query_filter, _error = actions._parse_json_object(str(query_raw), field_name="--query")
        args.query_filter = query_filter
    else:
        args.query_filter = None
    projection_raw = getattr(args, "projection", None)
    projection, _error = actions._parse_json_object(str(projection_raw or ""), field_name="--projection")
    args.projection = projection or None
    args.index_filter = getattr(args, "index", None)
    nosql_raw = getattr(args, "nosql_cmd", None)
    if nosql_raw:
        command, _error = actions._parse_json_object(str(nosql_raw), field_name="--nosql-cmd")
        args.nosql_command = command
    else:
        args.nosql_command = None
