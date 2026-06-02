"""Policy helpers for the mongodb audit module."""

from __future__ import annotations

from typing import Any

from ...stage_runtime import validate_basic_module_args
from .actions import _parse_document_selector, _parse_json_object


def validate_args(args: Any, console: Any) -> int | None:
    common_rc = validate_basic_module_args(args, console, module="mongodb", pure_http=False)
    if common_rc is not None:
        return common_rc
    query_raw = getattr(args, "query", None)
    projection_raw = getattr(args, "projection", None)
    nosql_cmd_raw = getattr(args, "nosql_cmd", None)
    document_raw = getattr(args, "document", None)
    collections = list(getattr(args, "collections", None) or getattr(args, "collection", None) or [])
    if query_raw:
        _query, query_error = _parse_json_object(str(query_raw), field_name="--query")
        if query_error:
            console.error(query_error)
            return 2
        if not collections:
            console.error("--query requires --collection")
            return 2
    if projection_raw:
        _projection, projection_error = _parse_json_object(str(projection_raw), field_name="--projection")
        if projection_error:
            console.error(projection_error)
            return 2
    if document_raw:
        if not collections:
            console.error("--document requires --collection")
            return 2
        if query_raw:
            console.error("--document cannot be combined with --query")
            return 2
        _value, _safe, document_error = _parse_document_selector(str(document_raw))
        if document_error:
            console.error(document_error)
            return 2
    if nosql_cmd_raw:
        _command, command_error = _parse_json_object(str(nosql_cmd_raw), field_name="--nosql-cmd")
        if command_error:
            console.error(command_error)
            return 2
    if bool(nosql_cmd_raw) and bool(getattr(args, "nosql_shell", False)):
        console.error("--nosql-cmd cannot be combined with --nosql-shell")
        return 2
    return None


__all__ = ["validate_args"]
