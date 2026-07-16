"""Policy helpers for the grpc audit module."""

from __future__ import annotations

from typing import Any

from ...stage_runtime import validate_basic_module_args
from . import actions


def validate_args(args: Any, console: Any) -> int | None:
    common_rc = validate_basic_module_args(args, console, module="grpc", pure_http=False)
    if common_rc is not None:
        return common_rc

    invoke_path = str(getattr(args, "invoke", "") or "").strip()
    try:
        metadata = actions._parse_metadata_items(getattr(args, "meta", None))
    except ValueError as exc:
        console.error(str(exc))
        return 2
    args._grpc_metadata = metadata
    if getattr(args, "data", None) is not None and not invoke_path:
        console.error("--data requires --invoke")
        return 2
    if metadata and not invoke_path:
        console.error("--meta requires --invoke")
        return 2
    if getattr(args, "proto_path", None) and not getattr(args, "proto", None):
        console.error("--proto-path requires --proto")
        return 2
    return None


__all__ = ["validate_args"]
