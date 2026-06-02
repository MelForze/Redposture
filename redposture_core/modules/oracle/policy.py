"""Policy helpers for the oracle audit module."""

from __future__ import annotations

from typing import Any

from ...stage_runtime import validate_basic_module_args


def validate_args(args: Any, console: Any) -> int | None:
    common_rc = validate_basic_module_args(args, console, module="oracle", pure_http=False)
    if common_rc is not None:
        return common_rc
    if getattr(args, "service", None) and getattr(args, "sid", None):
        console.error("--service cannot be combined with --sid")
        return 2
    query = str(getattr(args, "query", "") or "").strip()
    if query and not query.lower().startswith("select"):
        console.error("--query must be a read-only SELECT statement")
        return 2
    for field, option in (("os_write", "--os-write"), ("download", "--download")):
        value = str(getattr(args, field, "") or "").strip()
        if value and ":" not in value:
            console.error(f"{option} must use local:remote or remote:local syntax")
            return 2
    return None


__all__ = ["validate_args"]
