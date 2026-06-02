"""Policy helpers for the zookeeper audit module."""

from __future__ import annotations

from typing import Any

from ...stage_runtime import validate_basic_module_args


def validate_args(args: Any, console: Any) -> int | None:
    common_rc = validate_basic_module_args(args, console, module="zookeeper", pure_http=False)
    if common_rc is not None:
        return common_rc
    max_znodes = getattr(args, "max_znodes", None)
    if max_znodes is not None and int(max_znodes) <= 0:
        console.error("--max-znodes must be > 0")
        return 2
    return None


__all__ = ["validate_args"]
