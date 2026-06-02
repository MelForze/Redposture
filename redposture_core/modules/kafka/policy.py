"""Policy helpers for the kafka audit module."""

from __future__ import annotations

from typing import Any

from ...stage_runtime import validate_basic_module_args


def validate_args(args: Any, console: Any) -> int | None:
    common_rc = validate_basic_module_args(args, console, module="kafka", pure_http=False)
    if common_rc is not None:
        return common_rc
    max_messages = getattr(args, "max_messages", None)
    if max_messages is not None and int(max_messages) <= 0:
        console.error("--max-messages must be > 0")
        return 2
    return None


__all__ = ["validate_args"]
