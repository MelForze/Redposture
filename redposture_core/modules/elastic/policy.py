"""Policy helpers for the elastic audit module."""

from __future__ import annotations

from typing import Any

from ...stage_runtime import validate_basic_module_args


def validate_args(args: Any, console: Any) -> int | None:
    return validate_basic_module_args(args, console, module="elastic", pure_http=False)


__all__ = ["validate_args"]
