"""Policy helpers for the grpc audit module."""

from __future__ import annotations

from typing import Any

from ...stage_runtime import validate_basic_module_args


def validate_args(args: Any, console: Any) -> int | None:
    return validate_basic_module_args(args, console, module="grpc", pure_http=False)


__all__ = ["validate_args"]
