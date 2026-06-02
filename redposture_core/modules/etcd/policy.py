"""Policy helpers for the etcd audit module."""

from __future__ import annotations

from typing import Any

from ...stage_runtime import validate_basic_module_args


def validate_args(args: Any, console: Any) -> int | None:
    return validate_basic_module_args(args, console, module="etcd", pure_http=True)


__all__ = ["validate_args"]
