"""Policy helpers for the elastic audit module."""

from __future__ import annotations

from typing import Any

from ...discovery_options import validate_discovery_budget
from ...stage_runtime import validate_basic_module_args


def validate_args(args: Any, console: Any) -> int | None:
    return validate_basic_module_args(args, console, module="elastic", pure_http=False) or validate_discovery_budget(
        args, console
    )


__all__ = ["validate_args"]
