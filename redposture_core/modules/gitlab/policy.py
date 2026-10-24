"""Policy helpers for the gitlab audit module."""

from __future__ import annotations

from typing import Any

from ...discovery_options import validate_discovery_budget
from ...stage_runtime import validate_basic_module_args


def validate_args(args: Any, console: Any) -> int | None:
    if bool(getattr(args, "discover", False)):
        if (budget_error := validate_discovery_budget(args, console)) is not None:
            return budget_error
    return validate_basic_module_args(args, console, module="gitlab", pure_http=False)


__all__ = ["validate_args"]
