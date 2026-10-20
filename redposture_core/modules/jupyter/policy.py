"""Jupyter input validation."""

from typing import Any

from ..execution_api import validate
from ..token_api import safe_path, validate_token_args


def validate_args(args: Any, console: Any) -> int | None:
    result = validate_token_args(args, console, "jupyter")
    if result is not None:
        return result
    if (result := validate(args, console)) is not None:
        return result
    kernel = getattr(args, "kernel", "python3")
    if not kernel or not safe_path(kernel) or "/" in kernel:
        console.error("invalid --kernel")
        return 2
    value = getattr(args, "path", None)
    if value is not None and (not safe_path(value) or value.startswith("/")):
        console.error("invalid --path")
        return 2
    return None
