"""Nomad input validation."""

import uuid
from typing import Any

from ..execution_api import validate
from ..token_api import safe_path, validate_token_args


def validate_args(args: Any, console: Any) -> int | None:
    result = validate_token_args(args, console, "nomad")
    if result is not None:
        return result
    if (result := validate(args, console)) is not None:
        return result
    allocation = getattr(args, "allocation", None)
    task = getattr(args, "task", None)
    if (allocation or task) and not getattr(args, "execute", None):
        console.error("--allocation and --task require --execute")
        return 2
    if task and not allocation:
        console.error("--task requires --allocation")
        return 2
    if allocation:
        try:
            uuid.UUID(allocation)
        except ValueError:
            console.error("--allocation must be a full UUID")
            return 2
    value = getattr(args, "namespace", None)
    if value is not None and (not safe_path(value) or not value or "/" in value):
        console.error("invalid --namespace")
        return 2
    if value == "*" and (getattr(args, "execute", None) or getattr(args, "probe_submit", False)):
        console.error("--execute/--probe-submit requires one explicit namespace, not *")
        return 2
    return None
