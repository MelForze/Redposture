"""Nomad input validation."""

import uuid
from typing import Any

from ..execution_api import validate, validate_os_shell
from ..token_api import safe_path, validate_token_args


def validate_args(args: Any, console: Any) -> int | None:
    result = validate_token_args(args, console, "nomad")
    if result is not None:
        return result
    if (result := validate(args, console)) is not None:
        return result
    if (
        result := validate_os_shell(
            args,
            console,
            forbidden=(
                "show_jobs",
                "show_allocations",
                "show_nodes",
                "show_members",
                "show_agents",
                "show_variables",
                "show_deployments",
                "probe_submit",
                "discover",
                "enum_cve",
            ),
        )
    ) is not None:
        return result
    allocation = getattr(args, "allocation", None)
    task = getattr(args, "task", None)
    if (allocation or task) and not (getattr(args, "execute", None) or getattr(args, "os_shell", False)):
        console.error("--allocation and --task require --execute or --os-shell")
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
    if value == "*" and (
        getattr(args, "execute", None) or getattr(args, "os_shell", False) or getattr(args, "probe_submit", False)
    ):
        console.error("--execute/--probe-submit requires one explicit namespace, not *")
        return 2
    return None
