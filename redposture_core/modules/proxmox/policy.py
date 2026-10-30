"""Policy helpers for the proxmox audit module."""

from __future__ import annotations

from typing import Any

from ...discovery_options import validate_discovery_budget
from ...stage_runtime import validate_basic_module_args


def validate_args(args: Any, console: Any) -> int | None:
    from ..execution_api import validate as validate_execution

    execution_rc = validate_execution(args, console)
    if execution_rc is not None:
        return execution_rc
    vm = getattr(args, "vm", None)
    if getattr(args, "execute", None) is not None and vm is None:
        console.error("--execute requires --vm ID")
        return 2
    if vm is not None and not 100 <= vm <= 999999999:
        console.error("--vm must be a guest ID between 100 and 999999999")
        return 2
    node = getattr(args, "node", None)
    if node is not None:
        import re

        if not re.fullmatch(r"[A-Za-z0-9_.-]+", node):
            console.error("--node must be a valid Proxmox node name")
            return 2
    common_rc = validate_basic_module_args(args, console, module="proxmox", pure_http=False)
    if common_rc is not None:
        return common_rc
    grant_role = str(getattr(args, "grant_role", "") or "").strip()
    if grant_role and not str(getattr(args, "add_user", "") or "").strip():
        console.error("--grant-role requires --add-user")
        return 2
    grant_path = str(getattr(args, "grant_path", "/") or "").strip()
    if grant_role and not grant_path.startswith("/"):
        console.error("--grant-path must start with /")
        return 2
    return validate_discovery_budget(args, console)


__all__ = ["validate_args"]
