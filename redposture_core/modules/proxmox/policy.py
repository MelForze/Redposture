"""Policy helpers for the proxmox audit module."""

from __future__ import annotations

from typing import Any

from ...stage_runtime import validate_basic_module_args


def validate_args(args: Any, console: Any) -> int | None:
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
    return None


__all__ = ["validate_args"]
