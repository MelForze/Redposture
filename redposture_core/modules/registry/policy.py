"""Policy helpers for the registry audit module."""

from __future__ import annotations

from typing import Any

from ...stage_runtime import validate_basic_module_args


def validate_args(args: Any, console: Any) -> int | None:
    common_rc = validate_basic_module_args(args, console, module="registry")
    if common_rc is not None:
        return common_rc
    if getattr(args, "token", None) and (
        getattr(args, "username", None) is not None or getattr(args, "password", None) is not None
    ):
        console.error("use either --token or --username/--password, not both")
        return 2
    if bool(getattr(args, "show_tags", False)) and not getattr(args, "repository", None):
        console.error("--show-tags requires --repository")
        return 2
    if getattr(args, "tag", None) and not getattr(args, "repository", None):
        console.error("--tag requires --repository")
        return 2
    if bool(getattr(args, "metadata", False)) and (
        not getattr(args, "repository", None) or not getattr(args, "tag", None)
    ):
        console.error("--metadata requires --repository and --tag")
        return 2
    if bool(getattr(args, "assets", False)) and not bool(getattr(args, "nexus", False)):
        console.error("--assets requires --nexus")
        return 2
    if bool(getattr(args, "download", False)) and not getattr(args, "image", None):
        console.error("--download requires --image")
        return 2
    return None


__all__ = ["validate_args"]
