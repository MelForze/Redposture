"""Policy helpers for the ClickHouse Keeper audit module."""

from __future__ import annotations

from typing import Any

from ..zookeeper.policy import validate_zookeeper_protocol_args


def validate_args(args: Any, console: Any) -> int | None:
    common_rc = validate_zookeeper_protocol_args(args, console, module="keeper")
    if common_rc is not None:
        return common_rc
    create_user = getattr(args, "create_user", None)
    password = getattr(args, "create_userpass", None)
    if create_user is None and (password is not None or bool(getattr(args, "grant_admin", False))):
        console.error("--create-userpass and --grant-admin require --create-user")
        return 2
    if create_user is not None and not password:
        console.error("--create-user requires a non-empty --create-userpass")
        return 2
    if bool(getattr(args, "yes", False)) and create_user is None:
        console.error("--yes requires --create-user")
        return 2
    return None


__all__ = ["validate_args"]
