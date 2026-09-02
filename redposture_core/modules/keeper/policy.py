"""Policy helpers for the ClickHouse Keeper audit module."""

from __future__ import annotations

from typing import Any

from ..zookeeper.policy import validate_zookeeper_protocol_args


def validate_args(args: Any, console: Any) -> int | None:
    return validate_zookeeper_protocol_args(args, console, module="keeper")


__all__ = ["validate_args"]
