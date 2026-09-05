"""Argument validation for the MinIO module."""

from __future__ import annotations

from typing import Any


def validate_args(args: Any, console: Any) -> int | None:
    port = getattr(args, "port", None)
    if isinstance(port, int) and port <= 0:
        console.error("--port must be > 0")
        return 2
    if getattr(args, "session_token", None) and not (
        getattr(args, "username", None) and getattr(args, "password", None)
    ):
        console.error("--session-token requires -u/--username and -p/--password")
        return 2
    return None


__all__ = ["validate_args"]
