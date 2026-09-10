"""Argument validation for the MinIO module."""

from __future__ import annotations

from typing import Any


def validate_args(args: Any, console: Any) -> int | None:
    port = getattr(args, "port", None)
    if isinstance(port, int) and port <= 0:
        console.error("--port must be > 0")
        return 2
    username = getattr(args, "username", None)
    password = getattr(args, "password", None)
    if username is not None and str(username) == "":
        console.error("--username must not be empty")
        return 2
    if username is not None and password is None:
        console.error("--username and --password must be set together: -p/--password is missing")
        return 2
    if username is None and password is not None:
        console.error("--username and --password must be set together: -u/--username is missing")
        return 2
    if getattr(args, "session_token", None) and not (username and password):
        console.error("--session-token requires -u/--username and -p/--password")
        return 2
    bucket = getattr(args, "bucket", None)
    obj = getattr(args, "object", None)
    if bucket and obj:
        console.error("--bucket and --object are mutually exclusive; specify one")
        return 2
    if (getattr(args, "dump", False) or getattr(args, "download", False)) and not (bucket or obj):
        console.error("--dump/--download require --object bucket/key or --bucket name")
        return 2
    return None


__all__ = ["validate_args"]
