"""Argument validation for the Airflow module."""

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
    return None


__all__ = ["validate_args"]
