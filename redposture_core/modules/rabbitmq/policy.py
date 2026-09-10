"""RabbitMQ argument validation."""

from __future__ import annotations

from typing import Any


def validate_args(args: Any, console: Any) -> int | None:
    user, password = getattr(args, "username", None), getattr(args, "password", None)
    error = None
    if (user is None) != (password is None):
        error = "--username and --password must be supplied together"
    elif user is not None and (not user or ":" in user):
        error = "--username must be non-empty and cannot contain ':' with HTTP Basic auth"
    elif not 1 <= getattr(args, "page_size", 100) <= 500:
        error = "--page-size must be between 1 and 500"
    elif getattr(args, "limit", 1000) < 1:
        error = "--limit must be > 0"
    if error:
        console.error(error)
        return 2
    return None
