"""Jenkins argument validation."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def validate_args(args: Any, console: Any) -> int | None:
    token = getattr(args, "api_token", None)
    token_file = getattr(args, "api_token_file", None)
    if token_file:
        try:
            token = Path(token_file).read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError) as exc:
            console.error(f"cannot read --api-token-file: {exc}")
            return 2
    if token_file and not token:
        console.error("--api-token-file is empty")
        return 2
    if getattr(args, "api_token", None) is not None and not str(token).strip():
        console.error("--api-token is empty")
        return 2
    if token and (not getattr(args, "username", None) or getattr(args, "password", None) is not None):
        console.error("--api-token requires -u and cannot be combined with -p")
        return 2
    if token and any(char in token for char in "\r\n"):
        console.error("API token contains a line break")
        return 2
    if not token and (getattr(args, "username", None) is None) != (getattr(args, "password", None) is None):
        console.error("Jenkins password authentication requires both -u and -p")
        return 2
    args._jenkins_api_token = token
    return None


__all__ = ["validate_args"]
