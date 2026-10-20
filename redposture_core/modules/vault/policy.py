"""Validate Vault-specific options without exposing tokens in diagnostics."""

from __future__ import annotations

from typing import Any

from ..token_api import safe_path, validate_token_args


def validate_args(args: Any, console: Any) -> int | None:
    result = validate_token_args(args, console, "vault")
    if result is not None:
        return result
    if getattr(args, "mount", None) is not None:
        mount = str(args.mount).strip("/")
        if (
            not mount
            or not safe_path(mount)
            or any(segment in {".", "..", ""} for segment in mount.split("/"))
            or any(character in mount for character in "?#\r\n")
        ):
            console.error("--mount requires a nonempty Vault path without traversal or URL separators")
            return 2
        args.mount = mount + "/"
        if not bool(getattr(args, "discover", False)):
            console.error("--mount requires --discover")
            return 2
    return None


__all__ = ["validate_args"]
