"""Validate Vault-specific options without exposing tokens in diagnostics."""

from __future__ import annotations

import re
from typing import Any

from ..token_api import validate_token_args


def safe_vault_path(value: Any) -> bool:
    """Validate routing syntax without imposing a client identifier-size cap.

    Vault documents no enforced mount-point length limit. Its HTTP listener
    handles request limits; identifiers must reach it with their exact spelling.
    """
    if not isinstance(value, str):
        return False
    try:
        for offset in range(0, len(value), 65_536):
            value[offset : offset + 65_536].encode("utf-8")
    except UnicodeError:
        return False
    return (
        "//" not in value
        and not any(character in value for character in "\\\r\n\x00?#")
        and re.search(r"(?:^|/)\.{1,2}(?:/|$)", value) is None
    )


def validate_args(args: Any, console: Any) -> int | None:
    result = validate_token_args(args, console, "vault")
    if result is not None:
        return result
    if getattr(args, "mount", None) is not None:
        mount = str(args.mount).strip("/")
        if (
            not mount
            or not safe_vault_path(mount)
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
