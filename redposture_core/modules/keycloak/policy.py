"""Keycloak argument validation and token loading."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .actions import _MAX_REALMS


def validate_args(args: Any, console: Any) -> int | None:
    token = getattr(args, "token", None)
    token_file = getattr(args, "token_file", None)
    if token_file:
        try:
            token = Path(token_file).read_text(encoding="utf-8").strip()
        except OSError as exc:
            console.error(f"cannot read --token-file: {exc}")
            return 2
    if token_file and not token:
        console.error("--token-file is empty")
        return 2
    if token and ("\n" in token or "\r" in token):
        console.error("token contains a line break")
        return 2
    realms = getattr(args, "realm", None) or []
    if len(realms) > _MAX_REALMS or any(
        not realm or len(realm) > 128 or any(character in realm for character in "/?#\r\n") for realm in realms
    ):
        console.error("--realm requires at most 12 nonempty realm names without URL separators")
        return 2
    args._keycloak_token = token
    if token:
        # The common runtime must see an explicit credential for PR:L CVEs,
        # but never receive the bearer secret in its record serialization.
        args.token = "<redacted>"
    return None


__all__ = ["validate_args"]
