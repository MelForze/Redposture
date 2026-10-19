"""Validate captured MySQL native-password challenges for offline audit."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Iterable
from typing import Any


def mysql_native_scramble(password: str, salt: bytes) -> bytes:
    """Compute the 20-byte mysql_native_password client response."""
    stage1 = hashlib.sha1(password.encode("utf-8")).digest()
    stage2 = hashlib.sha1(stage1).digest()
    challenge = hashlib.sha1(salt + stage2).digest()
    return bytes(left ^ right for left, right in zip(stage1, challenge, strict=True))


def mysql_native_hashcat(event: dict[str, Any]) -> str | None:
    """Return hashcat mode 11200 material only for a complete native capture."""
    if event.get("service") != "mysql" or event.get("auth_plugin") != "mysql_native_password":
        return None
    salt = event.get("auth_salt")
    response = event.get("auth_response")
    if not isinstance(salt, str) or not isinstance(response, str):
        return None
    if len(salt) != 40 or len(response) != 40:
        return None
    try:
        if len(bytes.fromhex(salt)) != 20 or len(bytes.fromhex(response)) != 20:
            return None
    except ValueError:
        return None
    return f"$mysqlna${salt.lower()}*{response.lower()}"


def check_mysql_native_weak_password(event: dict[str, Any], candidates: Iterable[str]) -> str | None:
    """Check only the explicitly supplied, bounded candidate sequence."""
    hash_line = mysql_native_hashcat(event)
    if hash_line is None:
        return None
    salt_hex, response_hex = hash_line.removeprefix("$mysqlna$").split("*", 1)
    salt, response = bytes.fromhex(salt_hex), bytes.fromhex(response_hex)
    for password in candidates:
        if hmac.compare_digest(mysql_native_scramble(password, salt), response):
            return password
    return None
