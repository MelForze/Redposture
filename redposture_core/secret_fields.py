"""Shared field semantics for materialized and disk-backed discovery readers."""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Any

_SECRET_KEY_RE = re.compile(
    r"(?i)(?:^|[_\-.])(password|cipassword|passwd|pwd|passphrase|pass|credential|credentials|cred|creds|secret|apisecret|token|api[_-]?key|access[_-]?key|client[_-]?secret|session|cookie|private[_-]?key)(?:$|[_\-.])"
)

_NON_SECRET_FIELD_RE = re.compile(
    r"(?i)(?:(?:^|_)(?:public_key|api_key_id|access_key_id|secret_key_id|token_id|checksum|hash)(?:$|_)|"
    r"(?:^|_)(?:token_name|token_url|token_uri|nmspcuri)$)"
)

_SECRET_METADATA_SUFFIXES = frozenset(
    {"count", "length", "enabled", "name", "type", "endpoint", "policy", "status", "description", "format", "required"}
)

_SECRET_SENTINELS = frozenset(
    {
        "disabled",
        "enabled",
        "false",
        "n/a",
        "nil",
        "none",
        "null",
        "placeholder",
        "redacted",
        "[redacted]",
        "true",
        "<redacted>",
        "<value>",
    }
)

_SECRET_SENTINEL_MASK_RE = re.compile(r"(?:\*{3,}|x{4,})", re.IGNORECASE)

_TEMPLATE_PLACEHOLDER_RE = re.compile(r"(?:\$\{[^}]+\}|\{\{[^}]+\}\})")


def _is_secret_sentinel(value: Any) -> bool:
    """Return whether a value is an explicit non-secret marker."""

    if isinstance(value, bool):
        return True
    text = str(value).strip().casefold()
    return text in _SECRET_SENTINELS or bool(
        _SECRET_SENTINEL_MASK_RE.fullmatch(text) or _TEMPLATE_PLACEHOLDER_RE.fullmatch(text)
    )


def _normalize_secret_key(key: str) -> str:
    """Normalize schema names without retaining long paths or custom strings."""
    if type(key) is str and len(key) <= 128:
        return _cached_normalized_secret_key(key)
    return _uncached_normalized_secret_key(key)


@lru_cache(maxsize=4096)
def _cached_normalized_secret_key(key: str) -> str:
    return _uncached_normalized_secret_key(key)


def _uncached_normalized_secret_key(key: str) -> str:
    """Normalize delimited, camelCase and acronym-based field names."""
    separated = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", key)
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", separated)
    return re.sub(r"[\s.\-]+", "_", separated).lower()


def is_secret_field_name(key: str) -> bool:
    """Whether a mapping key can identify a secret without inspecting its value."""
    normalized = _normalize_secret_key(key)
    return (
        bool(_SECRET_KEY_RE.search(normalized))
        and not bool(_NON_SECRET_FIELD_RE.search(normalized))
        and not is_secret_metadata_field(normalized)
    )


def is_secret_metadata_field(key: str) -> bool:
    """Recognize secret-related metadata, without excluding actual short secrets."""
    normalized = _normalize_secret_key(key)
    prefix, _, suffix = normalized.rpartition("_")
    return suffix in _SECRET_METADATA_SUFFIXES and bool(_SECRET_KEY_RE.search(prefix))


def _key_detector(key: str) -> str:
    lowered = _normalize_secret_key(key)
    if "client_secret" in lowered:
        return "client_secret"
    if (
        "password" in lowered
        or "passwd" in lowered
        or "passphrase" in lowered
        or lowered.endswith(("pwd", "_pass"))
        or lowered == "pass"
    ):
        return "password"
    if "session" in lowered or "cookie" in lowered or lowered == "sid":
        return "session_cookie"
    if "api_key" in lowered or "apikey" in lowered:
        return "api_key"
    if "access_token" in lowered or "refresh_token" in lowered:
        return "access_token"
    return "generic_secret"
