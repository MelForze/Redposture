"""Validation value quality and context helpers."""

from __future__ import annotations

import re
from typing import Any

_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b")
_SENSITIVE_KEY_TOKENS = (
    "password",
    "passwd",
    "passphrase",
    "pwd",
    "secret",
    "token",
    "authtoken",
    "securitytoken",
    "apikey",
    "accesskey",
    "secretkey",
    "accesskeyid",
    "secretaccesskey",
    "accesstoken",
    "refreshtoken",
    "idtoken",
    "sessiontoken",
    "bearertoken",
    "clientsecret",
    "oauthsecret",
    "signingkey",
    "privatetoken",
    "privatekey",
    "tlskey",
    "sshkey",
    "masterauth",
    "requirepass",
    "saslpassword",
    "credentials",
)

_URL_SENSITIVE_QUERY_KEYS = (
    "password",
    "passwd",
    "passphrase",
    "pwd",
    "secret",
    "token",
    "apikey",
    "accesstoken",
    "refreshtoken",
    "clientsecret",
    "sessiontoken",
    "idtoken",
    "securitytoken",
    "signature",
    "sig",
    "auth",
    "credential",
)

_USERNAME_KEY_TOKENS = (
    "username",
    "login",
    "principal",
    "userid",
    "sasluser",
    "dbuser",
)

_USERNAME_EXCLUDE_TOKENS = ("useragent",)

_CONNECTION_KEY_TOKENS = (
    "uri",
    "url",
    "dsn",
    "connstr",
    "connection",
    "connectionstring",
    "datasourcename",
    "targetdsn",
    "scrapeuri",
    "endpoint",
    "address",
    "addr",
    "esuri",
    "mongodburi",
    "rabbiturl",
    "sqlalchemyurl",
    "jdbcurl",
    "server",
    "hostname",
    "dbname",
    "database",
    "instance",
    "service",
    "socket",
)

_KNOWN_DEFAULT_CREDENTIAL_PAIRS = {
    ("elastic", "password"),
    ("postgres", "postgres"),
    ("root", "root"),
    ("guest", "guest"),
    ("default", ""),
    ("default", "default"),
}

_CONNECTION_CONTEXT_KEYS = {
    "host",
    "hostname",
    "server",
    "addr",
    "address",
    "port",
    "database",
    "dbname",
    "service",
    "socket",
    "instance",
}

_NON_SECRET_LITERALS = {
    "-",
    "<empty>",
    "<none>",
    "none",
    "null",
    "n/a",
    "na",
    "false",
    "true",
    "on",
    "off",
    "yes",
    "no",
    "enabled",
    "disabled",
}
VALIDATION_PRECISION_LEGACY = "legacy"
VALIDATION_PRECISION_COLLECT_STRICT = "collect_strict"
_VALIDATION_PRECISION_PROFILES = {
    VALIDATION_PRECISION_LEGACY,
    VALIDATION_PRECISION_COLLECT_STRICT,
}
_PLACEHOLDER_VALUE_PATTERNS = (
    re.compile(r"^\$[A-Za-z_][A-Za-z0-9_]*$"),
    re.compile(r"^\$\{[A-Za-z_][A-Za-z0-9_]*\}$"),
    re.compile(r"^\$\([^)]+\)$"),
    re.compile(r"^%[A-Za-z_][A-Za-z0-9_]*%$"),
    re.compile(r"^<[A-Za-z_][A-Za-z0-9_]*>$"),
    re.compile(r"^\{\{[^{}]+\}\}$"),
)
_DUMMY_SECRET_TOKENS = {
    "changeme",
    "password",
    "passwd",
    "secret",
    "token",
    "example",
    "dummy",
    "placeholder",
    "sample",
    "test",
    "demo",
    "yourpassword",
    "yoursecret",
    "yourtoken",
}
_TOKEN_KEY_TOKENS = (
    "token",
    "apikey",
    "accesstoken",
    "refreshtoken",
    "idtoken",
    "sessiontoken",
    "auth",
    "authorization",
    "bearer",
    "serviceaccount",
    "privatekey",
)
_TOKEN_LIKE_VALUE_RE = re.compile(r"^[A-Za-z0-9._~+/=-]+$")
_HEX_TOKEN_RE = re.compile(r"^[A-Fa-f0-9]{20,}$")
_BASE64URLISH_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{20,}$")


def _normalize_precision_profile(profile: str | None) -> str:
    text = str(profile or "").strip().lower()
    if text in _VALIDATION_PRECISION_PROFILES:
        return text
    return VALIDATION_PRECISION_LEGACY


def _bump_suppressed_value_counter(
    counters: dict[str, int] | None,
    key: str,
) -> None:
    if counters is None:
        return
    counters[key] = int(counters.get(key, 0)) + 1


def _normalize_key_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _is_empty_or_masked(value: Any) -> bool:
    text = str(value if value is not None else "").strip().strip(",;")
    if text == "":
        return True
    lowered = text.lower()
    if lowered in _NON_SECRET_LITERALS:
        return True
    if set(text) <= {"*", "x", "X", "."} and len(text) >= 3:
        return True
    return False


def _clean_value_text(value: Any) -> str:
    text = str(value if value is not None else "").strip()
    while text and text[-1] in {",", ";", ")", "]"}:
        text = text[:-1].strip()
    if len(text) >= 2 and (
        (text.startswith('"') and text.endswith('"')) or (text.startswith("'") and text.endswith("'"))
    ):
        text = text[1:-1].strip()
    while text and text[0] in {'"', "'", "(", "["}:
        text = text[1:].strip()
    while text and text[-1] in {'"', "'"}:
        text = text[:-1].strip()
    return text


def _normalize_dummy_secret_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.strip().lower())


def _is_placeholder_value(value: Any) -> bool:
    text = _clean_value_text(value)
    if not text:
        return False
    return any(pattern.fullmatch(text) for pattern in _PLACEHOLDER_VALUE_PATTERNS)


def _is_dummy_secret_value(value: Any) -> bool:
    text = _clean_value_text(value)
    if not text:
        return False
    return _normalize_dummy_secret_token(text) in _DUMMY_SECRET_TOKENS


def _key_looks_token_like(key: str) -> bool:
    normalized = _normalize_key_token(key)
    if not normalized:
        return False
    return any(token in normalized for token in _TOKEN_KEY_TOKENS)


def _token_value_quality_ok(value: Any) -> bool:
    text = _clean_value_text(value)
    if not text:
        return False
    if _JWT_RE.fullmatch(text):
        return True
    if len(text) < 16:
        return False
    if _HEX_TOKEN_RE.fullmatch(text):
        return True
    if _BASE64URLISH_TOKEN_RE.fullmatch(text):
        return True
    if not _TOKEN_LIKE_VALUE_RE.fullmatch(text):
        return False
    has_lower = any(ch.islower() for ch in text)
    has_upper = any(ch.isupper() for ch in text)
    has_digit = any(ch.isdigit() for ch in text)
    has_symbol = any(not ch.isalnum() for ch in text)
    class_count = sum(1 for flag in (has_lower, has_upper, has_digit, has_symbol) if flag)
    if class_count >= 3:
        return True
    if class_count >= 2 and has_symbol and len(text) >= 20:
        return True
    return False


def _value_looks_secret(
    value: Any,
    *,
    precision_profile: str = VALIDATION_PRECISION_LEGACY,
    suppressed_value_counters: dict[str, int] | None = None,
) -> bool:
    profile = _normalize_precision_profile(precision_profile)
    if isinstance(value, bool):
        if profile == VALIDATION_PRECISION_COLLECT_STRICT:
            _bump_suppressed_value_counter(suppressed_value_counters, "suppressed_non_secret_values")
        return False
    if isinstance(value, (int, float)):
        if profile == VALIDATION_PRECISION_COLLECT_STRICT:
            _bump_suppressed_value_counter(suppressed_value_counters, "suppressed_non_secret_values")
        return False
    text = _clean_value_text(value)
    if _is_empty_or_masked(text):
        if profile == VALIDATION_PRECISION_COLLECT_STRICT:
            _bump_suppressed_value_counter(suppressed_value_counters, "suppressed_non_secret_values")
        return False
    if len(text) < 3:
        if profile == VALIDATION_PRECISION_COLLECT_STRICT:
            _bump_suppressed_value_counter(suppressed_value_counters, "suppressed_non_secret_values")
        return False
    if profile == VALIDATION_PRECISION_COLLECT_STRICT:
        if _is_placeholder_value(text):
            _bump_suppressed_value_counter(suppressed_value_counters, "suppressed_placeholders")
            return False
        if _is_dummy_secret_value(text):
            _bump_suppressed_value_counter(suppressed_value_counters, "suppressed_dummy_values")
            return False
    return True


def _value_looks_secret_for_key(
    key: str,
    value: Any,
    *,
    precision_profile: str = VALIDATION_PRECISION_LEGACY,
    suppressed_value_counters: dict[str, int] | None = None,
) -> bool:
    if not _value_looks_secret(
        value,
        precision_profile=precision_profile,
        suppressed_value_counters=suppressed_value_counters,
    ):
        return False
    profile = _normalize_precision_profile(precision_profile)
    if profile != VALIDATION_PRECISION_COLLECT_STRICT:
        return True
    if not _key_looks_token_like(key):
        return True
    if _token_value_quality_ok(value):
        return True
    _bump_suppressed_value_counter(suppressed_value_counters, "suppressed_non_secret_values")
    return False


def _value_looks_token_secret(
    value: Any,
    *,
    precision_profile: str = VALIDATION_PRECISION_LEGACY,
    suppressed_value_counters: dict[str, int] | None = None,
) -> bool:
    if not _value_looks_secret(
        value,
        precision_profile=precision_profile,
        suppressed_value_counters=suppressed_value_counters,
    ):
        return False
    profile = _normalize_precision_profile(precision_profile)
    if profile != VALIDATION_PRECISION_COLLECT_STRICT:
        return True
    if _token_value_quality_ok(value):
        return True
    _bump_suppressed_value_counter(suppressed_value_counters, "suppressed_non_secret_values")
    return False


def _value_looks_identifier(value: Any) -> bool:
    text = _clean_value_text(value)
    if _is_empty_or_masked(text):
        return False
    return bool(text)


def _key_looks_sensitive(key: str) -> bool:
    normalized = _normalize_key_token(key)
    if not normalized:
        return False
    return any(token in normalized for token in _SENSITIVE_KEY_TOKENS)


def _key_looks_username(key: str) -> bool:
    normalized = _normalize_key_token(key)
    if not normalized:
        return False
    if any(token in normalized for token in _USERNAME_EXCLUDE_TOKENS):
        return False
    if any(token in normalized for token in _USERNAME_KEY_TOKENS):
        return True
    return normalized.endswith("user") or normalized.endswith("account")


def _key_looks_connection(key: str) -> bool:
    normalized = _normalize_key_token(key)
    if not normalized:
        return False
    return any(token in normalized for token in _CONNECTION_KEY_TOKENS)


def _maybe_add_reason(reasons: list[str], reason: str) -> None:
    if reason and reason not in reasons:
        reasons.append(reason)


def _is_known_default_pair(username: Any, password: Any) -> bool:
    user_text = _clean_value_text(username).lower()
    password_text = _clean_value_text(password).lower()
    if not user_text:
        return False
    return (user_text, password_text) in _KNOWN_DEFAULT_CREDENTIAL_PAIRS


def _context_tokens_present(sample: str, tokens: tuple[str, ...]) -> list[str]:
    lowered = str(sample or "").lower()
    if not lowered:
        return []
    found: list[str] = []
    for token in tokens:
        if token in lowered and token not in found:
            found.append(token)
    return found


__all__ = [name for name in globals() if name.startswith("_") or name.startswith("VALIDATION_PRECISION_")]
