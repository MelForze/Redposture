"""Validation parsers and vulnerable credential extraction helpers."""

from __future__ import annotations

import base64
import binascii
import json
import re
import shlex
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

from .context import (
    _CONNECTION_CONTEXT_KEYS,
    _URL_SENSITIVE_QUERY_KEYS,
    VALIDATION_PRECISION_COLLECT_STRICT,
    VALIDATION_PRECISION_LEGACY,
    _clean_value_text,
    _is_dummy_secret_value,
    _is_known_default_pair,
    _is_placeholder_value,
    _key_looks_connection,
    _key_looks_sensitive,
    _key_looks_username,
    _maybe_add_reason,
    _normalize_key_token,
    _normalize_precision_profile,
    _value_looks_identifier,
    _value_looks_secret,
    _value_looks_secret_for_key,
    _value_looks_token_secret,
)
from .scoring import (
    _has_medium_signal,
    _is_strong_signal,
    _split_reason_signals,
)

# key=value / key: value for secret-looking keys (quoted/unquoted keys/values)
_TEXT_KV_RE = re.compile(
    r"(?i)[\"']?((?:[A-Za-z_][A-Za-z0-9_.-]*)?(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|secret[_-]?key|session[_-]?token|id[_-]?token|auth[_-]?token|bearer[_-]?token))[\"']?\s*[:=]\s*([^\s,;]+)"
)
_TEXT_GENERIC_KV_RE = re.compile(r"(?i)[\"']?([A-Za-z_][A-Za-z0-9_.-]*)[\"']?\s*[:=]\s*(\"[^\"]*\"|'[^']*'|[^\s,;]+)")
_CMD_FLAG_SECRET_RE = re.compile(
    r"(?i)(?:^|\s)(?:--|-D|/)?((?:[A-Za-z_][A-Za-z0-9_.-]*)?(?:password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|client[_-]?secret|session[_-]?token|id[_-]?token|auth[_-]?token|bearer[_-]?token|access[_-]?key|secret[_-]?key))\s*(?:=|\s)\s*(\"[^\"]+\"|'[^']+'|[^\s,;]+)"
)
_CMD_FLAG_GENERIC_RE = re.compile(
    r"(?i)(?:^|\s)(?:--|-D|/)([A-Za-z_][A-Za-z0-9_.-]*)\s*(?:=|:|\s)\s*(\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_URL_CANDIDATE_RE = re.compile(r"(?i)\b[a-z][a-z0-9+.-]{1,31}://[^\s\"'<>]+")
_AUTH_BASIC_RE = re.compile(r"(?i)\bauthorization\s*[:=]\s*basic\s+([A-Za-z0-9+/=]{8,})")
_AUTH_BEARER_RE = re.compile(r"(?i)\bauthorization\s*[:=]\s*bearer\s+([A-Za-z0-9._~+/-]{10,})")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b")
_PEM_PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_REDIS_PASS_RE = re.compile(r"(?i)\b(requirepass|masterauth)\s+([^\s]+)")
_MYSQL_STYLE_DSN_RE = re.compile(r"(?i)\b([A-Za-z0-9._-]+):([^@\s]+)@(?:tcp|unix)\([^)]+\)/(?:[^\s;]+)")
_SEMI_DSN_PAIR_RE = re.compile(r"(?i)(?:^|;)\s*([A-Za-z][A-Za-z0-9_ .-]*)\s*=\s*(\"[^\"]*\"|'[^']*'|[^;]+)")
_SPACE_DSN_PAIR_RE = re.compile(r"(?i)\b([A-Za-z][A-Za-z0-9_ .-]*)=(\"[^\"]*\"|'[^']*'|[^\s;]+)")
_PORT_PREFIX_RE = re.compile(r"^(\d+)_")
_METRIC_NAME_RE = re.compile(r"^[A-Za-z_:][A-Za-z0-9_:]*$")
_METRIC_LABEL_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)="((?:[^"\\]|\\.)*)"')
_QUERY_LABEL_KEYS = {"query", "statement", "sql"}
_SUPPRESS_SQL_METRIC_QUERY_RE = re.compile(
    r'(?is)\bpg_stat[a-z0-9_]*\b.*\bquery\s*=\s*"[^"]*\b(?:passwd|password)\b[^"]*\bfrom\b[^"]*"'
)
_EXPLICIT_SECRET_ASSIGN_RE = re.compile(r"(?i)\b(?:passwd|password|pwd|secret|token)\s*[:=]\s*[^\s,;\"']+")
_DEFAULT_VALIDATE_SUPPRESS_RULES = (
    {
        "id": "pg_stat_query_passwd_from_noise",
        "exporter": "postgres_exporter",
        "endpoint": "/metrics",
        "signals_any": {"flag_passwd", "flag_password", "passwd=value", "password=value"},
        "sample_re": _SUPPRESS_SQL_METRIC_QUERY_RE,
    },
)
_VALIDATE_TEXT_HINT_TOKENS = (
    "[cred]",
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "access_key",
    "secret_key",
    "authorization",
    "bearer",
    "basic",
    "requirepass",
    "masterauth",
    "private key",
    "data_source_name",
    "dsn",
    "jdbc:",
    "uri=",
    "url=",
    "@tcp(",
    "@unix(",
)


def _connection_reason(connection_context: str) -> str:
    return "cmd_connection_string_auth" if connection_context == "cmd" else "connection_string_auth"


def _connection_query_reason(connection_context: str) -> str:
    return "cmd_connection_string_query_secret" if connection_context == "cmd" else "connection_string_query_secret"


def _safe_decode_basic(value: str) -> str | None:
    token = value.strip()
    if not token:
        return None
    padding = "=" * ((4 - (len(token) % 4)) % 4)
    try:
        raw = base64.b64decode(token + padding, validate=False)
    except (binascii.Error, ValueError):
        return None
    decoded = raw.decode("utf-8", errors="replace")
    return decoded if decoded else None


def _analyze_url_candidate(
    candidate: str,
    *,
    connection_context: str | None = None,
    precision_profile: str = VALIDATION_PRECISION_LEGACY,
    suppressed_value_counters: dict[str, int] | None = None,
) -> list[str]:
    reasons: list[str] = []
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return reasons

    username = parsed.username
    password = parsed.password or ""
    if username and (
        _value_looks_secret(
            password,
            precision_profile=precision_profile,
            suppressed_value_counters=suppressed_value_counters,
        )
        or _is_known_default_pair(username, password)
    ):
        if connection_context == "cmd":
            _maybe_add_reason(reasons, _connection_reason("cmd"))
        elif connection_context == "connection":
            _maybe_add_reason(reasons, _connection_reason("connection"))
        else:
            _maybe_add_reason(reasons, "url_basic_auth")
            _maybe_add_reason(reasons, "url_basic_auth_username")
        if _is_known_default_pair(username, password):
            _maybe_add_reason(reasons, "default_creds_known_pair")

    if parsed.query:
        try:
            query_items = parse_qsl(parsed.query, keep_blank_values=True)
        except ValueError:
            query_items = []
        found_secret_query = False
        query_user_values: list[str] = []
        query_password_values: list[str] = []
        for key, value in query_items:
            normalized = _normalize_key_token(key)
            if any(token in normalized for token in _URL_SENSITIVE_QUERY_KEYS) and _value_looks_secret_for_key(
                key,
                value,
                precision_profile=precision_profile,
                suppressed_value_counters=suppressed_value_counters,
            ):
                if connection_context == "cmd":
                    _maybe_add_reason(reasons, _connection_query_reason("cmd"))
                elif connection_context == "connection":
                    _maybe_add_reason(reasons, _connection_query_reason("connection"))
                else:
                    _maybe_add_reason(reasons, f"url_query_{key.lower()}")
                found_secret_query = True
                query_password_values.append(value)
            if _key_looks_username(key) and _value_looks_identifier(value):
                query_user_values.append(value)
        if found_secret_query:
            for key, value in query_items:
                if _key_looks_username(key) and _value_looks_secret_for_key(
                    key,
                    value,
                    precision_profile=precision_profile,
                    suppressed_value_counters=suppressed_value_counters,
                ):
                    _maybe_add_reason(reasons, f"url_query_{key.lower()}")
            for query_user in query_user_values:
                for query_password in query_password_values:
                    if _is_known_default_pair(query_user, query_password):
                        _maybe_add_reason(reasons, "default_creds_known_pair")
                        break
    return reasons


def _detect_url_based_hits(
    text: str,
    *,
    connection_context: str | None = None,
    precision_profile: str = VALIDATION_PRECISION_LEGACY,
    suppressed_value_counters: dict[str, int] | None = None,
) -> list[str]:
    reasons: list[str] = []
    for match in _URL_CANDIDATE_RE.finditer(text):
        for reason in _analyze_url_candidate(
            match.group(0),
            connection_context=connection_context,
            precision_profile=precision_profile,
            suppressed_value_counters=suppressed_value_counters,
        ):
            _maybe_add_reason(reasons, reason)
    return reasons


def _kv_pairs_from_text(text: str, pattern: re.Pattern[str]) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for match in pattern.finditer(text):
        key = str(match.group(1) or "").strip()
        value = _clean_value_text(str(match.group(2) or ""))
        if not key or not value:
            continue
        pairs.append((key, value))
    return pairs


def _detect_kv_connection_string_hits(
    text: str,
    *,
    connection_context: str,
    precision_profile: str = VALIDATION_PRECISION_LEGACY,
    suppressed_value_counters: dict[str, int] | None = None,
) -> list[str]:
    reasons: list[str] = []
    semicolon_pairs = _kv_pairs_from_text(text, _SEMI_DSN_PAIR_RE)
    space_pairs = _kv_pairs_from_text(text, _SPACE_DSN_PAIR_RE)
    pairs = semicolon_pairs if len(semicolon_pairs) >= len(space_pairs) else space_pairs
    if not pairs:
        return reasons

    usernames: list[str] = []
    passwords: list[str] = []
    has_connection_context = "://" in text or "jdbc:" in text.lower()

    for key, value in pairs:
        normalized = _normalize_key_token(key)
        if normalized in _CONNECTION_CONTEXT_KEYS or _key_looks_connection(key):
            has_connection_context = True
        if _key_looks_username(key) and _value_looks_identifier(value):
            usernames.append(value)
        if _key_looks_sensitive(key) and (
            _value_looks_secret_for_key(
                key,
                value,
                precision_profile=precision_profile,
                suppressed_value_counters=suppressed_value_counters,
            )
            or value == ""
        ):
            passwords.append(value)

    if not has_connection_context or not usernames or not passwords:
        return reasons

    _maybe_add_reason(reasons, _connection_reason(connection_context))
    for username in usernames:
        for password in passwords:
            if _is_known_default_pair(username, password):
                _maybe_add_reason(reasons, "default_creds_known_pair")
                return reasons
    return reasons


def _detect_mysql_style_dsn_hits(
    text: str,
    *,
    connection_context: str,
    precision_profile: str = VALIDATION_PRECISION_LEGACY,
    suppressed_value_counters: dict[str, int] | None = None,
) -> list[str]:
    reasons: list[str] = []
    for match in _MYSQL_STYLE_DSN_RE.finditer(text):
        username = _clean_value_text(match.group(1))
        password = _clean_value_text(match.group(2))
        if not username or not (
            _value_looks_secret(
                password,
                precision_profile=precision_profile,
                suppressed_value_counters=suppressed_value_counters,
            )
            or _is_known_default_pair(username, password)
        ):
            continue
        _maybe_add_reason(reasons, _connection_reason(connection_context))
        if _is_known_default_pair(username, password):
            _maybe_add_reason(reasons, "default_creds_known_pair")
    return reasons


def _detect_connection_value_hits(
    value: Any,
    *,
    from_flag: bool,
    precision_profile: str = VALIDATION_PRECISION_LEGACY,
    suppressed_value_counters: dict[str, int] | None = None,
) -> list[str]:
    cleaned = _clean_value_text(value)
    if not cleaned:
        return []
    context = "cmd" if from_flag else "connection"
    reasons = _detect_url_based_hits(
        cleaned,
        connection_context=context,
        precision_profile=precision_profile,
        suppressed_value_counters=suppressed_value_counters,
    )
    for reason in _detect_mysql_style_dsn_hits(
        cleaned,
        connection_context=context,
        precision_profile=precision_profile,
        suppressed_value_counters=suppressed_value_counters,
    ):
        _maybe_add_reason(reasons, reason)
    for reason in _detect_kv_connection_string_hits(
        cleaned,
        connection_context=context,
        precision_profile=precision_profile,
        suppressed_value_counters=suppressed_value_counters,
    ):
        _maybe_add_reason(reasons, reason)
    if reasons:
        return reasons
    if cleaned.lower().startswith("jdbc:"):
        jdbc_inner = cleaned[5:]
        for reason in _detect_url_based_hits(
            jdbc_inner,
            connection_context=context,
            precision_profile=precision_profile,
            suppressed_value_counters=suppressed_value_counters,
        ):
            _maybe_add_reason(reasons, reason)
        for reason in _detect_kv_connection_string_hits(
            jdbc_inner,
            connection_context=context,
            precision_profile=precision_profile,
            suppressed_value_counters=suppressed_value_counters,
        ):
            _maybe_add_reason(reasons, reason)
        return reasons
    if "://" in cleaned:
        return _analyze_url_candidate(
            cleaned,
            connection_context=context,
            precision_profile=precision_profile,
            suppressed_value_counters=suppressed_value_counters,
        )
    return []


def _detect_connection_and_default_hits(
    cleaned: str,
    *,
    precision_profile: str = VALIDATION_PRECISION_LEGACY,
    suppressed_value_counters: dict[str, int] | None = None,
) -> list[str]:
    reasons: list[str] = []
    usernames: list[str] = []
    passwords: list[str] = []
    has_connection_context = False

    for reason in _detect_connection_value_hits(
        cleaned,
        from_flag=False,
        precision_profile=precision_profile,
        suppressed_value_counters=suppressed_value_counters,
    ):
        _maybe_add_reason(reasons, reason)

    for match in _TEXT_GENERIC_KV_RE.finditer(cleaned):
        start = match.start(1)
        if start > 0 and cleaned[start - 1] in {"-", "/"}:
            continue
        key = str(match.group(1) or "")
        value = _clean_value_text(str(match.group(2) or ""))
        if _key_looks_connection(key):
            has_connection_context = True
            for reason in _detect_connection_value_hits(
                value,
                from_flag=False,
                precision_profile=precision_profile,
                suppressed_value_counters=suppressed_value_counters,
            ):
                _maybe_add_reason(reasons, reason)
        if _key_looks_username(key) and _value_looks_secret_for_key(
            key,
            value,
            precision_profile=precision_profile,
            suppressed_value_counters=suppressed_value_counters,
        ):
            usernames.append(value)
        if _key_looks_sensitive(key) and (
            _value_looks_secret_for_key(
                key,
                value,
                precision_profile=precision_profile,
                suppressed_value_counters=suppressed_value_counters,
            )
            or value == ""
        ):
            passwords.append(value)

    for match in _CMD_FLAG_GENERIC_RE.finditer(cleaned):
        key = str(match.group(1) or "")
        value = _clean_value_text(str(match.group(2) or ""))
        if _key_looks_connection(key):
            has_connection_context = True
            for reason in _detect_connection_value_hits(
                value,
                from_flag=True,
                precision_profile=precision_profile,
                suppressed_value_counters=suppressed_value_counters,
            ):
                _maybe_add_reason(reasons, reason)
        if _key_looks_username(key) and _value_looks_secret_for_key(
            key,
            value,
            precision_profile=precision_profile,
            suppressed_value_counters=suppressed_value_counters,
        ):
            usernames.append(value)
        if _key_looks_sensitive(key) and (
            _value_looks_secret_for_key(
                key,
                value,
                precision_profile=precision_profile,
                suppressed_value_counters=suppressed_value_counters,
            )
            or value == ""
        ):
            passwords.append(value)

    if has_connection_context and usernames and passwords:
        _maybe_add_reason(reasons, "connection_string_auth")

    for username in usernames:
        for password in passwords:
            if _is_known_default_pair(username, password):
                _maybe_add_reason(reasons, "default_creds_known_pair")
                return reasons
    return reasons


def _collect_json_hits(
    payload: Any,
    path: str = "",
    *,
    precision_profile: str = VALIDATION_PRECISION_LEGACY,
    suppressed_value_counters: dict[str, int] | None = None,
) -> list[str]:
    hits: list[str] = []
    if isinstance(payload, dict):
        username_candidates: list[tuple[str, Any]] = []
        sensitive_candidates: list[tuple[str, Any]] = []
        found_sensitive_in_object = False
        for key, value in payload.items():
            key_text = str(key)
            sub_path = f"{path}.{key_text}" if path else key_text
            if _key_looks_sensitive(key_text) and _value_looks_secret_for_key(
                key_text,
                value,
                precision_profile=precision_profile,
                suppressed_value_counters=suppressed_value_counters,
            ):
                _maybe_add_reason(hits, sub_path)
                sensitive_candidates.append((sub_path, value))
                found_sensitive_in_object = True
            if _key_looks_username(key_text) and _value_looks_secret_for_key(
                key_text,
                value,
                precision_profile=precision_profile,
                suppressed_value_counters=suppressed_value_counters,
            ):
                username_candidates.append((sub_path, value))
            if isinstance(value, str):
                if _key_looks_connection(key_text):
                    reasons = _detect_connection_value_hits(
                        value,
                        from_flag=False,
                        precision_profile=precision_profile,
                        suppressed_value_counters=suppressed_value_counters,
                    )
                else:
                    reasons = _detect_hits_in_text(
                        value,
                        precision_profile=precision_profile,
                        suppressed_value_counters=suppressed_value_counters,
                    )
                for reason in reasons:
                    _maybe_add_reason(hits, f"{sub_path}:{reason}")
            hits.extend(
                _collect_json_hits(
                    value,
                    sub_path,
                    precision_profile=precision_profile,
                    suppressed_value_counters=suppressed_value_counters,
                )
            )
        if found_sensitive_in_object:
            for username_path, _username_value in username_candidates:
                _maybe_add_reason(hits, username_path)
            for _username_path, username_value in username_candidates:
                for sensitive_path, sensitive_value in sensitive_candidates:
                    if _is_known_default_pair(username_value, sensitive_value):
                        _maybe_add_reason(hits, f"{sensitive_path}:default_creds_known_pair")
                        break
        return hits
    if isinstance(payload, list):
        for idx, value in enumerate(payload):
            sub_path = f"{path}[{idx}]" if path else f"[{idx}]"
            if isinstance(value, str):
                for reason in _detect_hits_in_text(
                    value,
                    precision_profile=precision_profile,
                    suppressed_value_counters=suppressed_value_counters,
                ):
                    _maybe_add_reason(hits, f"{sub_path}:{reason}")
            hits.extend(
                _collect_json_hits(
                    value,
                    sub_path,
                    precision_profile=precision_profile,
                    suppressed_value_counters=suppressed_value_counters,
                )
            )
    return hits


def _extract_metric_query_label_values(line: str) -> list[str]:
    metric_line = line.strip()
    if "{" not in metric_line or "}" not in metric_line:
        return []
    open_brace = metric_line.find("{")
    close_brace = metric_line.rfind("}")
    if open_brace <= 0 or close_brace <= open_brace:
        return []

    metric_name = metric_line[:open_brace].strip()
    if not _METRIC_NAME_RE.fullmatch(metric_name):
        return []

    labels_blob = metric_line[open_brace + 1 : close_brace]
    if "=" not in labels_blob:
        return []

    values: list[str] = []
    for match in _METRIC_LABEL_RE.finditer(labels_blob):
        key = str(match.group(1) or "").strip().lower()
        if key not in _QUERY_LABEL_KEYS:
            continue
        raw_value = str(match.group(2) or "")
        value = raw_value.replace('\\"', '"').replace("\\\\", "\\")
        if value:
            values.append(value)
    return values


def _should_suppress_metric_query_only_noise(
    line: str,
    reasons: list[str],
    *,
    precision_profile: str = VALIDATION_PRECISION_LEGACY,
    suppressed_value_counters: dict[str, int] | None = None,
) -> bool:
    if not reasons:
        return False

    query_values = _extract_metric_query_label_values(line)
    if not query_values:
        return False

    if any(_is_strong_signal(reason) for reason in reasons):
        return False
    if _EXPLICIT_SECRET_ASSIGN_RE.search(line):
        return False

    query_reasons: list[str] = []
    for value in query_values:
        for reason in _detect_hits_in_text_core(
            value,
            precision_profile=precision_profile,
            suppressed_value_counters=suppressed_value_counters,
        ):
            _maybe_add_reason(query_reasons, reason)
    if not query_reasons:
        return False
    return set(reasons).issubset(set(query_reasons))


def _detect_structured_cmdline_hits(
    line: str,
    *,
    precision_profile: str = VALIDATION_PRECISION_LEGACY,
    suppressed_value_counters: dict[str, int] | None = None,
) -> list[str]:
    cleaned = str(line or "").strip()
    if not cleaned:
        return []

    try:
        tokens = shlex.split(cleaned, posix=True)
    except ValueError:
        return []
    if not tokens:
        return []

    reasons: list[str] = []
    usernames: list[str] = []
    passwords: list[str] = []
    has_connection_context = False

    def _iter_pairs(items: list[str]) -> list[tuple[str, str]]:
        pairs: list[tuple[str, str]] = []
        idx = 0
        while idx < len(items):
            token = str(items[idx] or "")
            if token.startswith("-D") and "=" in token:
                chunk = token[2:]
                key, value = chunk.split("=", 1)
                pairs.append((key, value))
                idx += 1
                continue
            if token.startswith(("--", "-D", "/")):
                body = token[2:] if token.startswith("--") else (token[2:] if token.startswith("-D") else token[1:])
                if "=" in body:
                    key, value = body.split("=", 1)
                    pairs.append((key, value))
                    idx += 1
                    continue
                if ":" in body and not body.lower().startswith("http"):
                    key, value = body.split(":", 1)
                    pairs.append((key, value))
                    idx += 1
                    continue
                if idx + 1 < len(items):
                    nxt = str(items[idx + 1] or "")
                    if nxt and not nxt.startswith("-"):
                        pairs.append((body, nxt))
                        idx += 2
                        continue
            idx += 1
        return pairs

    for token in tokens:
        if "://" in token or token.lower().startswith("jdbc:"):
            for reason in _detect_connection_value_hits(
                token,
                from_flag=True,
                precision_profile=precision_profile,
                suppressed_value_counters=suppressed_value_counters,
            ):
                _maybe_add_reason(reasons, reason)

    for key, value in _iter_pairs(tokens):
        key_text = str(key or "").strip()
        value_text = _clean_value_text(value)
        if not key_text:
            continue
        if _key_looks_connection(key_text):
            has_connection_context = True
            for reason in _detect_connection_value_hits(
                value_text,
                from_flag=True,
                precision_profile=precision_profile,
                suppressed_value_counters=suppressed_value_counters,
            ):
                _maybe_add_reason(reasons, reason)
        if _key_looks_sensitive(key_text) and _value_looks_secret_for_key(
            key_text,
            value_text,
            precision_profile=precision_profile,
            suppressed_value_counters=suppressed_value_counters,
        ):
            _maybe_add_reason(reasons, f"flag_{key_text.lower()}")
            passwords.append(value_text)
        if _key_looks_username(key_text) and _value_looks_secret_for_key(
            key_text,
            value_text,
            precision_profile=precision_profile,
            suppressed_value_counters=suppressed_value_counters,
        ):
            _maybe_add_reason(reasons, f"{key_text.lower()}=value")
            usernames.append(value_text)

    if has_connection_context and usernames and passwords:
        _maybe_add_reason(reasons, "connection_string_auth")
        for username in usernames:
            for password in passwords:
                if _is_known_default_pair(username, password):
                    _maybe_add_reason(reasons, "default_creds_known_pair")
                    break

    return reasons


def _detect_hits_in_text_core(
    line: str,
    *,
    precision_profile: str = VALIDATION_PRECISION_LEGACY,
    suppressed_value_counters: dict[str, int] | None = None,
) -> list[str]:
    reasons: list[str] = []
    cleaned = line.strip()
    if not cleaned:
        return reasons
    lower = cleaned.lower()
    has_hint = any(token in lower for token in _VALIDATE_TEXT_HINT_TOKENS)
    has_structured_hint = (
        "://" in lower
        or "eyj" in lower
        or "akia" in lower
        or "asia" in lower
        or (cleaned.count(":") == 4 and " " not in cleaned and "\t" not in cleaned)
    )
    if not has_hint and not has_structured_hint:
        return reasons

    line_upper = cleaned.upper()
    if "[CRED]" in line_upper:
        _maybe_add_reason(reasons, "cred_marker")

    for reason in _detect_structured_cmdline_hits(
        cleaned,
        precision_profile=precision_profile,
        suppressed_value_counters=suppressed_value_counters,
    ):
        _maybe_add_reason(reasons, reason)

    connection_reasons = _detect_connection_and_default_hits(
        cleaned,
        precision_profile=precision_profile,
        suppressed_value_counters=suppressed_value_counters,
    )
    for reason in connection_reasons:
        _maybe_add_reason(reasons, reason)

    for match in _TEXT_KV_RE.finditer(cleaned):
        key = str(match.group(1) or "").lower()
        value = _clean_value_text(str(match.group(2) or ""))
        if _value_looks_secret_for_key(
            key,
            value,
            precision_profile=precision_profile,
            suppressed_value_counters=suppressed_value_counters,
        ):
            _maybe_add_reason(reasons, f"{key}=value")

    for match in _CMD_FLAG_SECRET_RE.finditer(cleaned):
        key = str(match.group(1) or "").lower()
        value = _clean_value_text(str(match.group(2) or ""))
        if _value_looks_secret_for_key(
            key,
            value,
            precision_profile=precision_profile,
            suppressed_value_counters=suppressed_value_counters,
        ):
            _maybe_add_reason(reasons, f"flag_{key}")

    if not connection_reasons:
        for reason in _detect_url_based_hits(
            cleaned,
            precision_profile=precision_profile,
            suppressed_value_counters=suppressed_value_counters,
        ):
            _maybe_add_reason(reasons, reason)

    for match in _AUTH_BASIC_RE.finditer(cleaned):
        decoded = _safe_decode_basic(str(match.group(1) or ""))
        if not decoded or ":" not in decoded:
            continue
        username, password = decoded.split(":", 1)
        if _value_looks_secret(
            password,
            precision_profile=precision_profile,
            suppressed_value_counters=suppressed_value_counters,
        ) or _is_known_default_pair(username, password):
            _maybe_add_reason(reasons, "authorization_basic")
            if _is_known_default_pair(username, password):
                _maybe_add_reason(reasons, "default_creds_known_pair")

    for match in _AUTH_BEARER_RE.finditer(cleaned):
        token = _clean_value_text(str(match.group(1) or ""))
        if _value_looks_token_secret(
            token,
            precision_profile=precision_profile,
            suppressed_value_counters=suppressed_value_counters,
        ):
            _maybe_add_reason(reasons, "authorization_bearer")

    if _JWT_RE.search(cleaned):
        _maybe_add_reason(reasons, "jwt_token")

    if _PEM_PRIVATE_KEY_RE.search(cleaned):
        _maybe_add_reason(reasons, "private_key_pem")

    if _AWS_ACCESS_KEY_RE.search(cleaned):
        _maybe_add_reason(reasons, "aws_access_key_id")

    redis_match = _REDIS_PASS_RE.search(cleaned)
    if redis_match and _value_looks_secret(
        redis_match.group(2),
        precision_profile=precision_profile,
        suppressed_value_counters=suppressed_value_counters,
    ):
        _maybe_add_reason(reasons, f"redis_{redis_match.group(1).lower()}")

    # Username fields by themselves are noisy; keep them only when line also contains secret indicators.
    line_has_secret_context = bool(
        _TEXT_KV_RE.search(cleaned)
        or _CMD_FLAG_SECRET_RE.search(cleaned)
        or _AUTH_BASIC_RE.search(cleaned)
        or _AUTH_BEARER_RE.search(cleaned)
    )
    if line_has_secret_context:
        for match in re.finditer(r"(?i)[\"']?([A-Za-z_][A-Za-z0-9_.-]*)[\"']?\s*[:=]\s*([^\s,;]+)", cleaned):
            key = str(match.group(1) or "")
            value = _clean_value_text(str(match.group(2) or ""))
            if _key_looks_username(key) and _value_looks_secret_for_key(
                key,
                value,
                precision_profile=precision_profile,
                suppressed_value_counters=suppressed_value_counters,
            ):
                _maybe_add_reason(reasons, f"{key.lower()}=value")

    pgpass_parts = cleaned.split(":")
    if len(pgpass_parts) == 5:
        host, port, database, username, password = pgpass_parts
        if (
            host
            and (port.isdigit() or port == "*")
            and database
            and username
            and _value_looks_secret(
                password,
                precision_profile=precision_profile,
                suppressed_value_counters=suppressed_value_counters,
            )
        ):
            _maybe_add_reason(reasons, "pgpass_line")

    return list(dict.fromkeys(reasons))


def _detect_hits_in_text(
    line: str,
    *,
    precision_profile: str = VALIDATION_PRECISION_LEGACY,
    suppressed_value_counters: dict[str, int] | None = None,
) -> list[str]:
    reasons = _detect_hits_in_text_core(
        line,
        precision_profile=precision_profile,
        suppressed_value_counters=suppressed_value_counters,
    )
    if _should_suppress_metric_query_only_noise(
        line,
        reasons,
        precision_profile=precision_profile,
        suppressed_value_counters=suppressed_value_counters,
    ):
        return []
    return reasons


def _vulnerable_dedupe(values: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = _clean_value_text(value)
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def _vulnerable_username_allowed(value: Any) -> bool:
    text = _clean_value_text(value)
    if not _value_looks_identifier(text):
        return False
    return not _is_placeholder_value(text) and not _is_dummy_secret_value(text)


def _vulnerable_secret_allowed(key: str, value: Any) -> bool:
    return _value_looks_secret_for_key(
        key,
        value,
        precision_profile=VALIDATION_PRECISION_COLLECT_STRICT,
        suppressed_value_counters=None,
    )


def _vulnerable_key_bucket(key: str) -> str:
    normalized = _normalize_key_token(key)
    if "apikey" in normalized or normalized in {"accesskey", "accesskeyid", "secretaccesskey"}:
        return "api_keys"
    if "token" in normalized or "bearer" in normalized or normalized in {"auth", "authorization"}:
        return "api_keys"
    if "password" in normalized or "passwd" in normalized or normalized.endswith("pwd") or "secret" in normalized:
        return "passwords"
    return "passwords"


def _extract_vulnerable_credentials_from_text(text: str) -> tuple[list[str], list[str], list[str]]:
    sample = str(text or "")
    users: list[str] = []
    passwords: list[str] = []
    api_keys: list[str] = []

    for match in _URL_CANDIDATE_RE.finditer(sample):
        candidate = match.group(0).rstrip("),]")
        try:
            parsed = urlsplit(candidate)
        except ValueError:
            continue
        username = unquote(parsed.username or "")
        password = unquote(parsed.password or "")
        if (
            username
            and password
            and (_vulnerable_secret_allowed("password", password) or _is_known_default_pair(username, password))
        ):
            if _vulnerable_username_allowed(username):
                users.append(username)
            passwords.append(password)
        try:
            query_items = parse_qsl(parsed.query, keep_blank_values=True)
        except ValueError:
            query_items = []
        for key, value in query_items:
            if _key_looks_username(key) and _vulnerable_username_allowed(value):
                users.append(value)
            if not _key_looks_sensitive(key) or not _vulnerable_secret_allowed(key, value):
                continue
            if _vulnerable_key_bucket(key) == "api_keys":
                api_keys.append(value)
            else:
                passwords.append(value)

    for match in _AUTH_BASIC_RE.finditer(sample):
        decoded = _safe_decode_basic(str(match.group(1) or ""))
        if not decoded or ":" not in decoded:
            continue
        username, password = decoded.split(":", 1)
        if _vulnerable_secret_allowed("password", password) or _is_known_default_pair(username, password):
            if _vulnerable_username_allowed(username):
                users.append(username)
            passwords.append(password)

    for match in _AUTH_BEARER_RE.finditer(sample):
        token = _clean_value_text(str(match.group(1) or ""))
        if _value_looks_token_secret(
            token,
            precision_profile=VALIDATION_PRECISION_COLLECT_STRICT,
            suppressed_value_counters=None,
        ):
            api_keys.append(token)

    for match in _JWT_RE.finditer(sample):
        api_keys.append(str(match.group(0) or ""))

    for match in _AWS_ACCESS_KEY_RE.finditer(sample):
        api_keys.append(str(match.group(0) or ""))

    redis_match = _REDIS_PASS_RE.search(sample)
    if redis_match and _vulnerable_secret_allowed(str(redis_match.group(1)), str(redis_match.group(2))):
        passwords.append(str(redis_match.group(2)))

    for pattern in (_TEXT_GENERIC_KV_RE, _CMD_FLAG_GENERIC_RE):
        for match in pattern.finditer(sample):
            key = str(match.group(1) or "").strip()
            value = _clean_value_text(str(match.group(2) or ""))
            if not key or not value:
                continue
            if _key_looks_username(key) and _vulnerable_username_allowed(value):
                users.append(value)
            if not _key_looks_sensitive(key) or not _vulnerable_secret_allowed(key, value):
                continue
            if _vulnerable_key_bucket(key) == "api_keys":
                api_keys.append(value)
            else:
                passwords.append(value)

    return _vulnerable_dedupe(users), _vulnerable_dedupe(passwords), _vulnerable_dedupe(api_keys)


def _extract_vulnerable_credentials_from_hit(hit: dict[str, str | int]) -> tuple[list[str], list[str], list[str]]:
    body = str(hit.get("body") or "")
    samples = [body] if body else [str(hit.get("sample") or "")]

    users: list[str] = []
    passwords: list[str] = []
    api_keys: list[str] = []
    for sample in samples:
        sample_users, sample_passwords, sample_api_keys = _extract_vulnerable_credentials_from_text(sample)
        users.extend(sample_users)
        passwords.extend(sample_passwords)
        api_keys.extend(sample_api_keys)
    return _vulnerable_dedupe(users), _vulnerable_dedupe(passwords), _vulnerable_dedupe(api_keys)


def _extract_vulnerable_login_pairs_from_text(text: str) -> list[tuple[str, str]]:
    sample = str(text or "")
    pairs: list[tuple[str, str]] = []
    usernames: list[str] = []
    passwords: list[str] = []

    for match in _URL_CANDIDATE_RE.finditer(sample):
        candidate = match.group(0).rstrip("),]")
        try:
            parsed = urlsplit(candidate)
        except ValueError:
            continue
        username = unquote(parsed.username or "")
        password = unquote(parsed.password or "")
        if (
            username
            and password
            and _vulnerable_username_allowed(username)
            and (_vulnerable_secret_allowed("password", password) or _is_known_default_pair(username, password))
        ):
            pairs.append((username, password))

    for match in _AUTH_BASIC_RE.finditer(sample):
        decoded = _safe_decode_basic(str(match.group(1) or ""))
        if not decoded or ":" not in decoded:
            continue
        username, password = decoded.split(":", 1)
        if _vulnerable_username_allowed(username) and (
            _vulnerable_secret_allowed("password", password) or _is_known_default_pair(username, password)
        ):
            pairs.append((username, password))

    for pattern in (_TEXT_GENERIC_KV_RE, _CMD_FLAG_GENERIC_RE):
        for match in pattern.finditer(sample):
            key = str(match.group(1) or "").strip()
            value = _clean_value_text(str(match.group(2) or ""))
            if not key or not value:
                continue
            if _key_looks_username(key) and _vulnerable_username_allowed(value):
                usernames.append(value)
            elif _key_looks_sensitive(key) and _vulnerable_secret_allowed(key, value):
                bucket = _vulnerable_key_bucket(key)
                if bucket == "passwords":
                    passwords.append(value)

    redis_match = _REDIS_PASS_RE.search(sample)
    if redis_match and _vulnerable_secret_allowed(str(redis_match.group(1)), str(redis_match.group(2))):
        passwords.append(str(redis_match.group(2)))

    usernames = _vulnerable_dedupe(usernames)
    passwords = _vulnerable_dedupe(passwords)
    paired_passwords = {password for _username, password in pairs}
    passwords = [password for password in passwords if password not in paired_passwords]
    if passwords and usernames:
        if len(usernames) == len(passwords):
            pairs.extend(zip(usernames, passwords, strict=False))
        else:
            username = usernames[0] if usernames else ""
            pairs.extend((username, password) for password in passwords)

    result: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for username, password in pairs:
        user_text = _clean_value_text(username)
        password_text = _clean_value_text(password)
        if not password_text:
            continue
        key = (user_text, password_text)
        if key in seen:
            continue
        seen.add(key)
        result.append(key)
    return result


def _vulnerable_source_host_port(hit: dict[str, str | int]) -> tuple[str, str]:
    host = str(hit.get("host") or "-").strip() or "-"
    port = str(hit.get("port") or "-").strip() or "-"
    return host, port


def _vulnerable_source_api_keys(hit: dict[str, str | int], api_keys: list[str]) -> list[str]:
    host, port = _vulnerable_source_host_port(hit)
    return _vulnerable_dedupe([f"{host}:{port}:{api_key}" for api_key in api_keys])


def _extract_vulnerable_login_pairs_from_hit(hit: dict[str, str | int]) -> list[tuple[str, str]]:
    body = str(hit.get("body") or "")
    samples = [body] if body else [str(hit.get("sample") or "")]
    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for sample in samples:
        for username, password in _extract_vulnerable_login_pairs_from_text(sample):
            key = (_clean_value_text(username), _clean_value_text(password))
            if key in seen:
                continue
            seen.add(key)
            pairs.append(key)
    return pairs


def _sample_line_for_json_reasons(body: str, reasons: list[str]) -> str:
    lines = [line.strip() for line in body.splitlines() if line.strip()]
    if not lines:
        return ""
    for reason in reasons:
        reason_path = reason.split(":", 1)[0]
        leaf = reason_path.split(".")[-1].split("[", 1)[0].strip()
        if not leaf:
            continue
        for line in lines:
            if leaf in line:
                return line
    return lines[0]


def _detect_line_hits(
    line: str,
    input_format: str,
    *,
    precision_profile: str = VALIDATION_PRECISION_LEGACY,
    suppressed_value_counters: dict[str, int] | None = None,
) -> list[str]:
    stripped = line.strip()
    if not stripped:
        return []

    if input_format == "txt":
        return _detect_hits_in_text(
            stripped,
            precision_profile=precision_profile,
            suppressed_value_counters=suppressed_value_counters,
        )

    if input_format == "json":
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            return []
        return _collect_json_hits(
            payload,
            precision_profile=precision_profile,
            suppressed_value_counters=suppressed_value_counters,
        )

    # auto
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            return _detect_hits_in_text(
                stripped,
                precision_profile=precision_profile,
                suppressed_value_counters=suppressed_value_counters,
            )
        return _collect_json_hits(
            payload,
            precision_profile=precision_profile,
            suppressed_value_counters=suppressed_value_counters,
        )
    return _detect_hits_in_text(
        stripped,
        precision_profile=precision_profile,
        suppressed_value_counters=suppressed_value_counters,
    )


def _line_no_for_sample(lines: list[str], sample: str) -> int:
    if not lines:
        return 1
    sample_clean = sample.strip()
    if not sample_clean:
        return 1
    for idx, line in enumerate(lines, start=1):
        if line.strip() == sample_clean:
            return idx
    for idx, line in enumerate(lines, start=1):
        if sample_clean in line:
            return idx
    return 1


def _extract_line_correlation_context(
    line: str,
    *,
    precision_profile: str = VALIDATION_PRECISION_LEGACY,
    suppressed_value_counters: dict[str, int] | None = None,
) -> tuple[set[str], set[str]]:
    usernames: set[str] = set()
    passwords: set[str] = set()
    cleaned = str(line or "").strip()
    if not cleaned:
        return usernames, passwords

    for match in _TEXT_GENERIC_KV_RE.finditer(cleaned):
        key = str(match.group(1) or "").strip()
        value = _clean_value_text(str(match.group(2) or ""))
        if not key or not value:
            continue
        if _key_looks_username(key) and _value_looks_secret_for_key(
            key,
            value,
            precision_profile=precision_profile,
            suppressed_value_counters=suppressed_value_counters,
        ):
            usernames.add(value)
        if _key_looks_sensitive(key) and _value_looks_secret_for_key(
            key,
            value,
            precision_profile=precision_profile,
            suppressed_value_counters=suppressed_value_counters,
        ):
            passwords.add(value)

    for match in _CMD_FLAG_GENERIC_RE.finditer(cleaned):
        key = str(match.group(1) or "").strip()
        value = _clean_value_text(str(match.group(2) or ""))
        if not key or not value:
            continue
        if _key_looks_username(key) and _value_looks_secret_for_key(
            key,
            value,
            precision_profile=precision_profile,
            suppressed_value_counters=suppressed_value_counters,
        ):
            usernames.add(value)
        if _key_looks_sensitive(key) and _value_looks_secret_for_key(
            key,
            value,
            precision_profile=precision_profile,
            suppressed_value_counters=suppressed_value_counters,
        ):
            passwords.add(value)

    return usernames, passwords


def _apply_cross_line_correlation(
    *,
    lines: list[str],
    hits: list[dict[str, str | int]],
    precision_profile: str = VALIDATION_PRECISION_LEGACY,
    suppressed_value_counters: dict[str, int] | None = None,
) -> None:
    if _normalize_precision_profile(precision_profile) != VALIDATION_PRECISION_COLLECT_STRICT:
        return
    if not hits or not lines:
        return

    line_contexts: list[tuple[set[str], set[str]]] = [
        _extract_line_correlation_context(
            raw_line,
            precision_profile=precision_profile,
            suppressed_value_counters=suppressed_value_counters,
        )
        for raw_line in lines
    ]

    any_strong = False
    any_medium = False
    per_hit_signals: list[list[str]] = []
    for hit in hits:
        signals = _split_reason_signals(str(hit.get("reason") or ""))
        per_hit_signals.append(signals)
        if any(_is_strong_signal(signal) for signal in signals):
            any_strong = True
        if any(_has_medium_signal(signal) for signal in signals):
            any_medium = True

    for idx, hit in enumerate(hits):
        signals = per_hit_signals[idx]
        if not signals:
            continue
        has_strong = any(_is_strong_signal(signal) for signal in signals)
        has_medium = any(_has_medium_signal(signal) for signal in signals)
        line_no = int(hit.get("line_no") or 0)
        if line_no < 1 or line_no > len(line_contexts):
            continue

        correlated = False
        if not has_strong:
            if any_strong:
                _maybe_add_reason(signals, "correlated_with_strong")
                correlated = True
            elif not has_medium and any_medium:
                _maybe_add_reason(signals, "correlated_with_medium")
                correlated = True

        usernames_here, passwords_here = line_contexts[line_no - 1]
        usernames_near: set[str] = set(usernames_here)
        passwords_near: set[str] = set(passwords_here)
        for neighbor in (line_no - 2, line_no):
            if 0 <= neighbor < len(line_contexts):
                neighbor_users, neighbor_passwords = line_contexts[neighbor]
                usernames_near.update(neighbor_users)
                passwords_near.update(neighbor_passwords)

        if (passwords_here and usernames_near) or (usernames_here and passwords_near):
            _maybe_add_reason(signals, "correlated_user_password")
            correlated = True

        if correlated:
            hit["reason"] = ",".join(signals)


def _scan_body_hits(
    body: str,
    input_format: str,
    *,
    precision_profile: str = VALIDATION_PRECISION_LEGACY,
    suppressed_value_counters: dict[str, int] | None = None,
) -> tuple[int, list[dict[str, str | int]]]:
    text = body if isinstance(body, str) else str(body)
    lines = text.splitlines()
    line_count = len(lines)
    stripped = text.strip()
    if line_count == 0 and stripped:
        line_count = 1

    should_try_json = input_format == "json" or (
        input_format == "auto" and (stripped.startswith("{") or stripped.startswith("["))
    )
    if should_try_json and stripped:
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            pass
        else:
            reasons = list(
                dict.fromkeys(
                    _collect_json_hits(
                        payload,
                        precision_profile=precision_profile,
                        suppressed_value_counters=suppressed_value_counters,
                    )
                )
            )
            if reasons:
                sample = _sample_line_for_json_reasons(text, reasons) or stripped
                return (
                    line_count,
                    [
                        {
                            "reason": ",".join(reasons),
                            "sample": sample,
                            "line_no": _line_no_for_sample(lines, sample),
                        }
                    ],
                )
            return line_count, []

    if input_format == "json":
        hits: list[dict[str, str | int]] = []
        for line_no, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                reasons = _detect_hits_in_text(
                    line,
                    precision_profile=precision_profile,
                    suppressed_value_counters=suppressed_value_counters,
                )
            else:
                reasons = _collect_json_hits(
                    payload,
                    precision_profile=precision_profile,
                    suppressed_value_counters=suppressed_value_counters,
                )
            if not reasons:
                continue
            hits.append(
                {
                    "reason": ",".join(dict.fromkeys(reasons)),
                    "sample": line,
                    "line_no": line_no,
                }
            )
        _apply_cross_line_correlation(
            lines=lines,
            hits=hits,
            precision_profile=precision_profile,
            suppressed_value_counters=suppressed_value_counters,
        )
        return line_count, hits

    # Fallback to line-by-line text heuristics for truncated/invalid JSON and plaintext outputs.
    line_mode = input_format
    hits: list[dict[str, str | int]] = []
    for line_no, raw_line in enumerate(lines, start=1):
        reasons = _detect_line_hits(
            raw_line,
            line_mode,
            precision_profile=precision_profile,
            suppressed_value_counters=suppressed_value_counters,
        )
        if not reasons:
            continue
        hits.append(
            {
                "reason": ",".join(dict.fromkeys(reasons)),
                "sample": raw_line.strip(),
                "line_no": line_no,
            }
        )
    _apply_cross_line_correlation(
        lines=lines,
        hits=hits,
        precision_profile=precision_profile,
        suppressed_value_counters=suppressed_value_counters,
    )
    return line_count, hits


__all__ = [name for name in globals() if name.startswith("_")]
