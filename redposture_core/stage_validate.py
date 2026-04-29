"""Saved-output validation helpers."""

from __future__ import annotations

import base64
import binascii
import json
import re
import shlex
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

from .console import Console

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

_EXPORTER_DISPLAY_NAMES = {
    "nats_exporter": "NATS Exporter",
    "statsd_exporter": "StatsD Exporter",
    "mysqld_exporter": "MySQLd Exporter",
    "blackbox_exporter": "Blackbox Exporter",
    "elasticsearch_exporter": "Elasticsearch Exporter",
    "nginx_exporter": "Nginx Exporter",
    "haproxy_exporter": "HAProxy Exporter",
    "kafka_exporter": "Kafka Exporter",
    "node_exporter": "Node Exporter",
    "memcached_exporter": "Memcached Exporter",
    "postgres_exporter": "Postgres Exporter",
    "redis_exporter": "Redis Exporter",
    "clickhouse_exporter": "ClickHouse Exporter",
    "snmp_exporter": "SNMP Exporter",
    "apache_exporter": "Apache Exporter",
    "bind_exporter": "BIND Exporter",
    "mongodb_exporter": "MongoDB Exporter",
    "pgbouncer_exporter": "PgBouncer Exporter",
    "pgbackrest_exporter": "pgBackRest Exporter",
    "victoriametrics_exporter": "VictoriaMetrics Exporter",
    "ceph_exporter": "Ceph Exporter",
    "varnish_exporter": "Varnish Exporter",
    "windows_exporter": "Windows Exporter",
    "ipmi_exporter": "IPMI Exporter",
    "gobgp_exporter": "GoBGP Exporter",
    "frr_exporter": "FRR Exporter",
    "named_process_exporter": "Named Process Exporter",
    "sql_exporter": "SQL Exporter",
    "ping_exporter": "Ping Exporter",
    "rabbitmq_exporter": "RabbitMQ Exporter",
    "proxmox_exporter": "Proxmox Exporter",
}

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

_SCORE_STRONG = 8
_SCORE_MEDIUM = 4
_SCORE_WEAK = 1

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
_DENY_CONTEXT_TOKENS = (
    "example",
    "sample",
    "template",
    "placeholder",
    "docs",
    "documentation",
    "dummy",
    "mock",
    "testdata",
)
_ALLOW_CONTEXT_TOKENS = (
    "credential",
    "auth",
    "authorization",
    "password",
    "secret",
    "token",
    "apikey",
)


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
    if text.endswith(",") or text.endswith(";"):
        text = text[:-1].strip()
    if len(text) >= 2 and (
        (text.startswith('"') and text.endswith('"')) or (text.startswith("'") and text.endswith("'"))
    ):
        text = text[1:-1].strip()
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


def _signal_base_code(signal: str) -> str:
    text = str(signal or "").strip()
    if not text:
        return ""
    if ":" in text:
        return text.rsplit(":", 1)[1].strip()
    return text


def _is_explicit_key_value_signal(signal: str) -> bool:
    base = _signal_base_code(signal)
    return base.endswith("=value")


def _is_strong_signal(signal: str) -> bool:
    base = _signal_base_code(signal)
    if not base:
        return False
    if base == "correlated_with_strong":
        return True
    if base in {
        "authorization_basic",
        "authorization_bearer",
        "jwt_token",
        "private_key_pem",
        "aws_access_key_id",
        "pgpass_line",
    }:
        return True
    if base.startswith("redis_"):
        return True
    if base.endswith("connection_string_auth") or base.endswith("connection_string_query_secret"):
        return True
    return False


def _signal_score(signal: str) -> tuple[int, str]:
    base = _signal_base_code(signal)
    if base == "correlated_with_strong":
        return _SCORE_STRONG, "strong:correlated_with_strong"
    if base in {"correlated_with_medium", "correlated_user_password"}:
        return _SCORE_MEDIUM, f"medium:{base}"
    if _is_strong_signal(signal):
        return _SCORE_STRONG, f"strong:{base}"
    if _is_explicit_key_value_signal(signal) or base.startswith("flag_"):
        return _SCORE_MEDIUM, f"medium:{base}"
    return _SCORE_WEAK, f"weak:{base}"


def _endpoint_policy(endpoint: str, *, precision_profile: str) -> dict[str, Any]:
    profile = _normalize_precision_profile(precision_profile)
    if profile != VALIDATION_PRECISION_COLLECT_STRICT:
        return {"name": "legacy", "threshold": 0, "require_strong": False, "enabled": False}

    path = str(endpoint or "").split("?", 1)[0].strip() or "/debug/vars"
    if path == "/metrics":
        return {"name": "metrics_profile", "threshold": 8, "require_strong": True, "enabled": True}
    if path.startswith("/debug/pprof"):
        return {"name": "pprof_profile", "threshold": 5, "require_strong": False, "enabled": True}
    return {"name": "vars_profile", "threshold": 6, "require_strong": False, "enabled": True}


def _context_tokens_present(sample: str, tokens: tuple[str, ...]) -> list[str]:
    lowered = str(sample or "").lower()
    if not lowered:
        return []
    found: list[str] = []
    for token in tokens:
        if token in lowered and token not in found:
            found.append(token)
    return found


def _score_and_gate_hit(
    *,
    reason: str,
    endpoint: str,
    sample: str,
    precision_profile: str,
) -> dict[str, Any]:
    signals = _split_reason_signals(reason)
    score = 0
    strong_count = 0
    score_reasons: list[str] = []
    for signal in signals:
        points, label = _signal_score(signal)
        score += int(points)
        score_reasons.append(label)
        if _is_strong_signal(signal):
            strong_count += 1

    policy = _endpoint_policy(endpoint, precision_profile=precision_profile)
    profile = _normalize_precision_profile(precision_profile)
    deny_context = (
        _context_tokens_present(sample, _DENY_CONTEXT_TOKENS) if profile == VALIDATION_PRECISION_COLLECT_STRICT else []
    )
    allow_context = (
        _context_tokens_present(sample, _ALLOW_CONTEXT_TOKENS) if profile == VALIDATION_PRECISION_COLLECT_STRICT else []
    )

    context_penalty_applied = False
    context_bonus_applied = False
    context_gate_deny = False
    if deny_context:
        if strong_count < 1:
            context_gate_deny = True
            score_reasons.append("context:deny")
        else:
            score = max(0, score - 2)
            context_penalty_applied = True
            score_reasons.append("penalty:deny_context")
    elif allow_context:
        score += 1
        context_bonus_applied = True
        score_reasons.append("bonus:allow_context")

    gated_out = False
    if bool(policy.get("enabled")):
        threshold = int(policy.get("threshold") or 0)
        require_strong = bool(policy.get("require_strong"))
        if score < threshold:
            gated_out = True
        if require_strong and strong_count < 1:
            gated_out = True
    if context_gate_deny:
        gated_out = True

    return {
        "hit_score": score,
        "score_reasons": ",".join(score_reasons) if score_reasons else "-",
        "gated_out": gated_out,
        "strong_signal_count": strong_count,
        "endpoint_policy": str(policy.get("name") or "legacy"),
        "context_deny_tokens": ",".join(deny_context) if deny_context else "-",
        "context_allow_tokens": ",".join(allow_context) if allow_context else "-",
        "context_penalty_applied": context_penalty_applied,
        "context_bonus_applied": context_bonus_applied,
    }


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


def _clip(text: str, width: int = 180) -> str:
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def _split_reason_signals(reason: str) -> list[str]:
    signals: list[str] = []
    for chunk in str(reason or "").split(","):
        token = chunk.strip()
        if token and token not in signals:
            signals.append(token)
    return signals


def _match_validate_suppress_rule(
    rule: dict[str, Any],
    *,
    exporter: str,
    endpoint: str,
    signals: list[str],
    sample: str,
) -> bool:
    rule_exporter = str(rule.get("exporter") or "").strip().lower()
    if rule_exporter and exporter.strip().lower() != rule_exporter:
        return False

    rule_endpoint = str(rule.get("endpoint") or "").strip()
    if rule_endpoint and endpoint.strip() != rule_endpoint:
        return False

    wanted_signals = set(rule.get("signals_any") or ())
    if wanted_signals:
        base_signals = {_signal_base_code(signal) for signal in signals}
        if not (base_signals & wanted_signals):
            return False

    sample_re = rule.get("sample_re")
    if isinstance(sample_re, re.Pattern):
        if not sample_re.search(sample):
            return False
    elif sample_re:
        return False

    if _EXPLICIT_SECRET_ASSIGN_RE.search(sample):
        return False
    return True


def _suppress_rule_id_for_hit(
    *,
    exporter: str,
    endpoint: str,
    reason: str,
    sample: str,
) -> str | None:
    signals = _split_reason_signals(reason)
    for rule in _DEFAULT_VALIDATE_SUPPRESS_RULES:
        if _match_validate_suppress_rule(
            rule,
            exporter=exporter,
            endpoint=endpoint,
            signals=signals,
            sample=sample,
        ):
            return str(rule.get("id") or "default_suppress_rule")
    return None


def _validate_group_key(
    *,
    host: str,
    port: str,
    exporter: str,
    endpoint: str,
    reason: str,
) -> tuple[str, str, str, str, str]:
    return (
        str(host or "-"),
        str(port or "-"),
        str(exporter or "-"),
        str(endpoint or "-"),
        str(reason or "-"),
    )


def _validate_group_key_from_match(item: dict[str, str | int]) -> tuple[str, str, str, str, str]:
    return _validate_group_key(
        host=str(item.get("host") or "-"),
        port=str(item.get("port") or "-"),
        exporter=str(item.get("exporter") or "-"),
        endpoint=str(item.get("endpoint") or "-"),
        reason=str(item.get("reason") or "-"),
    )


def _group_validate_matches(
    matches: list[dict[str, str | int]],
    group_counts: dict[tuple[str, str, str, str, str], int] | None = None,
) -> list[dict[str, str | int]]:
    grouped: dict[tuple[str, str, str, str, str], dict[str, str | int]] = {}
    order: list[tuple[str, str, str, str, str]] = []

    for item in matches:
        key = _validate_group_key_from_match(item)
        existing = grouped.get(key)
        if existing is None:
            merged = dict(item)
            merged["count"] = 1
            grouped[key] = merged
            order.append(key)
            continue
        existing["count"] = int(existing.get("count") or 1) + 1
        existing["sample"] = str(item.get("sample") or "")
        if "hit_score" in item:
            existing["hit_score"] = int(item.get("hit_score") or 0)
        if "score_reasons" in item:
            existing["score_reasons"] = str(item.get("score_reasons") or "-")
        if "gated_out" in item:
            existing["gated_out"] = bool(item.get("gated_out"))
        if "endpoint_policy" in item:
            existing["endpoint_policy"] = str(item.get("endpoint_policy") or "-")
        if "line_no" in item:
            existing["line_no"] = int(item.get("line_no") or 1)
        if "record_no" in item:
            existing["record_no"] = int(item.get("record_no") or 0)
        if "rel" in item:
            existing["rel"] = str(item.get("rel") or "")

    if group_counts:
        for key in order:
            grouped[key]["count"] = int(group_counts.get(key, int(grouped[key].get("count") or 1)))

    return [grouped[key] for key in order]


def _signal_path_leaf(signal: str) -> str:
    token = str(signal or "").strip()
    if not token:
        return ""
    if ":" in token:
        token = token.split(":", 1)[0]
    leaf = token.split(".")[-1]
    leaf = leaf.split("[", 1)[0].strip()
    return leaf.lower()


def _signal_reason_phrase(signal: str) -> str:
    base = _signal_base_code(signal)
    if base == "private_key_pem":
        return "private key"
    if base == "jwt_token":
        return "JWT token"
    if base == "aws_access_key_id":
        return "AWS access key"
    if base == "authorization_basic":
        return "basic auth header"
    if base == "authorization_bearer":
        return "bearer auth header"
    if base.endswith("connection_string_auth"):
        return "conn creds"
    if base.endswith("connection_string_query_secret"):
        return "conn query secret"
    if base == "pgpass_line":
        return "pgpass line"
    if base.startswith("redis_"):
        redis_key = base[len("redis_") :].replace("_", " ").strip()
        return f"redis {redis_key}".strip()
    if base.startswith("flag_"):
        return f"flag {base[len('flag_') :]}"
    if base.endswith("=value"):
        return f"{base[: -len('=value')]} value"
    if base == "default_creds_known_pair":
        return "default creds pair"
    if base == "cred_marker":
        return "cred marker"
    if base == "correlated_with_strong":
        return "cross-line strong corroboration"
    if base == "correlated_with_medium":
        return "cross-line corroboration"
    if base == "correlated_user_password":
        return "cross-line user/password pair"

    leaf = _signal_path_leaf(signal)
    if leaf and _key_looks_sensitive(leaf):
        return f"{leaf} field"
    if leaf and _key_looks_username(leaf):
        return f"{leaf} field"

    compact = base.replace("_", " ").strip()
    return compact if compact else "credential indicator"


def _all_reasons_from_signals(signals: list[str]) -> str:
    reasons: list[str] = []
    for signal in signals:
        phrase = _signal_reason_phrase(signal)
        if phrase and phrase not in reasons:
            reasons.append(phrase)
    return ", ".join(reasons) if reasons else "credential indicator"


def _find_key_value_spans(sample: str, key: str) -> list[tuple[int, int]]:
    key_text = str(key or "").strip()
    if not key_text:
        return []
    pattern = re.compile(rf"(?i)[\"']?{re.escape(key_text)}[\"']?\s*[:=]\s*(\"[^\"]+\"|'[^']+'|[^\s,;]+)")
    return [(match.start(), match.end()) for match in pattern.finditer(sample)]


def _find_flag_spans(sample: str, key: str) -> list[tuple[int, int]]:
    key_text = str(key or "").strip()
    if not key_text:
        return []
    pattern = re.compile(
        rf"(?i)(?:^|\s)((?:--|-D|/)?{re.escape(key_text)}\s*(?:=|:|\s)\s*(\"[^\"]+\"|'[^']+'|[^\s,;]+))"
    )
    return [(match.start(1), match.end(1)) for match in pattern.finditer(sample)]


def _find_signal_spans(sample: str, signal: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    base = _signal_base_code(signal)
    leaf = _signal_path_leaf(signal)

    if base.endswith("=value"):
        key = base[: -len("=value")]
        spans.extend(_find_key_value_spans(sample, key))
    elif base.startswith("flag_"):
        key = base[len("flag_") :]
        spans.extend(_find_flag_spans(sample, key))
    elif base == "authorization_basic":
        spans.extend((match.start(), match.end()) for match in _AUTH_BASIC_RE.finditer(sample))
    elif base == "authorization_bearer":
        spans.extend((match.start(), match.end()) for match in _AUTH_BEARER_RE.finditer(sample))
    elif base == "jwt_token":
        spans.extend((match.start(), match.end()) for match in _JWT_RE.finditer(sample))
    elif base == "private_key_pem":
        spans.extend((match.start(), match.end()) for match in _PEM_PRIVATE_KEY_RE.finditer(sample))
    elif base == "aws_access_key_id":
        spans.extend((match.start(), match.end()) for match in _AWS_ACCESS_KEY_RE.finditer(sample))
    elif base == "pgpass_line":
        stripped = sample.strip()
        if stripped:
            start = sample.find(stripped)
            spans.append((start, start + len(stripped)))
    elif base.startswith("redis_"):
        spans.extend((match.start(), match.end()) for match in _REDIS_PASS_RE.finditer(sample))
    elif base.startswith("url_") or "connection_string_auth" in base or "connection_string_query_secret" in base:
        spans.extend((match.start(), match.end()) for match in _URL_CANDIDATE_RE.finditer(sample))
    elif base == "cred_marker":
        marker = "[CRED]"
        offset = sample.upper().find(marker)
        if offset >= 0:
            spans.append((offset, offset + len(marker)))

    if not spans and leaf and _key_looks_sensitive(leaf):
        spans.extend(_find_key_value_spans(sample, leaf))
    if not spans and leaf and _key_looks_username(leaf):
        spans.extend(_find_key_value_spans(sample, leaf))
    if not spans and base == "default_creds_known_pair":
        pattern = re.compile(r"(?i)\b[^:/\s]+:[^@\s]+@")
        spans.extend((match.start(), match.end()) for match in pattern.finditer(sample))

    return spans


def _collect_signal_spans(sample: str, signals: list[str]) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    seen: set[tuple[int, int]] = set()
    for signal in signals:
        for start, end in _find_signal_spans(sample, signal):
            if end <= start:
                continue
            key = (start, end)
            if key in seen:
                continue
            seen.add(key)
            spans.append(key)
    spans.sort(key=lambda item: (item[0], item[1]))
    return spans


def _highlight_evidence(sample: str, signals: list[str]) -> str:
    evidence = str(sample or "").strip()
    if not evidence:
        return "-"
    spans = _collect_signal_spans(evidence, signals)
    if not spans:
        return evidence
    return evidence


def _normalize_reason_render(reason: str, sample: str) -> tuple[str, str, str]:
    signals = _split_reason_signals(reason)
    if not signals:
        return "-", "-", _highlight_evidence(sample, [])
    return (
        _all_reasons_from_signals(signals),
        ",".join(signals),
        _highlight_evidence(sample, signals),
    )


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


def _exporter_display_name(raw: str) -> str:
    key = (raw or "").strip().lower()
    return _EXPORTER_DISPLAY_NAMES.get(key, raw or "-")


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


def _has_medium_signal(signal: str) -> bool:
    base = _signal_base_code(signal)
    if base in {"correlated_with_medium", "correlated_user_password"}:
        return True
    return _is_explicit_key_value_signal(signal) or base.startswith("flag_")


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


def _load_collect_index(input_dir: Path) -> dict[str, dict[str, Any]]:
    index_path = input_dir / "index.jsonl"
    if not index_path.exists() or not index_path.is_file():
        return {}
    result: dict[str, dict[str, Any]] = {}
    try:
        with index_path.open("r", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                line = raw.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(payload, dict):
                    continue
                rel = str(payload.get("response_file") or "").strip()
                if not rel:
                    continue
                result[rel] = payload
    except OSError:
        return {}
    return result


def _fallback_meta_from_rel(rel: str) -> dict[str, str]:
    path_obj = Path(rel)
    if path_obj.is_absolute():
        return {"host": "-", "port": "-", "exporter": "-", "endpoint": "-"}
    parts = path_obj.parts
    if len(parts) < 3:
        return {"host": "-", "port": "-", "exporter": "-", "endpoint": "-"}
    host = parts[0]
    exporter = parts[1]
    filename = parts[-1]
    port = "-"
    match = _PORT_PREFIX_RE.match(filename)
    if match:
        port = match.group(1)
    return {"host": host, "port": port, "exporter": exporter, "endpoint": "-"}


def _render_validate_row(
    out: Console,
    *,
    host: str,
    port: str,
    exporter: str,
    reason: str,
    endpoint: str,
    sample: str,
    count: int = 1,
    hit_score: int | None = None,
    score_reasons: str = "-",
    gated_non_debug: bool = False,
    endpoint_policy: str = "-",
    debug: bool = False,
) -> None:
    reason_human, signals, evidence_value = _normalize_reason_render(reason, sample)
    tag = f"{'VALIDATE':<8}"
    prefix = f"\t{_clip(host, 64)}\t{_clip(port, 16)}\t"
    endpoint_row_label = out._paint("Endpoint:", "white", sys.stdout)
    endpoint_row_value = out._paint(endpoint, "orange", sys.stdout)
    reason_label = out._paint("Reason:", "white", sys.stdout)
    reason_value = out._paint(reason_human, "orange", sys.stdout)
    signals_label = out._paint("Signals:", "white", sys.stdout)
    signals_value = out._paint(signals, "orange", sys.stdout)
    score_label = out._paint("Score:", "white", sys.stdout)
    score_value = out._paint(str(hit_score if hit_score is not None else "-"), "orange", sys.stdout)
    gate_label = out._paint("Gate:", "white", sys.stdout)
    gate_value = out._paint("gated_non_debug=yes" if gated_non_debug else "gated_non_debug=no", "orange", sys.stdout)
    policy_label = out._paint("Policy:", "white", sys.stdout)
    policy_value = out._paint(str(endpoint_policy or "-"), "orange", sys.stdout)
    score_reasons_label = out._paint("ScoreSignals:", "white", sys.stdout)
    score_reasons_value = out._paint(str(score_reasons or "-"), "orange", sys.stdout)
    leak_label = out._paint("Leak:", "white", sys.stdout)
    leak_value = out._paint(evidence_value, "orange", sys.stdout)
    count_label = out._paint("Count:", "white", sys.stdout)
    count_value = out._paint(str(max(1, int(count))), "orange", sys.stdout)
    header = (
        f"{out._paint(tag, 'blue', sys.stdout)}"
        f"{out._paint(prefix, 'white', sys.stdout)}"
        f" {out._paint('[*]', 'blue', sys.stdout)} "
        f"{out._paint(f'Dump Validate {_exporter_display_name(exporter)}', 'white', sys.stdout)}"
    )
    endpoint_row = (
        f"{out._paint(tag, 'blue', sys.stdout)}"
        f"{out._paint(prefix, 'white', sys.stdout)}"
        f" {endpoint_row_label} {endpoint_row_value}"
    )
    details = (
        f"{out._paint(tag, 'blue', sys.stdout)}{out._paint(prefix, 'white', sys.stdout)} {reason_label} {reason_value}"
    )
    evidence = (
        f"{out._paint(tag, 'blue', sys.stdout)}{out._paint(prefix, 'white', sys.stdout)} {leak_label} {leak_value}"
    )
    count_row = (
        f"{out._paint(tag, 'blue', sys.stdout)}{out._paint(prefix, 'white', sys.stdout)} {count_label} {count_value}"
    )
    out.plain(header)
    out.plain(endpoint_row)
    out.plain(details)
    if debug:
        signals_row = (
            f"{out._paint(tag, 'blue', sys.stdout)}"
            f"{out._paint(prefix, 'white', sys.stdout)}"
            f" {signals_label} {signals_value}"
        )
        out.plain(signals_row)
        score_row = (
            f"{out._paint(tag, 'blue', sys.stdout)}"
            f"{out._paint(prefix, 'white', sys.stdout)}"
            f" {score_label} {score_value} {gate_label} {gate_value} {policy_label} {policy_value}"
        )
        out.plain(score_row)
        score_reasons_row = (
            f"{out._paint(tag, 'blue', sys.stdout)}"
            f"{out._paint(prefix, 'white', sys.stdout)}"
            f" {score_reasons_label} {score_reasons_value}"
        )
        out.plain(score_reasons_row)
    out.plain(evidence)
    if count > 1:
        out.plain(count_row)


def _render_validate_source_row(
    out: Console,
    *,
    source: str,
    reason: str,
    sample: str,
    count: int = 1,
    hit_score: int | None = None,
    score_reasons: str = "-",
    gated_non_debug: bool = False,
    endpoint_policy: str = "-",
    debug: bool = False,
) -> None:
    reason_human, signals, evidence_value = _normalize_reason_render(reason, sample)
    tag = f"{'VALIDATE':<8}"
    prefix = f"\t{_clip(source, 64)}\t-\t"
    reason_label = out._paint("Reason:", "white", sys.stdout)
    reason_value = out._paint(reason_human, "orange", sys.stdout)
    signals_label = out._paint("Signals:", "white", sys.stdout)
    signals_value = out._paint(signals, "orange", sys.stdout)
    score_label = out._paint("Score:", "white", sys.stdout)
    score_value = out._paint(str(hit_score if hit_score is not None else "-"), "orange", sys.stdout)
    gate_label = out._paint("Gate:", "white", sys.stdout)
    gate_value = out._paint("gated_non_debug=yes" if gated_non_debug else "gated_non_debug=no", "orange", sys.stdout)
    policy_label = out._paint("Policy:", "white", sys.stdout)
    policy_value = out._paint(str(endpoint_policy or "-"), "orange", sys.stdout)
    score_reasons_label = out._paint("ScoreSignals:", "white", sys.stdout)
    score_reasons_value = out._paint(str(score_reasons or "-"), "orange", sys.stdout)
    leak_label = out._paint("Leak:", "white", sys.stdout)
    leak_value = out._paint(evidence_value, "orange", sys.stdout)
    count_label = out._paint("Count:", "white", sys.stdout)
    count_value = out._paint(str(max(1, int(count))), "orange", sys.stdout)
    header = (
        f"{out._paint(tag, 'blue', sys.stdout)}"
        f"{out._paint(prefix, 'white', sys.stdout)}"
        f" {out._paint('[*]', 'blue', sys.stdout)} "
        f"{out._paint('Dump Validate Source', 'white', sys.stdout)}"
    )
    details = (
        f"{out._paint(tag, 'blue', sys.stdout)}{out._paint(prefix, 'white', sys.stdout)} {reason_label} {reason_value}"
    )
    evidence = (
        f"{out._paint(tag, 'blue', sys.stdout)}{out._paint(prefix, 'white', sys.stdout)} {leak_label} {leak_value}"
    )
    count_row = (
        f"{out._paint(tag, 'blue', sys.stdout)}{out._paint(prefix, 'white', sys.stdout)} {count_label} {count_value}"
    )
    out.plain(header)
    out.plain(details)
    if debug:
        signals_row = (
            f"{out._paint(tag, 'blue', sys.stdout)}"
            f"{out._paint(prefix, 'white', sys.stdout)}"
            f" {signals_label} {signals_value}"
        )
        out.plain(signals_row)
        score_row = (
            f"{out._paint(tag, 'blue', sys.stdout)}"
            f"{out._paint(prefix, 'white', sys.stdout)}"
            f" {score_label} {score_value} {gate_label} {gate_value} {policy_label} {policy_value}"
        )
        out.plain(score_row)
        score_reasons_row = (
            f"{out._paint(tag, 'blue', sys.stdout)}"
            f"{out._paint(prefix, 'white', sys.stdout)}"
            f" {score_reasons_label} {score_reasons_value}"
        )
        out.plain(score_reasons_row)
    out.plain(evidence)
    if count > 1:
        out.plain(count_row)


def _resolve_validate_summary_target(matches: list[dict[str, str | int]]) -> tuple[str, str]:
    if not matches:
        return "-", "-"
    hosts = {str(item.get("host") or "-") for item in matches if str(item.get("host") or "-") != "-"}
    ports = {str(item.get("port") or "-") for item in matches if str(item.get("port") or "-") != "-"}
    exporters = {str(item.get("exporter") or "-") for item in matches if str(item.get("exporter") or "-") != "-"}

    if len(hosts) == 1:
        host = next(iter(hosts))
    else:
        host = "-"

    # Avoid misleading summaries like "VALIDATE ... 9116" when hits came from multiple exporters/ports.
    if len(ports) == 1 and len(exporters) <= 1 and host != "-":
        port = next(iter(ports))
    else:
        port = "-"

    return host, port


def _render_validate_complete_row(
    out: Console,
    *,
    host: str,
    port: str,
    total_lines: int,
    credential_hits: int,
    unique_hits: int | None = None,
    ok: bool,
) -> None:
    tag = f"{'VALIDATE':<8}"
    prefix = f"\t{_clip(host, 64)}\t{_clip(port, 16)}\t"
    mark = "[+]" if ok else "[!]"
    mark_color = "green" if ok else "red"
    message = f"validate complete: lines={total_lines} credential_hits={credential_hits}"
    if unique_hits is not None:
        message += f" unique_hits={unique_hits}"
    row = (
        f"{out._paint(tag, 'blue', sys.stdout)}"
        f"{out._paint(prefix, 'white', sys.stdout)}"
        f" {out._paint(mark, mark_color, sys.stdout)} "
        f"{out._paint(message, mark_color, sys.stdout)}"
    )
    out.plain(row)


def run_validation(
    input_path: str,
    *,
    input_format: str = "auto",
    precision_profile: str = VALIDATION_PRECISION_LEGACY,
    show: bool = False,
    max_lines: int = 20,
    fail_on_creds: bool = False,
    debug: bool = False,
    console: Console | None = None,
) -> int:
    out = console or Console(debug=debug)
    pipeline_started_at = time.monotonic()
    normalized_precision_profile = _normalize_precision_profile(precision_profile)
    path_obj = Path(input_path)
    if not path_obj.exists():
        out.error(f"input not found: {path_obj}")
        return 2

    files: list[Path]
    if path_obj.is_file():
        files = [path_obj]
    else:
        files = [path for path in sorted(path_obj.rglob("*")) if path.is_file()]

    if not files:
        out.error(f"no files to validate: {path_obj}")
        return 2

    if debug:
        out.info(f"validate started: input={path_obj} files={len(files)} format={input_format}")
        out.debug(f"pass=1 detect start total={len(files)}")

    index_map: dict[str, dict[str, Any]] = {}
    if path_obj.is_dir():
        index_map = _load_collect_index(path_obj)

    total_lines = 0
    hit_count = 0
    matches: list[dict[str, str | int]] = []
    group_counts: dict[tuple[str, str, str, str, str], int] = {}
    suppressed_hits = 0
    suppressed_rules: dict[str, int] = {}
    suppressed_value_counters: dict[str, int] = {}
    gated_non_debug_hits = 0
    unlimited = max_lines <= 0

    for file_path in files:
        try:
            body = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            out.warn(f"skip file={file_path}: {exc}")
            continue

        line_count, hits = _scan_body_hits(
            body,
            input_format,
            precision_profile=normalized_precision_profile,
            suppressed_value_counters=suppressed_value_counters,
        )
        total_lines += line_count
        if not hits:
            continue

        rel = str(file_path.relative_to(path_obj)) if path_obj.is_dir() else str(file_path)
        meta = index_map.get(rel) or _fallback_meta_from_rel(rel)
        for hit in hits:
            reason = str(hit.get("reason") or "-")
            sample = str(hit.get("sample") or "")
            host = str(meta.get("host") or "-")
            port = str(meta.get("port") or "-")
            exporter = str(meta.get("exporter") or "-")
            endpoint = str(meta.get("endpoint") or "-")

            suppress_rule_id = _suppress_rule_id_for_hit(
                exporter=exporter,
                endpoint=endpoint,
                reason=reason,
                sample=sample,
            )
            if suppress_rule_id is not None:
                suppressed_hits += 1
                suppressed_rules[suppress_rule_id] = int(suppressed_rules.get(suppress_rule_id, 0)) + 1
                continue

            score_info = _score_and_gate_hit(
                reason=reason,
                endpoint=endpoint,
                sample=sample,
                precision_profile=normalized_precision_profile,
            )
            if not debug and bool(score_info.get("gated_out")):
                gated_non_debug_hits += 1
                continue

            hit_count += 1
            group_key = _validate_group_key(
                host=host,
                port=port,
                exporter=exporter,
                endpoint=endpoint,
                reason=reason,
            )
            group_counts[group_key] = int(group_counts.get(group_key, 0)) + 1
            if not unlimited and len(matches) >= max_lines:
                continue
            matches.append(
                {
                    "rel": rel,
                    "line_no": int(hit.get("line_no") or 1),
                    "reason": reason,
                    "sample": sample,
                    "host": host,
                    "port": port,
                    "exporter": exporter,
                    "endpoint": endpoint,
                    "hit_score": int(score_info.get("hit_score") or 0),
                    "score_reasons": str(score_info.get("score_reasons") or "-"),
                    "gated_out": bool(score_info.get("gated_out")),
                    "endpoint_policy": str(score_info.get("endpoint_policy") or "-"),
                }
            )

    detect_ms = int((time.monotonic() - pipeline_started_at) * 1000)
    if debug:
        out.debug(f"pass=1 detect complete files={len(files)} credential_hits={hit_count}")
        out.debug(f"stage_trace stage_name=detect_protocol attempt=1 duration_ms={detect_ms} result=ok error=-")

    if debug and suppressed_hits > 0:
        rules_text = ",".join(f"{key}:{suppressed_rules[key]}" for key in sorted(suppressed_rules))
        out.debug(f"validate suppressed hits: count={suppressed_hits} rules={rules_text}")
    if debug and normalized_precision_profile == VALIDATION_PRECISION_COLLECT_STRICT and gated_non_debug_hits > 0:
        out.debug(f"validate score gate: profile=collect_strict gated_non_debug_hits={gated_non_debug_hits}")
    if debug:
        placeholder_count = int(suppressed_value_counters.get("suppressed_placeholders", 0))
        dummy_count = int(suppressed_value_counters.get("suppressed_dummy_values", 0))
        non_secret_count = int(suppressed_value_counters.get("suppressed_non_secret_values", 0))
        if placeholder_count or dummy_count or non_secret_count:
            out.debug(
                "validate value suppressions: "
                f"profile={normalized_precision_profile} "
                f"suppressed_placeholders={placeholder_count} "
                f"suppressed_dummy_values={dummy_count} "
                f"suppressed_non_secret_values={non_secret_count}"
            )

    if hit_count <= 0:
        if debug:
            out.debug("pass=2 deep start total=0")
            out.debug("stage2_gate=skip reason=credential_hits=0")
            out.debug("pass=2 deep complete processed=0")
            out.debug("stage_trace stage_name=data attempt=1 duration_ms=0 result=skip error=no_credential_hits")
            total_ms = int((time.monotonic() - pipeline_started_at) * 1000)
            out.debug(
                f"stage_timing_summary status=clean attempts=1/1 detect_ms={detect_ms} data_ms=0 total_ms={total_ms}"
            )
        _render_validate_complete_row(
            out,
            host="-",
            port="-",
            total_lines=total_lines,
            credential_hits=0,
            unique_hits=0,
            ok=True,
        )
        return 0

    grouped_matches = _group_validate_matches(matches, group_counts)
    render_started_at = time.monotonic()
    if debug:
        out.debug(f"pass=2 deep start total={len(grouped_matches)}")
        out.debug("stage2_gate=run reason=credential_hits>0")

    if show:
        for item in grouped_matches:
            host = str(item.get("host") or "-")
            port = str(item.get("port") or "-")
            exporter = str(item.get("exporter") or "-")
            endpoint = str(item.get("endpoint") or "-")
            reason = str(item.get("reason") or "-")
            sample = str(item.get("sample") or "")
            count = int(item.get("count") or 1)
            if host == "-":
                rel = str(item.get("rel") or "-")
                line_no = int(item.get("line_no") or 0)
                _render_validate_source_row(
                    out,
                    source=f"{rel}:{line_no}",
                    reason=reason,
                    sample=sample,
                    count=count,
                    hit_score=int(item.get("hit_score") or 0),
                    score_reasons=str(item.get("score_reasons") or "-"),
                    gated_non_debug=bool(item.get("gated_out")),
                    endpoint_policy=str(item.get("endpoint_policy") or "-"),
                    debug=debug,
                )
                continue
            _render_validate_row(
                out,
                host=host,
                port=port,
                exporter=exporter,
                reason=reason,
                endpoint=endpoint,
                sample=sample,
                count=count,
                hit_score=int(item.get("hit_score") or 0),
                score_reasons=str(item.get("score_reasons") or "-"),
                gated_non_debug=bool(item.get("gated_out")),
                endpoint_policy=str(item.get("endpoint_policy") or "-"),
                debug=debug,
            )
        hidden = hit_count - len(matches)
        if hidden > 0:
            out.warn(f"... {hidden} additional hit(s) hidden")

    summary_host, summary_port = _resolve_validate_summary_target(grouped_matches)
    unique_hits = len(group_counts)
    _render_validate_complete_row(
        out,
        host=summary_host,
        port=summary_port,
        total_lines=total_lines,
        credential_hits=hit_count,
        unique_hits=unique_hits,
        ok=False,
    )
    data_ms = int((time.monotonic() - render_started_at) * 1000)
    if debug:
        out.debug(f"pass=2 deep complete processed={len(grouped_matches)}")
        out.debug(f"stage_trace stage_name=data attempt=1 duration_ms={data_ms} result=ok error=-")
        total_ms = int((time.monotonic() - pipeline_started_at) * 1000)
        out.debug(
            f"stage_timing_summary status=hits attempts=1/1 detect_ms={detect_ms} data_ms={data_ms} total_ms={total_ms}"
        )
    if fail_on_creds:
        return 1
    return 0


def run_validation_records(
    records: list[dict[str, Any]],
    *,
    input_format: str = "auto",
    precision_profile: str = VALIDATION_PRECISION_LEGACY,
    show: bool = False,
    max_lines: int = 20,
    fail_on_creds: bool = False,
    debug: bool = False,
    console: Console | None = None,
) -> int:
    accumulator = ValidationRecordAccumulator(
        input_format=input_format,
        max_lines=max_lines,
        precision_profile=precision_profile,
    )
    for record in records:
        accumulator.feed(record)
    return accumulator.finish(
        show=show,
        fail_on_creds=fail_on_creds,
        debug=debug,
        console=console,
        source="memory",
        records_total=len(records),
    )


def scan_validation_hits(
    body: str,
    *,
    input_format: str = "auto",
    precision_profile: str = VALIDATION_PRECISION_LEGACY,
) -> tuple[int, list[dict[str, str | int]]]:
    """Return line count and validation hits for a body without rendering output."""
    return _scan_body_hits(body, input_format, precision_profile=precision_profile)


class ValidationRecordAccumulator:
    """Streaming credential-hit accumulator for in-memory validation records."""

    def __init__(
        self,
        *,
        input_format: str = "auto",
        max_lines: int = 20,
        precision_profile: str = VALIDATION_PRECISION_LEGACY,
    ) -> None:
        self._input_format = input_format
        self._precision_profile = _normalize_precision_profile(precision_profile)
        self._max_lines = max_lines
        self._unlimited = max_lines <= 0
        self._started_at = time.monotonic()
        self._record_no = 0
        self.total_lines = 0
        self.hit_count = 0
        self.raw_hit_count = 0
        self.shown_hit_count = 0
        self.suppressed_hits = 0
        self._suppressed_rules: dict[str, int] = {}
        self._suppressed_value_counters: dict[str, int] = {}
        self._raw_group_counts: dict[tuple[str, str, str, str, str], int] = {}
        self._shown_group_counts: dict[tuple[str, str, str, str, str], int] = {}
        self.matches_raw: list[dict[str, str | int]] = []
        self.matches_shown: list[dict[str, str | int]] = []

    def vulnerable_targets_from_shown_hits(self) -> tuple[list[str], list[str]]:
        hosts: set[str] = set()
        urls: set[str] = set()
        for host, port, _exporter, endpoint, _reason in self._shown_group_counts:
            host_text = str(host or "").strip()
            port_text = str(port or "").strip()
            endpoint_text = str(endpoint or "").strip()
            if not host_text or host_text == "-" or not port_text.isdigit():
                continue
            if not endpoint_text.startswith("/"):
                continue
            urls.add(f"http://{host_text}:{int(port_text)}{endpoint_text}")
        hosts.update(row[0] for row in self.vulnerable_login_rows_from_shown_hits() if row[0] != "-")
        return sorted(hosts), sorted(urls)

    def vulnerable_login_rows_from_shown_hits(self) -> list[tuple[str, str, str]]:
        rows: list[tuple[str, str, str]] = []
        seen: set[tuple[str, str, str]] = set()
        for hit in self.matches_shown:
            host, _port = _vulnerable_source_host_port(hit)
            for username, password in _extract_vulnerable_login_pairs_from_hit(hit):
                row = (host, username, password)
                if row in seen:
                    continue
                seen.add(row)
                rows.append(row)
        return rows

    def vulnerable_credentials_from_shown_hits(self) -> tuple[list[str], list[str], list[str]]:
        login_rows = self.vulnerable_login_rows_from_shown_hits()
        users = [row[1] for row in login_rows]
        passwords = [row[2] for row in login_rows]
        api_keys: list[str] = []
        for hit in self.matches_shown:
            _hit_users, _hit_passwords, hit_api_keys = _extract_vulnerable_credentials_from_hit(hit)
            api_keys.extend(_vulnerable_source_api_keys(hit, hit_api_keys))
        return _vulnerable_dedupe(users), _vulnerable_dedupe(passwords), _vulnerable_dedupe(api_keys)

    def vulnerable_findings_from_shown_hits(self) -> list[dict[str, object]]:
        findings: list[dict[str, object]] = []
        seen: set[tuple[str, str, str, str, str, str, str, str]] = set()
        for hit in self.matches_shown:
            users, passwords, api_keys = _extract_vulnerable_credentials_from_hit(hit)
            source_api_keys = _vulnerable_source_api_keys(hit, api_keys)
            if not users and not passwords and not source_api_keys:
                continue
            host, port = _vulnerable_source_host_port(hit)
            endpoint = str(hit.get("endpoint") or "-").strip() or "-"
            exporter = str(hit.get("exporter") or "-").strip() or "-"
            reason = str(hit.get("reason") or "-").strip() or "-"
            key = (
                host,
                port,
                endpoint,
                exporter,
                reason,
                ",".join(users),
                ",".join(passwords),
                ",".join(source_api_keys),
            )
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                {
                    "host": host,
                    "port": port,
                    "endpoint": endpoint,
                    "exporter": exporter,
                    "reason": reason,
                    "users": users,
                    "passwords": passwords,
                    "api_keys": source_api_keys,
                }
            )
        return findings

    def feed(self, record: dict[str, Any]) -> None:
        self._record_no += 1
        body = str(record.get("body") or "")
        if not body:
            return

        host = str(record.get("host") or "-")
        port = str(record.get("port") or "-")
        exporter = str(record.get("exporter") or "-")
        endpoint = str(record.get("endpoint") or "-")

        line_count, hits = _scan_body_hits(
            body,
            self._input_format,
            precision_profile=self._precision_profile,
            suppressed_value_counters=self._suppressed_value_counters,
        )
        self.total_lines += line_count
        if not hits:
            return

        for hit in hits:
            reason = str(hit.get("reason") or "-")
            sample = str(hit.get("sample") or "")
            suppress_rule_id = _suppress_rule_id_for_hit(
                exporter=exporter,
                endpoint=endpoint,
                reason=reason,
                sample=sample,
            )
            if suppress_rule_id is not None:
                self.suppressed_hits += 1
                self._suppressed_rules[suppress_rule_id] = int(self._suppressed_rules.get(suppress_rule_id, 0)) + 1
                continue

            score_info = _score_and_gate_hit(
                reason=reason,
                endpoint=endpoint,
                sample=sample,
                precision_profile=self._precision_profile,
            )
            gated_out = bool(score_info.get("gated_out"))

            self.raw_hit_count += 1
            group_key = _validate_group_key(
                host=host,
                port=port,
                exporter=exporter,
                endpoint=endpoint,
                reason=reason,
            )
            self._raw_group_counts[group_key] = int(self._raw_group_counts.get(group_key, 0)) + 1

            hit_payload: dict[str, str | int] = {
                "record_no": self._record_no,
                "line_no": int(hit.get("line_no") or 1),
                "reason": reason,
                "sample": sample,
                "body": body,
                "host": host,
                "port": port,
                "exporter": exporter,
                "endpoint": endpoint,
                "hit_score": int(score_info.get("hit_score") or 0),
                "score_reasons": str(score_info.get("score_reasons") or "-"),
                "gated_out": gated_out,
                "endpoint_policy": str(score_info.get("endpoint_policy") or "-"),
            }
            if self._unlimited or len(self.matches_raw) < self._max_lines:
                self.matches_raw.append(hit_payload)

            if gated_out:
                continue
            self.shown_hit_count += 1
            self._shown_group_counts[group_key] = int(self._shown_group_counts.get(group_key, 0)) + 1
            if self._unlimited or len(self.matches_shown) < self._max_lines:
                self.matches_shown.append(hit_payload)

        self.hit_count = self.shown_hit_count

    def finish(
        self,
        *,
        show: bool,
        fail_on_creds: bool,
        debug: bool,
        console: Console | None = None,
        source: str = "memory",
        records_total: int | None = None,
    ) -> int:
        out = console or Console(debug=debug)
        finish_started_at = time.monotonic()
        if debug:
            records_value = records_total if records_total is not None else self._record_no
            out.info(f"validate started: source={source} records={records_value} format={self._input_format}")
            out.debug(f"pass=1 detect start total={records_value}")
            detect_ms = int((finish_started_at - self._started_at) * 1000)
            raw_hits = self.raw_hit_count
            shown_hits = self.shown_hit_count
            if self._precision_profile == VALIDATION_PRECISION_COLLECT_STRICT:
                out.debug(
                    f"pass=1 detect complete records={records_value} credential_hits={raw_hits} shown_hits={shown_hits}"
                )
            else:
                out.debug(f"pass=1 detect complete records={records_value} credential_hits={raw_hits}")
            out.debug(f"stage_trace stage_name=detect_protocol attempt=1 duration_ms={detect_ms} result=ok error=-")
            if self.suppressed_hits > 0:
                rules_text = ",".join(f"{key}:{self._suppressed_rules[key]}" for key in sorted(self._suppressed_rules))
                out.debug(f"validate suppressed hits: count={self.suppressed_hits} rules={rules_text}")
            placeholder_count = int(self._suppressed_value_counters.get("suppressed_placeholders", 0))
            dummy_count = int(self._suppressed_value_counters.get("suppressed_dummy_values", 0))
            non_secret_count = int(self._suppressed_value_counters.get("suppressed_non_secret_values", 0))
            if placeholder_count or dummy_count or non_secret_count:
                out.debug(
                    "validate value suppressions: "
                    f"profile={self._precision_profile} "
                    f"suppressed_placeholders={placeholder_count} "
                    f"suppressed_dummy_values={dummy_count} "
                    f"suppressed_non_secret_values={non_secret_count}"
                )
        else:
            detect_ms = 0

        effective_hit_count = self.raw_hit_count if debug else self.shown_hit_count
        effective_matches = self.matches_raw if debug else self.matches_shown
        effective_group_counts = self._raw_group_counts if debug else self._shown_group_counts

        if effective_hit_count <= 0:
            if debug:
                out.debug("pass=2 deep start total=0")
                out.debug("stage2_gate=skip reason=credential_hits=0")
                out.debug("pass=2 deep complete processed=0")
                out.debug("stage_trace stage_name=data attempt=1 duration_ms=0 result=skip error=no_credential_hits")
                total_ms = int((time.monotonic() - self._started_at) * 1000)
                out.debug(
                    f"stage_timing_summary status=clean attempts=1/1 "
                    f"detect_ms={detect_ms} data_ms=0 total_ms={total_ms}"
                )
            _render_validate_complete_row(
                out,
                host="-",
                port="-",
                total_lines=self.total_lines,
                credential_hits=0,
                unique_hits=0,
                ok=True,
            )
            return 0

        grouped_matches = _group_validate_matches(effective_matches, effective_group_counts)
        render_started_at = time.monotonic()
        if debug:
            out.debug(f"pass=2 deep start total={len(grouped_matches)}")
            out.debug("stage2_gate=run reason=credential_hits>0")

        if show:
            for item in grouped_matches:
                host = str(item.get("host") or "-")
                port = str(item.get("port") or "-")
                exporter = str(item.get("exporter") or "-")
                endpoint = str(item.get("endpoint") or "-")
                reason = str(item.get("reason") or "-")
                sample = str(item.get("sample") or "")
                count = int(item.get("count") or 1)
                if host == "-":
                    record_no = int(item.get("record_no") or 0)
                    line_no = int(item.get("line_no") or 0)
                    _render_validate_source_row(
                        out,
                        source=f"record#{record_no}:{line_no}",
                        reason=reason,
                        sample=sample,
                        count=count,
                        hit_score=int(item.get("hit_score") or 0),
                        score_reasons=str(item.get("score_reasons") or "-"),
                        gated_non_debug=bool(item.get("gated_out")),
                        endpoint_policy=str(item.get("endpoint_policy") or "-"),
                        debug=debug,
                    )
                    continue
                _render_validate_row(
                    out,
                    host=host,
                    port=port,
                    exporter=exporter,
                    reason=reason,
                    endpoint=endpoint,
                    sample=sample,
                    count=count,
                    hit_score=int(item.get("hit_score") or 0),
                    score_reasons=str(item.get("score_reasons") or "-"),
                    gated_non_debug=bool(item.get("gated_out")),
                    endpoint_policy=str(item.get("endpoint_policy") or "-"),
                    debug=debug,
                )
            hidden = effective_hit_count - len(effective_matches)
            if hidden > 0:
                out.warn(f"... {hidden} additional hit(s) hidden")

        summary_host, summary_port = _resolve_validate_summary_target(grouped_matches)
        _render_validate_complete_row(
            out,
            host=summary_host,
            port=summary_port,
            total_lines=self.total_lines,
            credential_hits=effective_hit_count,
            unique_hits=len(effective_group_counts),
            ok=False,
        )
        if debug:
            data_ms = int((time.monotonic() - render_started_at) * 1000)
            out.debug(f"pass=2 deep complete processed={len(grouped_matches)}")
            out.debug(f"stage_trace stage_name=data attempt=1 duration_ms={data_ms} result=ok error=-")
            total_ms = int((time.monotonic() - self._started_at) * 1000)
            out.debug(
                f"stage_timing_summary status=hits attempts=1/1 "
                f"detect_ms={detect_ms} data_ms={data_ms} total_ms={total_ms}"
            )
        if fail_on_creds:
            return 1
        return 0
