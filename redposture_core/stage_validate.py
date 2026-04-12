"""Saved-output validation helpers."""

from __future__ import annotations

import base64
import binascii
import json
import re
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

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


def _value_looks_secret(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return False
    text = _clean_value_text(value)
    if _is_empty_or_masked(text):
        return False
    if len(text) < 3:
        return False
    return True


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


def _analyze_url_candidate(candidate: str, *, connection_context: str | None = None) -> list[str]:
    reasons: list[str] = []
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return reasons

    username = parsed.username
    password = parsed.password or ""
    if username and (_value_looks_secret(password) or _is_known_default_pair(username, password)):
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
            if any(token in normalized for token in _URL_SENSITIVE_QUERY_KEYS) and _value_looks_secret(value):
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
                if _key_looks_username(key) and _value_looks_secret(value):
                    _maybe_add_reason(reasons, f"url_query_{key.lower()}")
            for query_user in query_user_values:
                for query_password in query_password_values:
                    if _is_known_default_pair(query_user, query_password):
                        _maybe_add_reason(reasons, "default_creds_known_pair")
                        break
    return reasons


def _detect_url_based_hits(text: str, *, connection_context: str | None = None) -> list[str]:
    reasons: list[str] = []
    for match in _URL_CANDIDATE_RE.finditer(text):
        for reason in _analyze_url_candidate(match.group(0), connection_context=connection_context):
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


def _detect_kv_connection_string_hits(text: str, *, connection_context: str) -> list[str]:
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
        if _key_looks_sensitive(key) and (_value_looks_secret(value) or value == ""):
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


def _detect_mysql_style_dsn_hits(text: str, *, connection_context: str) -> list[str]:
    reasons: list[str] = []
    for match in _MYSQL_STYLE_DSN_RE.finditer(text):
        username = _clean_value_text(match.group(1))
        password = _clean_value_text(match.group(2))
        if not username or not (_value_looks_secret(password) or _is_known_default_pair(username, password)):
            continue
        _maybe_add_reason(reasons, _connection_reason(connection_context))
        if _is_known_default_pair(username, password):
            _maybe_add_reason(reasons, "default_creds_known_pair")
    return reasons


def _detect_connection_value_hits(value: Any, *, from_flag: bool) -> list[str]:
    cleaned = _clean_value_text(value)
    if not cleaned:
        return []
    context = "cmd" if from_flag else "connection"
    reasons = _detect_url_based_hits(cleaned, connection_context=context)
    for reason in _detect_mysql_style_dsn_hits(cleaned, connection_context=context):
        _maybe_add_reason(reasons, reason)
    for reason in _detect_kv_connection_string_hits(cleaned, connection_context=context):
        _maybe_add_reason(reasons, reason)
    if reasons:
        return reasons
    if cleaned.lower().startswith("jdbc:"):
        jdbc_inner = cleaned[5:]
        for reason in _detect_url_based_hits(jdbc_inner, connection_context=context):
            _maybe_add_reason(reasons, reason)
        for reason in _detect_kv_connection_string_hits(jdbc_inner, connection_context=context):
            _maybe_add_reason(reasons, reason)
        return reasons
    if "://" in cleaned:
        return _analyze_url_candidate(cleaned, connection_context=context)
    return []


def _detect_connection_and_default_hits(cleaned: str) -> list[str]:
    reasons: list[str] = []
    usernames: list[str] = []
    passwords: list[str] = []
    has_connection_context = False

    for reason in _detect_connection_value_hits(cleaned, from_flag=False):
        _maybe_add_reason(reasons, reason)

    for match in _TEXT_GENERIC_KV_RE.finditer(cleaned):
        start = match.start(1)
        if start > 0 and cleaned[start - 1] in {"-", "/"}:
            continue
        key = str(match.group(1) or "")
        value = _clean_value_text(str(match.group(2) or ""))
        if _key_looks_connection(key):
            has_connection_context = True
            for reason in _detect_connection_value_hits(value, from_flag=False):
                _maybe_add_reason(reasons, reason)
        if _key_looks_username(key) and _value_looks_secret(value):
            usernames.append(value)
        if _key_looks_sensitive(key) and (_value_looks_secret(value) or value == ""):
            passwords.append(value)

    for match in _CMD_FLAG_GENERIC_RE.finditer(cleaned):
        key = str(match.group(1) or "")
        value = _clean_value_text(str(match.group(2) or ""))
        if _key_looks_connection(key):
            has_connection_context = True
            for reason in _detect_connection_value_hits(value, from_flag=True):
                _maybe_add_reason(reasons, reason)
        if _key_looks_username(key) and _value_looks_secret(value):
            usernames.append(value)
        if _key_looks_sensitive(key) and (_value_looks_secret(value) or value == ""):
            passwords.append(value)

    if has_connection_context and usernames and passwords:
        _maybe_add_reason(reasons, "connection_string_auth")

    for username in usernames:
        for password in passwords:
            if _is_known_default_pair(username, password):
                _maybe_add_reason(reasons, "default_creds_known_pair")
                return reasons
    return reasons


def _collect_json_hits(payload: Any, path: str = "") -> list[str]:
    hits: list[str] = []
    if isinstance(payload, dict):
        username_candidates: list[tuple[str, Any]] = []
        sensitive_candidates: list[tuple[str, Any]] = []
        found_sensitive_in_object = False
        for key, value in payload.items():
            key_text = str(key)
            sub_path = f"{path}.{key_text}" if path else key_text
            if _key_looks_sensitive(key_text) and _value_looks_secret(value):
                _maybe_add_reason(hits, sub_path)
                sensitive_candidates.append((sub_path, value))
                found_sensitive_in_object = True
            if _key_looks_username(key_text) and _value_looks_secret(value):
                username_candidates.append((sub_path, value))
            if isinstance(value, str):
                if _key_looks_connection(key_text):
                    reasons = _detect_connection_value_hits(value, from_flag=False)
                else:
                    reasons = _detect_hits_in_text(value)
                for reason in reasons:
                    _maybe_add_reason(hits, f"{sub_path}:{reason}")
            hits.extend(_collect_json_hits(value, sub_path))
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
                for reason in _detect_hits_in_text(value):
                    _maybe_add_reason(hits, f"{sub_path}:{reason}")
            hits.extend(_collect_json_hits(value, sub_path))
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
    if _is_explicit_key_value_signal(signal):
        return True
    return False


def _should_suppress_metric_query_only_noise(line: str, reasons: list[str]) -> bool:
    if not reasons:
        return False

    query_values = _extract_metric_query_label_values(line)
    if not query_values:
        return False

    if any(_is_strong_signal(reason) for reason in reasons):
        return False

    query_reasons: list[str] = []
    for value in query_values:
        for reason in _detect_hits_in_text_core(value):
            _maybe_add_reason(query_reasons, reason)
    if not query_reasons:
        return False
    return set(reasons).issubset(set(query_reasons))


def _detect_hits_in_text_core(line: str) -> list[str]:
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

    connection_reasons = _detect_connection_and_default_hits(cleaned)
    for reason in connection_reasons:
        _maybe_add_reason(reasons, reason)

    for match in _TEXT_KV_RE.finditer(cleaned):
        key = str(match.group(1) or "").lower()
        value = _clean_value_text(str(match.group(2) or ""))
        if _value_looks_secret(value):
            _maybe_add_reason(reasons, f"{key}=value")

    for match in _CMD_FLAG_SECRET_RE.finditer(cleaned):
        key = str(match.group(1) or "").lower()
        value = _clean_value_text(str(match.group(2) or ""))
        if _value_looks_secret(value):
            _maybe_add_reason(reasons, f"flag_{key}")

    if not connection_reasons:
        for reason in _detect_url_based_hits(cleaned):
            _maybe_add_reason(reasons, reason)

    for match in _AUTH_BASIC_RE.finditer(cleaned):
        decoded = _safe_decode_basic(str(match.group(1) or ""))
        if not decoded or ":" not in decoded:
            continue
        username, password = decoded.split(":", 1)
        if _value_looks_secret(password) or _is_known_default_pair(username, password):
            _maybe_add_reason(reasons, "authorization_basic")
            if _is_known_default_pair(username, password):
                _maybe_add_reason(reasons, "default_creds_known_pair")

    for match in _AUTH_BEARER_RE.finditer(cleaned):
        token = _clean_value_text(str(match.group(1) or ""))
        if _value_looks_secret(token):
            _maybe_add_reason(reasons, "authorization_bearer")

    if _JWT_RE.search(cleaned):
        _maybe_add_reason(reasons, "jwt_token")

    if _PEM_PRIVATE_KEY_RE.search(cleaned):
        _maybe_add_reason(reasons, "private_key_pem")

    if _AWS_ACCESS_KEY_RE.search(cleaned):
        _maybe_add_reason(reasons, "aws_access_key_id")

    redis_match = _REDIS_PASS_RE.search(cleaned)
    if redis_match and _value_looks_secret(redis_match.group(2)):
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
            if _key_looks_username(key) and _value_looks_secret(value):
                _maybe_add_reason(reasons, f"{key.lower()}=value")

    pgpass_parts = cleaned.split(":")
    if len(pgpass_parts) == 5:
        host, port, database, username, password = pgpass_parts
        if host and (port.isdigit() or port == "*") and database and username and _value_looks_secret(password):
            _maybe_add_reason(reasons, "pgpass_line")

    return list(dict.fromkeys(reasons))


def _detect_hits_in_text(line: str) -> list[str]:
    reasons = _detect_hits_in_text_core(line)
    if _should_suppress_metric_query_only_noise(line, reasons):
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


def _detect_line_hits(line: str, input_format: str) -> list[str]:
    stripped = line.strip()
    if not stripped:
        return []

    if input_format == "txt":
        return _detect_hits_in_text(stripped)

    if input_format == "json":
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            return []
        return _collect_json_hits(payload)

    # auto
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            return _detect_hits_in_text(stripped)
        return _collect_json_hits(payload)
    return _detect_hits_in_text(stripped)


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


def _scan_body_hits(body: str, input_format: str) -> tuple[int, list[dict[str, str | int]]]:
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
            reasons = list(dict.fromkeys(_collect_json_hits(payload)))
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
                reasons = _detect_hits_in_text(line)
            else:
                reasons = _collect_json_hits(payload)
            if not reasons:
                continue
            hits.append(
                {
                    "reason": ",".join(dict.fromkeys(reasons)),
                    "sample": line,
                    "line_no": line_no,
                }
            )
        return line_count, hits

    # Fallback to line-by-line text heuristics for truncated/invalid JSON and plaintext outputs.
    line_mode = input_format
    hits: list[dict[str, str | int]] = []
    for line_no, raw_line in enumerate(lines, start=1):
        reasons = _detect_line_hits(raw_line, line_mode)
        if not reasons:
            continue
        hits.append(
            {
                "reason": ",".join(dict.fromkeys(reasons)),
                "sample": raw_line.strip(),
                "line_no": line_no,
            }
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
    debug: bool = False,
) -> None:
    reason_human, signals, evidence_value = _normalize_reason_render(reason, sample)
    tag = f"{'VALIDATE':<8}"
    prefix = f"\t{_clip(source, 64)}\t-\t"
    reason_label = out._paint("Reason:", "white", sys.stdout)
    reason_value = out._paint(reason_human, "orange", sys.stdout)
    signals_label = out._paint("Signals:", "white", sys.stdout)
    signals_value = out._paint(signals, "orange", sys.stdout)
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
    show: bool = False,
    max_lines: int = 20,
    fail_on_creds: bool = False,
    debug: bool = False,
    console: Console | None = None,
) -> int:
    out = console or Console(debug=debug)
    pipeline_started_at = time.monotonic()
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
    unlimited = max_lines <= 0

    for file_path in files:
        try:
            body = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            out.warn(f"skip file={file_path}: {exc}")
            continue

        line_count, hits = _scan_body_hits(body, input_format)
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
                }
            )

    detect_ms = int((time.monotonic() - pipeline_started_at) * 1000)
    if debug:
        out.debug(f"pass=1 detect complete files={len(files)} credential_hits={hit_count}")
        out.debug(f"stage_trace stage_name=detect_protocol attempt=1 duration_ms={detect_ms} result=ok error=-")

    if debug and suppressed_hits > 0:
        rules_text = ",".join(f"{key}:{suppressed_rules[key]}" for key in sorted(suppressed_rules))
        out.debug(f"validate suppressed hits: count={suppressed_hits} rules={rules_text}")

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
    show: bool = False,
    max_lines: int = 20,
    fail_on_creds: bool = False,
    debug: bool = False,
    console: Console | None = None,
) -> int:
    accumulator = ValidationRecordAccumulator(input_format=input_format, max_lines=max_lines)
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
) -> tuple[int, list[dict[str, str | int]]]:
    """Return line count and validation hits for a body without rendering output."""
    return _scan_body_hits(body, input_format)


class ValidationRecordAccumulator:
    """Streaming credential-hit accumulator for in-memory validation records."""

    def __init__(self, *, input_format: str = "auto", max_lines: int = 20) -> None:
        self._input_format = input_format
        self._max_lines = max_lines
        self._unlimited = max_lines <= 0
        self._started_at = time.monotonic()
        self._record_no = 0
        self.total_lines = 0
        self.hit_count = 0
        self.suppressed_hits = 0
        self._suppressed_rules: dict[str, int] = {}
        self._group_counts: dict[tuple[str, str, str, str, str], int] = {}
        self.matches: list[dict[str, str | int]] = []

    def feed(self, record: dict[str, Any]) -> None:
        self._record_no += 1
        body = str(record.get("body") or "")
        if not body:
            return

        host = str(record.get("host") or "-")
        port = str(record.get("port") or "-")
        exporter = str(record.get("exporter") or "-")
        endpoint = str(record.get("endpoint") or "-")

        line_count, hits = _scan_body_hits(body, self._input_format)
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

            self.hit_count += 1
            group_key = _validate_group_key(
                host=host,
                port=port,
                exporter=exporter,
                endpoint=endpoint,
                reason=reason,
            )
            self._group_counts[group_key] = int(self._group_counts.get(group_key, 0)) + 1
            if not self._unlimited and len(self.matches) >= self._max_lines:
                continue
            self.matches.append(
                {
                    "record_no": self._record_no,
                    "line_no": int(hit.get("line_no") or 1),
                    "reason": reason,
                    "sample": sample,
                    "host": host,
                    "port": port,
                    "exporter": exporter,
                    "endpoint": endpoint,
                }
            )

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
            out.debug(f"pass=1 detect complete records={records_value} credential_hits={self.hit_count}")
            out.debug(f"stage_trace stage_name=detect_protocol attempt=1 duration_ms={detect_ms} result=ok error=-")
            if self.suppressed_hits > 0:
                rules_text = ",".join(f"{key}:{self._suppressed_rules[key]}" for key in sorted(self._suppressed_rules))
                out.debug(f"validate suppressed hits: count={self.suppressed_hits} rules={rules_text}")
        else:
            detect_ms = 0

        if self.hit_count <= 0:
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

        grouped_matches = _group_validate_matches(self.matches, self._group_counts)
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
                    debug=debug,
                )
            hidden = self.hit_count - len(self.matches)
            if hidden > 0:
                out.warn(f"... {hidden} additional hit(s) hidden")

        summary_host, summary_port = _resolve_validate_summary_target(grouped_matches)
        _render_validate_complete_row(
            out,
            host=summary_host,
            port=summary_port,
            total_lines=self.total_lines,
            credential_hits=self.hit_count,
            unique_hits=len(self._group_counts),
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
