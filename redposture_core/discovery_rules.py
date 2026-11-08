"""Product-neutral scalar rules and evidence for secret discovery.

Product adapters supply values and field context. These rules own no transport,
credential validation, Elasticsearch mappings or result pagination.
"""

from __future__ import annotations

import base64
import binascii
import html
import json
import math
import re
import time
import urllib.parse
import zlib
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, replace
from itertools import chain
from typing import Any, Literal, TypeAlias

from .discovery_entropy import entropy_candidates
from .discovery_sql import _ACCOUNT as _ACCOUNT
from .discovery_sql import SQL_IDENTIFIED_HEAD, SQL_IDENTIFIED_PREFIX, SQL_PASSWORD_HEAD, SQLDialect, SQLLiteral
from .discovery_uri import uri_carrier_kind
from .discovery_values import DiskBackedText
from .secret_fields import (
    _NON_SECRET_FIELD_RE,
    _is_secret_sentinel,
    _normalize_secret_key,
    is_secret_field_name,
    is_secret_metadata_field,
)
from .secret_literals import AssignmentLiterals

FieldClass: TypeAlias = Literal["strong", "medium", "excluded", "neutral"]

_STRONG_FIELDS = {
    "secret",
    "password",
    "passwd",
    "pwd",
    "passphrase",
    "credential",
    "credentials",
    "cred",
    "creds",
    "apisecret",
    "client_secret",
    "private_key",
    "secret_access_key",
    "aws_secret_access_key",
    "azure_storage_key",
    "storage_account_key",
    "account_key",
    "dockerconfigjson",
    "client_key_data",
    "authorization",
    "api_token",
    "refresh_token",
    "connection_string",
    "connection_uri",
    "dsn",
}

_MEDIUM_FIELDS = {
    "secret",
    "token",
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "cookie",
    "session",
    "webhook",
    "key",
}

_EXCLUDED_FIELDS = {
    "public_key",
    "certificate",
    "cert",
    "key_id",
    "api_key_id",
    "access_key_id",
    "aws_access_key_id",
    "token_id",
    "username",
    "user",
    "email",
    "checksum",
    "hash",
    "policy",
    "count",
    "token_count",
    "source",
    "script",
    "type",
    "provider",
    "status",
    "expires",
    "expires_at",
    "expiration",
    "ttl",
}

_PLACEHOLDER_RE = re.compile(
    r"^(?:"
    r"\$\{[^}]+\}|\{\{[^}]+\}\}|<[^>]*(?:redact|secret|password|token)[^>]*>|"
    r"redacted|masked|hidden|none|null|n/?a|x{4,}|\*{4,}|-{4,}"
    r")$",
    re.IGNORECASE,
)

_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")

_JWT_RE = re.compile(
    r"(?<![A-Za-z0-9_-])([A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]{8,}){0,2})(?![A-Za-z0-9_-])"
)

_JWE_RE = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"([A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})"
    r"(?![A-Za-z0-9_-])"
)

_AWS_ACCESS_RE = re.compile(r"(?<![A-Z0-9])((?:AKIA|ASIA)[A-Z0-9]{16})(?![A-Z0-9])")

_AWS_SECRET_RE = re.compile(r"[A-Za-z0-9/+=]{40}")

_GOOGLE_API_RE = re.compile(r"(?<![A-Za-z0-9_-])(AIza[A-Za-z0-9_-]{35})(?![A-Za-z0-9_-])")

_GITHUB_RE = re.compile(
    r"(?<![A-Za-z0-9_])((?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{22,255}))(?![A-Za-z0-9_])"
)

_GITLAB_RE = re.compile(r"(?<![A-Za-z0-9_-])(glpat-[A-Za-z0-9_-]{16,255})(?![A-Za-z0-9_-])")

_SLACK_RE = re.compile(r"(?<![A-Za-z0-9-])(xox[baprs]-[A-Za-z0-9-]{10,255})(?![A-Za-z0-9-])")

_STRIPE_RE = re.compile(r"(?<![A-Za-z0-9_])((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,255})(?![A-Za-z0-9_])")

_VAULT_RE = re.compile(r"(?<![A-Za-z0-9.])(hvs\.[A-Za-z0-9_-]{16,255})(?![A-Za-z0-9_-])")

_NPM_RE = re.compile(r"(?<![A-Za-z0-9_])(npm_[A-Za-z0-9]{20,255})(?![A-Za-z0-9_])")

_PROVIDER_TOKENS = (
    (re.compile(r"(?<![\w-])(sk-(?:proj-|ant-[\w-]{4,})?[A-Za-z0-9_-]{20,})(?![\w-])"), "api_token"),
    (re.compile(r"(?<!\w)(glsa_[A-Za-z0-9_-]{20,})(?!\w)"), "grafana_token"),
    (re.compile(r"(?<!\w)(dop_v1_[A-Za-z0-9]{32,})(?!\w)"), "digitalocean_token"),
    (re.compile(r"(?<!\w)(shpat_[A-Za-z0-9]{24,})(?!\w)"), "shopify_token"),
    (re.compile(r"(?<!\w)(dckr_pat_[A-Za-z0-9_-]{20,})(?!\w)"), "docker_token"),
    (re.compile(r"(?<!\w)(pypi-AgEI[A-Za-z0-9_-]{16,})(?!\w)"), "pypi_token"),
    (re.compile(r"(?<!\w)(SG\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,})(?!\w)"), "sendgrid_token"),
    (re.compile(r"(?<!\w)(SK[0-9a-fA-F]{32})(?!\w)"), "twilio_token"),
    (re.compile(r"(?<!\w)(\d{6,12}:AA[A-Za-z0-9_-]{20,})(?!\w)"), "telegram_token"),
    (re.compile(r"(https://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+)"), "slack_webhook"),
)

# Necessary literal starts only; this gate never confirms a provider token.
_PROVIDER_MARKER = re.compile(
    r"AIza|gh[pousr]_|github_pat_|glpat-|xox|[sr]k_(?:live|test)_|hvs\.|npm_|"
    r"sk-|glsa_|dop_v1_|shpat_|dckr_pat_|pypi-AgEI|SG\.|SK|:AA|https://hooks\.slack\.com/services/"
)

_AUTH_HEADER_RE = re.compile(r"(?i)\b(Basic|Bearer)\s+([A-Za-z0-9._~+/=-]{8,})")

_AZURE_SAS_RE = re.compile(r"(?i)(?:^|[?&])sig=([^&\s]{8,})")

_AZURE_ACCOUNT_KEY_RE = re.compile(r"(?i)(?:^|[;\s])AccountKey=([^;\s]{16,})")

_CREDENTIAL_URI_RE = re.compile(r"(?<![A-Za-z0-9+.-])(?:jdbc:)?[A-Za-z][A-Za-z0-9+.-]*://[^\s\"']+")

_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----[\s\S]+?-----END(?: [A-Z0-9]+)? PRIVATE KEY-----"
)

_KEY_VALUE_RE = re.compile(
    r"(?i)(?<![\w.])(?:--)?"
    r"((?:[A-Za-z][A-Za-z0-9]{0,32}[._-])*"
    r"(?:password|passwd|pwd|passphrase|credential|credentials|cred|creds|pass|"
    r"client[_-]?secret|api[_-]?secret|apisecret|api[_-]?token|"
    r"_?auth[_-]?token|refresh[_-]?token|secret[_-]?access[_-]?key|"
    r"secret[_-]?key|api[_-]?key|apikey|secret|token))"
    r"[\"']?\s*(?:=>|[:=])\s*(?:[\"']([^\"'\s,;<>]+)[\"']|([^\s,;&<>]+))"
)

_SECRET_KEY_SUFFIXES = (
    "password",
    "passwd",
    "pwd",
    "passphrase",
    "credential",
    "credentials",
    "cred",
    "creds",
    "client_secret",
    "api_secret",
    "apisecret",
    "api_token",
    "token",
    "auth_token",
    "refresh_token",
    "secret_access_key",
    "secret_key",
    "apikey",
)

_SQL_PASSWORD_RE = re.compile(r"(?i)\b(?:WITH\s+)?PASSWORD\s+['\"]([^'\"\s;]{4,})['\"]")

# Compatibility exports for the former Elastic classifier; execution uses the
# shared incremental literal reader below.
_SQL_ACCOUNT_TOKEN = _ACCOUNT
_SQL_IDENTIFIED_BY_RE = re.compile(
    SQL_IDENTIFIED_PREFIX + r"('(?:''|\\.|[^'\\])*'|\"(?:\"\"|\\.|[^\"\\])*\")(?=$|[\s;,])"
)

_XML_SECRET_RE = re.compile(r"(?is)<([A-Za-z][\w:.-]{0,79})\b[^>]{0,2048}>([^<>]{4,4096})</\1\s*>")

_TAG_RE = re.compile(r"<([A-Za-z][\w:.-]{0,79})\b([^<>]{0,2048})>", re.IGNORECASE)

_ATTR_RE = re.compile(r"([A-Za-z][\w:.-]{0,79})\s*=\s*([\"'])(.*?)\2", re.DOTALL)
_PASSWORD_HASH_RE = re.compile(r"\$(?:2[aby]|argon2(?:id|i|d)|scrypt)\$[^\s\"']{20,}")
_WEBHOOK_RE = re.compile(r"https://(?:hooks\.slack\.com/services|discord(?:app)?\.com/api/webhooks)/[^\s\"']+")
_SESSION_RE = re.compile(r"(?i)\b(?:session(?:id)?|sid|auth_token)\s*[=:]\s*([A-Za-z0-9._~+/-]{8,})")

SCALAR_DETECTOR_TYPES = (
    "password",
    "secret",
    "private_key",
    "jwt",
    "jwe",
    "google_api_key",
    "github_token",
    "gitlab_token",
    "slack_token",
    "stripe_key",
    "vault_token",
    "npm_token",
    "bearer_token",
    "azure_sas_signature",
    "azure_storage_key",
    "aws_secret_access_key",
    "password_hash",
    "connection_string",
    "signed_url",
    "basic_auth",
    "aws_credentials",
    "oauth_credentials",
    "session_cookie",
    "webhook",
    *(kind for _regex, kind in _PROVIDER_TOKENS),
)


@dataclass(frozen=True)
class DetectedSecret:
    value: str | DiskBackedText
    secret_type: str
    score: int
    detectors: tuple[str, ...]
    available: bool = True
    span: tuple[int, int] | None = None
    field_name: str | None = None


def _confidence(score: int) -> str:
    if score >= 90:
        return "very_high"
    if score >= 75:
        return "high"
    return "medium" if score >= 60 else "low"


def normalize_field_name(value: str) -> str:
    """Normalize dotted, snake, kebab and camel-case field names."""

    text = re.sub(r"\[\d*]", "", str(value).strip())
    text = _normalize_secret_key(text)
    text = re.sub(r"[^A-Za-z0-9]+", "_", text)
    return re.sub(r"_+", "_", text).strip("_").lower()


def classify_field(value: str) -> FieldClass:
    """Classify a mapping/JSON path without treating generic IDs as secrets."""

    segments = [segment for segment in re.split(r"[./]+", str(value)) if segment]
    leaf = normalize_field_name(segments[-1] if segments else value)
    parts = [part for part in leaf.split("_") if part]
    if leaf in _EXCLUDED_FIELDS:
        return "excluded"
    if _NON_SECRET_FIELD_RE.search(leaf) or is_secret_metadata_field(leaf):
        return "excluded"
    if {"public", "key"}.issubset(parts) or {"api", "key", "id"}.issubset(parts):
        return "excluded"
    if leaf.endswith(("_id", "_count", "_hash", "_checksum", "_policy")) and leaf not in {"session_id", "sessionid"}:
        return "excluded"
    if leaf in _STRONG_FIELDS:
        return "strong"
    if leaf in _MEDIUM_FIELDS:
        return "medium"
    if {"client", "secret"}.issubset(parts) or {"private", "key"}.issubset(parts):
        return "strong"
    if any(
        part in {"password", "passwd", "passphrase", "credential", "credentials", "cred", "creds"} for part in parts
    ):
        return "strong"
    if "apisecret" in parts:
        return "strong"
    if any(part in {"secret", "token"} for part in parts):
        return "medium"
    if is_secret_field_name(leaf):
        return "strong"
    if leaf in {"value", "data", "content", "material"}:
        for ancestor in reversed(segments[:-1]):
            ancestor_class = classify_field(ancestor)
            if ancestor_class in {"strong", "medium"}:
                return ancestor_class
    return "neutral"


def classify_field_name(value: str) -> FieldClass:
    """Classify a literal schema key; its dots are not container boundaries."""
    normalized = _normalize_secret_key(value)
    if _NON_SECRET_FIELD_RE.search(normalized) or is_secret_metadata_field(normalized):
        return "excluded"
    result = classify_field(normalize_field_name(value))
    if result == "neutral" and is_secret_field_name(value):
        return "strong"
    return result


def _disk_field_hint(value: DiskBackedText, deadline: float | None = None, *, normalized_name: bool = False) -> str:
    """Retain Elastic's field policy using bounded token state for a long key."""
    token = ""
    tokens: list[str] = []
    relevant: set[str] = set()
    count = 0
    last = ""
    previous = ""
    ancestor = ""
    last_segment = ""
    segment_present = False
    full_tokens: list[str] = []
    full_size = 0
    wanted = {
        "public",
        "key",
        "api",
        "id",
        "client",
        "secret",
        "private",
        "password",
        "passwd",
        "passphrase",
        "credential",
        "credentials",
        "cred",
        "creds",
        "apisecret",
        "token",
    }

    def finish_token() -> None:
        nonlocal token, count, last, full_size
        if not token:
            return
        count += 1
        last = token
        if len(tokens) < 8:
            tokens.append(token)
        if token in wanted:
            relevant.add(token)
        if normalized_name and full_size <= 256:
            full_size += len(token) + 1
            if full_size <= 256:
                full_tokens.append(token)
            else:
                full_tokens.clear()
        token = ""

    def finish_segment() -> str:
        nonlocal count, last, segment_present
        finish_token()
        leaf = "_".join(tokens) if count <= 8 else ""
        if not count and not segment_present:
            result = ""
        elif leaf in _EXCLUDED_FIELDS or {"public", "key"} <= relevant or {"api", "key", "id"} <= relevant:
            result = "hash"
        elif count > 1 and last in {"id", "count", "hash", "checksum", "policy"}:
            result = "hash"
        elif (
            leaf in _STRONG_FIELDS
            or {"client", "secret"} <= relevant
            or {"private", "key"} <= relevant
            or relevant
            & {"password", "passwd", "passphrase", "credential", "credentials", "cred", "creds", "apisecret"}
        ):
            result = "password" if last in {"password", "passwd", "pwd", "passphrase", "pass"} else "client_secret"
        elif leaf in _MEDIUM_FIELDS or relevant & {"secret", "token"}:
            # `secret` is an explicitly strong field. Use a medium alias so
            # the hint cannot promote a long generic token/secret field.
            result = "token"
        elif leaf in {"value", "data", "content", "material"}:
            result = leaf
        else:
            result = "neutral"
        tokens.clear()
        relevant.clear()
        count, last = 0, ""
        segment_present = False
        return result

    def characters() -> Iterator[str]:
        # normalize_field_name removes numeric array suffixes before inserting
        # camel boundaries. A long unclosed suffix needs only enough digits to
        # establish that its token cannot equal any recognized policy word.
        bracket = False
        digits = ""
        nonlocal segment_present
        for chunk in value.iter_text_chunks():
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError("max_seconds")
            for char in chunk:
                if char not in "./":
                    segment_present = True
                if bracket:
                    if char.isdecimal():
                        if len(digits) < 129:
                            digits += char
                        continue
                    if char == "]":
                        bracket, digits = False, ""
                        continue
                    yield "["
                    yield from digits
                    bracket, digits = False, ""
                if char == "[":
                    bracket = True
                else:
                    yield char
        if bracket:
            yield "["
            yield from digits

    for char in characters():
        if char in "./":
            hint = finish_segment()
            if hint:
                last_segment = hint
            if classify_field(hint) in {"strong", "medium"}:
                ancestor = hint
        elif char.isascii() and char.isalnum():
            if char.isupper() and ("a" <= previous <= "z" or "0" <= previous <= "9"):
                finish_token()
            if len(token) < 128:
                token += char.lower()
        else:
            finish_token()
        previous = char
    hint = finish_segment() or last_segment or "neutral"
    if normalized_name:
        return "_".join(full_tokens)
    return f"{ancestor}.{hint}" if ancestor and hint in {"value", "data", "content", "material"} else hint


def _looks_placeholder(value: str | DiskBackedText) -> bool:
    if isinstance(value, DiskBackedText):
        return value.obvious_placeholder
    text = value.strip()
    return not text or _is_secret_sentinel(text) or _PLACEHOLDER_RE.fullmatch(text) is not None


def _plausible_opaque_secret(value: str, *, minimum: int = 12) -> bool:
    text = value.strip()
    if len(text) < minimum:
        return False
    if text.lower() in {
        "anonymous",
        "disabled",
        "enabled",
        "expired",
        "invalid",
        "optional",
        "public",
        "required",
        "supported",
        "unsupported",
    }:
        return False
    character_classes = sum(
        bool(regex.search(text))
        for regex in (
            re.compile(r"[a-z]"),
            re.compile(r"[A-Z]"),
            re.compile(r"[0-9]"),
            re.compile(r"[^A-Za-z0-9]"),
        )
    )
    return _shannon_entropy(text) >= 3.0 and (character_classes >= 2 or len(text) >= 24)


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for character in value:
        counts[character] = counts.get(character, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _candidate(
    value: str | DiskBackedText,
    secret_type: str,
    score: int,
    *detectors: str,
    span: tuple[int, int] | None = None,
    field_name: str | None = None,
) -> DetectedSecret:
    return DetectedSecret(
        value=value,
        secret_type=secret_type,
        score=min(100, max(0, score)),
        detectors=tuple(dict.fromkeys(detectors)),
        span=span,
        field_name=field_name,
    )


def analyze_aws_pair(access: Any, secret: Any) -> DetectedSecret | None:
    """A paired identifier strengthens evidence; an identifier alone is not a secret."""
    if (
        isinstance(access, str)
        and isinstance(secret, str)
        and _AWS_ACCESS_RE.fullmatch(access)
        and _AWS_SECRET_RE.fullmatch(secret)
        and not _looks_placeholder(secret)
    ):
        return _candidate(secret, "aws_secret_access_key", 99, "aws_credential_pair", "sensitive_field")
    return None


def _secret_key_kind(value: str) -> str | None:
    name = normalize_field_name(value)

    def ends_with_segment(suffix: str) -> bool:
        return name == suffix or name.endswith(f"_{suffix}")

    if any(ends_with_segment(suffix) for suffix in ("password", "passwd", "pwd", "passphrase", "pass")):
        return "password"
    if any(ends_with_segment(suffix) for suffix in _SECRET_KEY_SUFFIXES):
        return "secret"
    if is_secret_field_name(name):
        return "secret"
    return None


def _split_user_password(value: str) -> tuple[str, str] | None:
    """Parse one decoded credential pair without mistaking JSON/config blobs for it."""

    if "\r" in value or "\n" in value or ":" not in value:
        return None
    username, password = value.split(":", 1)
    if not password or re.fullmatch(r"[A-Za-z0-9_.@\\/+-]{1,256}", username) is None:
        return None
    return username, password


def _decode_basic(value: str) -> str | None:
    try:
        decoded = base64.b64decode(value, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError, binascii.Error):
        return None
    pair = _split_user_password(decoded)
    return pair[1] if pair is not None else None


def _decode_credential_base64(value: str) -> str | None:
    compact = value.strip()
    if not (8 <= len(compact) <= 8192) or len(compact) % 4:
        return None
    try:
        decoded = base64.b64decode(compact, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError, binascii.Error):
        return None
    if not decoded or any(ord(character) < 9 for character in decoded):
        return None
    return decoded


def _structured_decoded_text(value: str) -> bool:
    stripped = value.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            return isinstance(json.loads(value), (dict, list))
        except ValueError:
            return False
    return bool(_KEY_VALUE_RE.search(value) or _XML_SECRET_RE.search(value) or _TAG_RE.search(value))


def _decode_structured_blob(value: str, max_bytes: int) -> str | None:
    """Unwrap at most two encodings, accepting only bounded structured text.

    Plain base64 user:password pairs in neutral fields remain unreported: their
    encoding alone is not evidence that a document contains a credential.
    """

    if max_bytes <= 0 or len(value) > min(max_bytes * 2, 131_072):
        return None
    current = value.strip()
    for _ in range(2):
        raw: bytes | None = None
        if re.fullmatch(r"[0-9a-fA-F]{16,}", current) and len(current) % 2 == 0:
            try:
                raw = bytes.fromhex(current)
            except ValueError:
                pass
        if raw is None and re.fullmatch(r"[A-Za-z0-9_+/=-]{16,}", current):
            try:
                raw = base64.b64decode(current + "=" * (-len(current) % 4), altchars=b"-_", validate=True)
            except (ValueError, binascii.Error):
                pass
        if raw is None or len(raw) > max_bytes:
            return None
        if raw.startswith(b"\x1f\x8b"):
            try:
                decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
                raw = decompressor.decompress(raw, max_bytes + 1)
                if len(raw) > max_bytes or not decompressor.eof:
                    return None
            except zlib.error:
                return None
        try:
            current = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
        if _structured_decoded_text(current):
            return current
    return None


def _decode_base64url_json(value: str) -> Mapping[str, Any] | None:
    try:
        padding = "=" * ((4 - len(value) % 4) % 4)
        decoded = base64.urlsafe_b64decode(value + padding)
        parsed = json.loads(decoded.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, binascii.Error):
        return None
    return parsed if isinstance(parsed, Mapping) else None


def _validated_jwt(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 3:
        return False
    header = _decode_base64url_json(parts[0])
    if header is None or not isinstance(header.get("alg"), str):
        return False
    payload = _decode_base64url_json(parts[1])
    return payload is not None and bool(parts[2])


def _validated_jwe(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 5:
        return False
    header = _decode_base64url_json(parts[0])
    return (
        header is not None
        and isinstance(header.get("alg"), str)
        and isinstance(header.get("enc"), str)
        and all(bool(parts[offset]) for offset in (2, 3, 4))
    )


def _credential_uri_carriers(text: str) -> Iterator[tuple[str, str, tuple[int, int]]]:
    for match in _CREDENTIAL_URI_RE.finditer(text):
        raw = match.group()
        if kind := uri_carrier_kind(raw):
            yield raw, kind, match.span()


def analyze_value(
    value: Any,
    *,
    path: str = "",
    field_classification: FieldClass | None = None,
    allow_base64: bool = True,
    sql_dialect: SQLDialect = "unknown",
) -> list[DetectedSecret]:
    """Analyze one scalar and return confidence-scored secret candidates."""

    if isinstance(value, bool) or value is None:
        return []
    text = str(value)
    stripped = text.strip()
    field_class = field_classification or classify_field(path)
    markup = stripped.startswith("<") and ("=" in stripped or "</" in stripped)
    if _looks_placeholder(stripped) and not markup:
        return [
            DetectedSecret(
                value="",
                secret_type="secret_indicator",
                score=0,
                detectors=("placeholder", "sensitive_field") if field_class != "neutral" else ("placeholder",),
                available=False,
            )
        ]

    from .discovery_credentials import COOKIE_HEAD, valid_basic_carrier, valid_cookie_carrier
    from .discovery_dsn import dsn_carriers

    dsns = list(dsn_carriers(text))
    if len(dsns) == 1 and dsns[0][0] == stripped:
        return (
            [_candidate(stripped, "connection_string", 96, "connection_dsn", span=dsns[0][1])]
            if dsns[0][2]
            else [DetectedSecret("", "secret_indicator", 0, ("placeholder",), available=False)]
        )
    if valid_cookie_carrier(stripped, body=normalize_field_name(path).endswith("cookie")):
        return [_candidate(stripped, "session_cookie", 90, "cookie_carrier")]
    if normalize_field_name(path).endswith("auth") and valid_basic_carrier(stripped, encoded=True):
        return [_candidate(stripped, "encoded_credentials", 92, "registry_auth", "credential_pair")]

    detections: list[DetectedSecret] = []
    if stripped.startswith("#cloud-config"):
        from .discovery_cloudinit import CloudInitPasswords

        cloudinit = CloudInitPasswords(
            lambda secret: detections.append(_candidate(secret, "password", 85, "cloud_init_password")),
            lambda _reason: None,
        )
        try:
            cloudinit.feed(text)
            cloudinit.finish()
        finally:
            cloudinit.close()
    literals = AssignmentLiterals(text, lambda name: _secret_key_kind(name) is not None)
    for assignment_literal in literals.items:
        kind = _secret_key_kind(assignment_literal.name)
        if kind and assignment_literal.value and not _looks_placeholder(assignment_literal.value):
            detections.append(
                _candidate(
                    assignment_literal.value,
                    kind,
                    85,
                    "credential_pair",
                    "sensitive_field",
                    span=(assignment_literal.start, assignment_literal.end),
                    field_name=assignment_literal.name,
                )
            )
    for match in _PRIVATE_KEY_RE.finditer(text):
        detections.append(_candidate(match.group(0), "private_key", 100, "private_key_pem", span=match.span()))
    for match in _JWE_RE.finditer(text):
        token = match.group(1)
        if _validated_jwe(token):
            detections.append(_candidate(token, "jwe", 95, "jwe_structure", span=match.span(1)))
    for match in _JWT_RE.finditer(text):
        token = match.group(1)
        if _validated_jwt(token):
            detections.append(_candidate(token, "jwt", 95, "jwt_structure", span=match.span(1)))
    for match in _AWS_ACCESS_RE.finditer(text):
        detections.append(
            DetectedSecret(
                value=match.group(1),
                secret_type="aws_access_key_id",
                score=0,
                detectors=("aws_access_key_format",),
                available=False,
            )
        )
    if _PROVIDER_MARKER.search(text) is not None:
        for regex, secret_type, detector, score in (
            (_GOOGLE_API_RE, "google_api_key", "google_api_key_format", 98),
            (_GITHUB_RE, "github_token", "github_token_format", 98),
            (_GITLAB_RE, "gitlab_token", "gitlab_token_format", 98),
            (_SLACK_RE, "slack_token", "slack_token_format", 98),
            (_STRIPE_RE, "stripe_key", "stripe_key_format", 98),
            (_VAULT_RE, "vault_token", "vault_token_format", 98),
            (_NPM_RE, "npm_token", "npm_token_format", 98),
        ):
            for match in regex.finditer(text):
                detections.append(_candidate(match.group(1), secret_type, score, detector, span=match.span(1)))
        for regex, secret_type in _PROVIDER_TOKENS:
            for match in regex.finditer(text):
                detections.append(
                    _candidate(match.group(1), secret_type, 96, "provider_token_format", span=match.span(1))
                )
    for regex, secret_type, score, rule_id in (
        (_PASSWORD_HASH_RE, "password_hash", 70, "password_hash"),
        (_WEBHOOK_RE, "webhook", 96, "webhook_url"),
        (_SESSION_RE, "session_cookie", 70, "session_assignment"),
    ):
        for match in regex.finditer(text):
            secret = match.group(1) if match.lastindex else match.group(0)
            if not _looks_placeholder(secret):
                detections.append(_candidate(secret, secret_type, score, rule_id, span=match.span()))
    for match in _AUTH_HEADER_RE.finditer(text):
        kind = match.group(1).lower()
        token = match.group(2)
        if kind == "basic":
            password = _decode_basic(token)
            if password:
                detections.append(
                    _candidate(match.group(0), "basic_auth", 92, "basic_auth", "credential_pair", span=match.span())
                )
        elif _plausible_opaque_secret(token):
            detections.append(_candidate(token, "bearer_token", 90, "bearer_auth"))
    for match in _KEY_VALUE_RE.finditer(text):
        if literals.overlap(*match.span()) is not None:
            continue
        raw_name = match.group(1)
        kind = _secret_key_kind(raw_name)
        if kind is None:
            continue
        secret = match.group(2) or match.group(3) or ""
        if secret and not _looks_placeholder(secret):
            detections.append(
                _candidate(
                    secret, kind, 85, "credential_pair", "sensitive_field", span=match.span(), field_name=raw_name
                )
            )
    for match in chain(SQL_IDENTIFIED_HEAD.finditer(text), SQL_PASSWORD_HEAD.finditer(text)):
        sql_reader = SQLLiteral(match.group(1), portion=max(64, len(text)), dialect=sql_dialect)
        try:
            end = match.end() + sql_reader.feed(text[match.end() :], final=True)
            secret = sql_reader.take()
        finally:
            sql_reader.close()
        if isinstance(secret, str) and len(secret) >= 4 and not _looks_placeholder(secret):
            detections.append(_candidate(secret, "password", 85, "sql_password", span=(match.start(), end)))
    if "\n" in text and "," in text:
        from .discovery_csv import CSVCell, CSVSecretStream

        def csv_cell(cell: CSVCell) -> None:
            kind = _secret_key_kind(str(cell.name))
            if kind and isinstance(cell.value, str) and not _looks_placeholder(cell.value):
                detections.append(_candidate(cell.value, kind, 82, "csv_secret_column", field_name=str(cell.name)))

        reader = CSVSecretStream(csv_cell, lambda _reason: None, portion=max(64, len(text)))
        try:
            reader.feed(text)
            reader.finish()
        finally:
            reader.close()
    for match in _XML_SECRET_RE.finditer(text):
        kind = _secret_key_kind(match.group(1))
        secret = html.unescape(match.group(2).strip())
        if kind and not _looks_placeholder(secret):
            detections.append(_candidate(secret, kind, 85, "xml_secret_element"))
    for tag in _TAG_RE.finditer(text):
        attributes = {name.lower(): html.unescape(raw) for name, _quote, raw in _ATTR_RE.findall(tag.group(2))}
        input_kind = _secret_key_kind(attributes.get("name", ""))
        if tag.group(1).lower() == "input" and input_kind:
            secret = attributes.get("value", "")
            if not _looks_placeholder(secret):
                detections.append(_candidate(secret, input_kind, 85, "html_secret_input"))
        for name, secret in attributes.items():
            kind = _secret_key_kind(name.removeprefix("data-"))
            if kind and not _looks_placeholder(secret):
                detections.append(_candidate(secret, kind, 85, "xml_secret_attribute"))
    lowered_text = text.lower()
    if "sv=" in lowered_text and any(marker in lowered_text for marker in ("&se=", "&sp=", "&sr=")):
        for match in _AZURE_SAS_RE.finditer(text):
            signature = urllib.parse.unquote(match.group(1))
            if len(signature) >= 16:
                detections.append(_candidate(signature, "azure_sas_signature", 96, "azure_sas", span=match.span(1)))
    for match in _AZURE_ACCOUNT_KEY_RE.finditer(text):
        account_key = match.group(1)
        if not _looks_placeholder(account_key):
            detections.append(
                _candidate(
                    account_key,
                    "azure_storage_key",
                    98,
                    "azure_storage_connection_string",
                    "credential_pair",
                )
            )

    cookie_spans = []
    for header in COOKIE_HEAD.finditer(text):
        end = text.find("\n", header.start())
        end = len(text) if end < 0 else end
        raw = text[header.start() : end].rstrip("\r")
        if valid_cookie_carrier(raw):
            cookie_spans.append((raw, "session_cookie", (header.start(), header.start() + len(raw))))
    carriers = (
        [(raw, "connection_string", span) for raw, span, _available in dsns]
        + cookie_spans
        + list(_credential_uri_carriers(text))
    )
    outer_carriers = []
    maximum_end = -1
    for carrier in sorted(carriers, key=lambda row: (row[2][0], -row[2][1])):
        if carrier[2][1] > maximum_end:
            outer_carriers.append(carrier)
            maximum_end = carrier[2][1]
    carriers = outer_carriers
    dsn_spans = {span: available for _raw, span, available in dsns}
    for raw, kind, span in carriers:
        if span in dsn_spans and not dsn_spans[span]:
            detections.append(
                DetectedSecret("", "secret_indicator", 0, ("connection_dsn", "placeholder"), available=False, span=span)
            )
            continue
        detections.append(
            _candidate(
                raw,
                kind,
                96,
                "connection_dsn"
                if span in dsn_spans
                else "cookie_carrier"
                if kind == "session_cookie"
                else "credential_uri"
                if kind == "connection_string"
                else "signed_url",
                span=span,
            )
        )
    if carriers:
        detections = [
            d
            for d in detections
            if d.span is None
            or "credential_uri" in d.detectors
            or "signed_url" in d.detectors
            or "connection_dsn" in d.detectors
            or "cookie_carrier" in d.detectors
            or not any(a <= d.span[0] and d.span[1] <= b for _v, _k, (a, b) in carriers)
        ]

    if field_class in {"strong", "medium"}:
        normalized = normalize_field_name(path)
        if any(name in normalized for name in ("password", "passwd", "pwd")):
            secret_type = "password"
        elif normalized.endswith(("aws_secret_access_key", "secret_access_key")):
            secret_type = "aws_secret_access_key"
        elif any(name in normalized for name in ("azure_storage_key", "storage_account_key", "account_key")):
            secret_type = "azure_storage_key"
        else:
            secret_type = "secret"
        decoded_value_added = False
        base64_contexts = (
            "password",
            "passwd",
            "pwd",
            "client_secret",
            "private_key",
            "secret_access_key",
            "authorization",
            "api_token",
            "refresh_token",
            "credentials",
            "connection_string",
            "dsn",
            "auth",
            "dockerconfigjson",
            "client_key_data",
        )
        if allow_base64 and normalized.endswith(base64_contexts):
            decoded = _decode_credential_base64(stripped)
            if decoded:
                if decoded.lstrip().startswith(("{", "[")):
                    detections.append(_candidate(decoded, "encoded_credentials", 78, "base64_credential"))
                    decoded_value_added = True
                elif _PRIVATE_KEY_RE.search(decoded):
                    detections.append(_candidate(decoded, "private_key", 99, "base64_credential", "private_key_pem"))
                    decoded_value_added = True
                elif (pair := _split_user_password(decoded)) is not None:
                    detections.append(_candidate(pair[1], "password", 92, "base64_credential", "credential_pair"))
                    decoded_value_added = True
                elif not _looks_placeholder(decoded):
                    detections.append(_candidate(decoded, secret_type, 88, "base64_credential", "sensitive_field"))
                    decoded_value_added = True
        base_score = 85 if field_class == "strong" else 68
        if field_class == "medium" and not _plausible_opaque_secret(stripped, minimum=8):
            base_score = 0
        if len(stripped) < 4:
            base_score -= 20
        if re.fullmatch(r"[0-9a-fA-F]{32,128}", stripped) and normalized.endswith(("hash", "checksum")):
            base_score = 0
        has_strong_format = any(detection.available and detection.score >= 90 for detection in detections)
        if base_score >= 55 and not has_strong_format and not decoded_value_added:
            detectors = ["sensitive_field"]
            if _shannon_entropy(stripped) >= 3.5:
                detectors.append("plausible_value")
                base_score = min(94, base_score + 5)
            detections.append(
                _candidate(text, secret_type, base_score, *detectors, span=(0, len(text)), field_name=path)
            )

    explicit_values = {item.value for item in detections if item.available and isinstance(item.value, str)}
    spans = sorted(item.span for item in detections if item.span is not None)
    detections.extend(
        _candidate(candidate, "high_entropy", 55, "entropy_candidate")
        for candidate in entropy_candidates(text, path, explicit_values, spans, literals)
    )

    unique: dict[object, DetectedSecret] = {}
    for detection in detections:
        identity = getattr(detection.value, "secret_digest", None)
        key = ("encoded_bytes", identity) if identity is not None else detection.value
        previous = unique.get(key)
        if previous is None:
            unique[key] = detection
        else:
            preferred = detection if detection.score > previous.score else previous
            unique[key] = replace(
                preferred, detectors=tuple(dict.fromkeys((*previous.detectors, *detection.detectors)))
            )
    return list(unique.values())
