"""Reusable, value-oriented secret detection primitives.

The engine deliberately does not decide which database columns should be read.
Callers provide every value in scope and this module recursively inspects nested
containers and JSON text while returning stable, fingerprinted matches.
"""

from __future__ import annotations

import base64
import binascii
import html
import json
import math
import re
import zlib
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from hashlib import sha256
from typing import Any
from urllib.parse import urlsplit


@dataclass(frozen=True)
class SecretMatch:
    detector: str
    confidence: str
    object_path: str
    value: str


_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("password", "high", re.compile(r"(?i)\b(?:password|passwd|pwd)\s*[=:]\s*[\"']?([^\s,;\"']{4,})")),
    (
        "private_key",
        "high",
        re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
    ),
    ("certificate", "medium", re.compile(r"-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----")),
    ("bearer_token", "high", re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{12,})")),
    ("basic_auth", "high", re.compile(r"(?i)\bbasic\s+([A-Za-z0-9+/]{8,}={0,2})")),
    ("jwt", "high", re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\b")),
    ("aws_access_key", "high", re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA)[A-Z0-9]{16}\b")),
    ("github_token", "high", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b")),
    ("gitlab_token", "high", re.compile(r"\bglpat-[A-Za-z0-9_-]{16,255}\b")),
    ("slack_token", "high", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,255}\b")),
    ("stripe_key", "high", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,255}\b")),
    ("api_token", "high", re.compile(r"(?<![\w-])sk-(?:proj-|ant-[\w-]{4,})?[A-Za-z0-9_-]{20,}(?![\w-])")),
    ("grafana_token", "high", re.compile(r"(?<!\w)glsa_[A-Za-z0-9_-]{20,}(?!\w)")),
    ("digitalocean_token", "high", re.compile(r"(?<!\w)dop_v1_[A-Za-z0-9]{32,}(?!\w)")),
    ("shopify_token", "high", re.compile(r"(?<!\w)shpat_[A-Za-z0-9]{24,}(?!\w)")),
    ("docker_token", "high", re.compile(r"(?<!\w)dckr_pat_[A-Za-z0-9_-]{20,}(?!\w)")),
    ("pypi_token", "high", re.compile(r"(?<!\w)pypi-AgEI[A-Za-z0-9_-]{16,}(?!\w)")),
    ("sendgrid_token", "high", re.compile(r"(?<!\w)SG\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}(?!\w)")),
    ("twilio_token", "high", re.compile(r"(?<!\w)SK[0-9a-fA-F]{32}(?!\w)")),
    ("telegram_token", "high", re.compile(r"(?<!\w)\d{6,12}:AA[A-Za-z0-9_-]{20,}(?!\w)")),
    (
        "webhook",
        "high",
        re.compile(r"https://(?:hooks\.slack\.com/services|discord(?:app)?\.com/api/webhooks)/[^\s\"']+"),
    ),
    ("password_hash", "medium", re.compile(r"\$(?:2[aby]|argon2(?:id|i|d)|scrypt)\$[^\s\"']{20,}")),
    (
        "connection_string",
        "high",
        re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|clickhouse)://[^\s\"']+"),
    ),
    (
        "credential_pair",
        "high",
        re.compile(r"(?i)\b(?:user(?:name)?|login)\s*[=:]\s*[^\s,;]+.{0,80}?\b(?:pass(?:word)?|pwd)\s*[=:]\s*[^\s,;]+"),
    ),
    ("client_secret", "high", re.compile(r"(?i)\bclient[_-]?secret\s*[=:]\s*[\"']?([^\s,;\"']{6,})")),
    (
        "access_token",
        "high",
        re.compile(r"(?i)\b(?:access|refresh)[_-]?token\s*[=:]\s*[\"']?([^\s,;\"']{8,})"),
    ),
    (
        "api_key",
        "high",
        re.compile(r"(?i)\b(?:api[_-]?key|access[_-]?token|secret[_-]?key)\s*[=:]\s*[\"']?([^\s,;\"']{8,})"),
    ),
    (
        "session_cookie",
        "medium",
        re.compile(r"(?i)\b(?:session(?:id)?|sid|auth_token)\s*[=:]\s*([A-Za-z0-9._~+/-]{8,})"),
    ),
)

_SECRET_KEY_RE = re.compile(
    r"(?i)(?:^|[_\-.])(password|passwd|pwd|passphrase|pass|credential|credentials|cred|creds|secret|apisecret|token|api[_-]?key|access[_-]?key|client[_-]?secret|session|cookie|private[_-]?key)(?:$|[_\-.])"
)
_NON_SECRET_FIELD_RE = re.compile(
    r"(?i)(?:^|_)(?:public_key|api_key_id|access_key_id|secret_key_id|token_id|checksum|hash)(?:$|_)"
)
_ASSIGNMENT_RE = re.compile(
    r"(?i)(?<![\w.])(?:--)?((?:[A-Za-z][A-Za-z0-9]{0,32}[._-])*"
    r"(?:password|passwd|pwd|passphrase|pass|credential|credentials|cred|creds|"
    r"client[_-]?secret|api[_-]?secret|apisecret|api[_-]?token|"
    r"auth[_-]?token|refresh[_-]?token|secret[_-]?key|apikey))"
    r"[\"']?\s*(?:=>|[:=])\s*(?:[\"']([^\"'\s,;<>]+)[\"']|([^\s,;&<>]+))"
)
_SQL_PASSWORD_RE = re.compile(r"(?i)\b(?:WITH\s+)?PASSWORD\s+['\"]([^'\"\s;]{4,})['\"]")
_XML_ELEMENT_RE = re.compile(r"(?is)<([A-Za-z][\w:.-]{0,79})\b[^>]{0,2048}>([^<>]{4,4096})</\1\s*>")
_XML_TAG_RE = re.compile(r"<([A-Za-z][\w:.-]{0,79})\b([^<>]{0,2048})>", re.IGNORECASE)
_XML_ATTR_RE = re.compile(r"([A-Za-z][\w:.-]{0,79})\s*=\s*([\"'])(.*?)\2", re.DOTALL)
_MAX_DECODED_BYTES = 64 * 1024
_WORD_RE = re.compile(r"[A-Za-z0-9_+/=-]{20,256}")
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
        "true",
        "<redacted>",
        "<value>",
    }
)
_SECRET_SENTINEL_MASK_RE = re.compile(r"(?:\*{3,}|x{4,})", re.IGNORECASE)
_TEMPLATE_PLACEHOLDER_RE = re.compile(r"(?:\$\{[^}]+\}|\{\{[^}]+\}\})")


def detector_names() -> tuple[str, ...]:
    return tuple(dict.fromkeys([item[0] for item in _PATTERNS] + ["url_credentials", "generic_secret", "high_entropy"]))


def fingerprint(value: str) -> str:
    return sha256(value.encode("utf-8", errors="surrogatepass")).hexdigest()


def mask_secret(value: str) -> str:
    if "PRIVATE KEY-----" in value:
        return "<private-key:redacted>"
    if "CERTIFICATE-----" in value:
        return "<certificate:redacted>"
    if len(value) <= 8:
        return "*" * max(4, len(value))
    return f"{value[:4]}...{value[-4:]}"


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    size = len(value)
    return -sum((count / size) * math.log2(count / size) for count in counts.values())


def _url_credential(text: str) -> Iterable[str]:
    # Only try the beginning of a scheme. Retrying at every position inside
    # a long non-URL token makes ordinary discovery values quadratic.
    for match in re.finditer(r"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*://[^\s\"']+", text):
        candidate = match.group(0)
        try:
            parsed = urlsplit(candidate)
        except ValueError:
            continue
        if parsed.username is not None and parsed.password is not None:
            yield candidate


def _is_secret_sentinel(value: Any) -> bool:
    """Return whether a value is an explicit non-secret marker."""

    if isinstance(value, bool):
        return True
    text = str(value).strip().casefold()
    return text in _SECRET_SENTINELS or bool(
        _SECRET_SENTINEL_MASK_RE.fullmatch(text) or _TEMPLATE_PLACEHOLDER_RE.fullmatch(text)
    )


def _scan_text(text: str, path: str, enabled: set[str]) -> list[SecretMatch]:
    found: list[SecretMatch] = []
    for name, confidence, pattern in _PATTERNS:
        if name not in enabled:
            continue
        for match in pattern.finditer(text):
            value = match.group(1) if match.lastindex else match.group(0)
            if value and not _is_secret_sentinel(value):
                found.append(SecretMatch(name, confidence, path, value))
    for match in _ASSIGNMENT_RE.finditer(text):
        value = match.group(2) or match.group(3) or ""
        detector = _key_detector(match.group(1))
        if detector in enabled and len(value) >= 4 and not _is_secret_sentinel(value):
            found.append(SecretMatch(detector, "high", path, value))
    if "password" in enabled:
        for match in _SQL_PASSWORD_RE.finditer(text):
            if not _is_secret_sentinel(match.group(1)):
                found.append(SecretMatch("password", "high", path, match.group(1)))
    for match in _XML_ELEMENT_RE.finditer(text):
        detector = _key_detector(match.group(1))
        value = html.unescape(match.group(2).strip())
        if (
            _SECRET_KEY_RE.search(_normalize_secret_key(match.group(1)))
            and detector in enabled
            and not _is_secret_sentinel(value)
        ):
            found.append(SecretMatch(detector, "high", path, value))
    for tag in _XML_TAG_RE.finditer(text):
        attrs = {name.lower(): html.unescape(raw) for name, _quote, raw in _XML_ATTR_RE.findall(tag.group(2))}
        named = attrs.get("name", "") if tag.group(1).lower() == "input" else ""
        if named and _SECRET_KEY_RE.search(_normalize_secret_key(named)):
            value = attrs.get("value", "")
            detector = _key_detector(named)
            if value and detector in enabled and not _is_secret_sentinel(value):
                found.append(SecretMatch(detector, "high", path, value))
        for name, value in attrs.items():
            normalized = _normalize_secret_key(name.removeprefix("data-"))
            detector = _key_detector(normalized)
            if _SECRET_KEY_RE.search(normalized) and value and detector in enabled and not _is_secret_sentinel(value):
                found.append(SecretMatch(detector, "high", path, value))
    if "url_credentials" in enabled:
        found.extend(SecretMatch("url_credentials", "high", path, value) for value in _url_credential(text))
    path_field = _normalize_secret_key(path.rsplit(".", 1)[-1])
    if "high_entropy" in enabled and not _NON_SECRET_FIELD_RE.search(path_field):
        for candidate in _WORD_RE.findall(text):
            if any(
                match.detector != "high_entropy"
                and (match.value == candidate or ("=" in candidate and match.value in candidate))
                for match in found
            ):
                continue
            classes = sum(
                bool(re.search(pattern, candidate)) for pattern in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]")
            )
            if classes >= 3 and re.search(r"[a-z]", candidate) and _entropy(candidate) >= 4.2:
                try:
                    decoded_candidate = base64.b64decode(
                        candidate + "=" * (-len(candidate) % 4), altchars=b"-_", validate=True
                    ).decode("utf-8")
                except (ValueError, UnicodeDecodeError, binascii.Error):
                    decoded_candidate = ""
                if decoded_candidate and all(
                    character.isprintable() or character.isspace() for character in decoded_candidate
                ):
                    continue
                found.append(SecretMatch("high_entropy", "low", path, candidate))
    return found


def _normalize_secret_key(key: str) -> str:
    """Normalize delimited, camelCase and acronym-based field names."""
    separated = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", key)
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", separated)
    return re.sub(r"[\s.\-]+", "_", separated).lower()


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


def _decode_structured_blob(value: str) -> str | None:
    """Decode only small, structured text; random encoded bytes are not evidence."""

    compact = value.strip()
    for _ in range(2):
        if not 16 <= len(compact) <= _MAX_DECODED_BYTES * 2:
            return None
        raw: bytes | None = None
        if len(compact) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]{16,}", compact):
            try:
                raw = bytes.fromhex(compact)
            except ValueError:
                pass
        elif re.fullmatch(r"[A-Za-z0-9_+/=-]{16,}", compact):
            try:
                raw = base64.b64decode(compact + "=" * (-len(compact) % 4), altchars=b"-_", validate=True)
            except (ValueError, binascii.Error):
                pass
        if raw is None or len(raw) > _MAX_DECODED_BYTES:
            return None
        if raw.startswith(b"\x1f\x8b"):
            try:
                unzip = zlib.decompressobj(16 + zlib.MAX_WBITS)
                raw = unzip.decompress(raw, _MAX_DECODED_BYTES + 1)
                if not unzip.eof or len(raw) > _MAX_DECODED_BYTES:
                    return None
            except zlib.error:
                return None
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
        stripped = decoded.lstrip()
        if stripped.startswith(("{", "[")):
            try:
                if isinstance(json.loads(decoded), (dict, list)):
                    return decoded
            except ValueError:
                pass
        if _ASSIGNMENT_RE.search(decoded) or _XML_ELEMENT_RE.search(decoded) or _SQL_PASSWORD_RE.search(decoded):
            return decoded
        compact = decoded.strip()
    return None


def scan_value(
    value: Any,
    *,
    object_path: str = "$",
    enabled: Iterable[str] | None = None,
    _depth: int = 0,
    _decode_depth: int = 0,
) -> list[SecretMatch]:
    """Inspect a scalar or nested value without dropping malformed JSON text."""

    if _depth > 32:
        return []
    enabled_set = set(enabled or detector_names())
    if isinstance(value, Mapping):
        matches: list[SecretMatch] = []
        for raw_key, nested in value.items():
            key = str(raw_key)
            path = f"{object_path}.{key}"
            normalized_key = _normalize_secret_key(key)
            nested_json = False
            if isinstance(nested, str) and len(nested) <= _MAX_DECODED_BYTES and nested.lstrip().startswith(("{", "[")):
                try:
                    nested_json = isinstance(json.loads(nested), (dict, list))
                except ValueError:
                    pass
            if (
                _SECRET_KEY_RE.search(normalized_key)
                and not _NON_SECRET_FIELD_RE.search(normalized_key)
                and nested is not None
                and nested != ""
                and not nested_json
                and not (isinstance(nested, str) and _decode_structured_blob(nested) is not None)
                and not isinstance(nested, (Mapping, list, tuple, set))
                and not _is_secret_sentinel(nested)
            ):
                detector = _key_detector(normalized_key)
                if detector in enabled_set:
                    matches.append(SecretMatch(detector, "high", path, str(nested)))
            matches.extend(
                scan_value(
                    nested, object_path=path, enabled=enabled_set, _depth=_depth + 1, _decode_depth=_decode_depth
                )
            )
        return matches
    if isinstance(value, (list, tuple, set)):
        matches = []
        for index, nested in enumerate(value):
            matches.extend(
                scan_value(
                    nested,
                    object_path=f"{object_path}[{index}]",
                    enabled=enabled_set,
                    _depth=_depth + 1,
                    _decode_depth=_decode_depth,
                )
            )
        return matches
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
    elif isinstance(value, str):
        text = value
    else:
        return []

    stripped = text.strip()
    if stripped.startswith(("{", "[")):
        try:
            parsed = json.loads(stripped)
        except (TypeError, ValueError, json.JSONDecodeError):
            parsed = None
        if parsed is not None:
            return scan_value(
                parsed, object_path=object_path, enabled=enabled_set, _depth=_depth + 1, _decode_depth=_decode_depth
            )
    matches = _scan_text(text, object_path, enabled_set)
    if _decode_depth < 2:
        decoded = _decode_structured_blob(stripped)
        if decoded is not None:
            matches.extend(
                scan_value(
                    decoded,
                    object_path=object_path,
                    enabled=enabled_set,
                    _depth=_depth + 1,
                    _decode_depth=_decode_depth + 1,
                )
            )
    return list(dict.fromkeys(matches))


def decode_basic_identity(value: str) -> str | None:
    """Return decoded Basic identity for consumers that want extra context."""

    try:
        return base64.b64decode(value, validate=True).decode("utf-8", errors="replace")
    except (ValueError, UnicodeError):
        return None


__all__ = [
    "SecretMatch",
    "decode_basic_identity",
    "detector_names",
    "fingerprint",
    "mask_secret",
    "scan_value",
]
