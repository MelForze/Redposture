"""Reusable, value-oriented secret detection primitives.

The engine deliberately does not decide which database columns should be read.
Callers provide every value in scope and this module recursively inspects nested
containers and JSON text while returning stable, fingerprinted matches.
"""

from __future__ import annotations

import base64
import json
import math
import re
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
    r"(?i)(?:^|[_\-.])(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|session|cookie|private[_-]?key)(?:$|[_\-.])"
)
_WORD_RE = re.compile(r"[A-Za-z0-9_+/=-]{20,256}")


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
    for match in re.finditer(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s\"']+", text):
        candidate = match.group(0)
        try:
            parsed = urlsplit(candidate)
        except ValueError:
            continue
        if parsed.username is not None and parsed.password is not None:
            yield candidate


def _scan_text(text: str, path: str, enabled: set[str]) -> list[SecretMatch]:
    found: list[SecretMatch] = []
    for name, confidence, pattern in _PATTERNS:
        if name not in enabled:
            continue
        for match in pattern.finditer(text):
            value = match.group(1) if match.lastindex else match.group(0)
            if value:
                found.append(SecretMatch(name, confidence, path, value))
    if "url_credentials" in enabled:
        found.extend(SecretMatch("url_credentials", "high", path, value) for value in _url_credential(text))
    if "high_entropy" in enabled:
        for candidate in _WORD_RE.findall(text):
            classes = sum(
                bool(re.search(pattern, candidate)) for pattern in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]")
            )
            if classes >= 3 and _entropy(candidate) >= 4.2:
                found.append(SecretMatch("high_entropy", "low", path, candidate))
    return found


def _key_detector(key: str) -> str:
    lowered = key.lower().replace("-", "_")
    if "client_secret" in lowered:
        return "client_secret"
    if "password" in lowered or "passwd" in lowered or lowered.endswith("pwd"):
        return "password"
    if "session" in lowered or "cookie" in lowered or lowered == "sid":
        return "session_cookie"
    if "api_key" in lowered or "apikey" in lowered:
        return "api_key"
    if "access_token" in lowered or "refresh_token" in lowered:
        return "access_token"
    return "generic_secret"


def scan_value(
    value: Any,
    *,
    object_path: str = "$",
    enabled: Iterable[str] | None = None,
    _depth: int = 0,
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
            if (
                _SECRET_KEY_RE.search(key)
                and nested is not None
                and nested != ""
                and not isinstance(nested, (Mapping, list, tuple, set))
            ):
                detector = _key_detector(key)
                if detector in enabled_set:
                    matches.append(SecretMatch(detector, "high", path, str(nested)))
            matches.extend(scan_value(nested, object_path=path, enabled=enabled_set, _depth=_depth + 1))
        return matches
    if isinstance(value, (list, tuple, set)):
        matches = []
        for index, nested in enumerate(value):
            matches.extend(
                scan_value(nested, object_path=f"{object_path}[{index}]", enabled=enabled_set, _depth=_depth + 1)
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
            return scan_value(parsed, object_path=object_path, enabled=enabled_set, _depth=_depth + 1)
    return _scan_text(text, object_path, enabled_set)


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
