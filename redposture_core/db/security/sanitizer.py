"""Payload sanitizer used before persisting DB blobs or raw JSON."""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from .secrets import SecretCandidate

_SECRET_KEY_RE = re.compile(
    r"(?i)(password|passwd|secret|token|authorization|api[_-]?key|access[_-]?key|private[_-]?key|uri|dsn|conn|connection)"
)
_BASIC_RE = re.compile(r"(?i)(?:authorization\s*:\s*)?basic\s+([A-Za-z0-9+/=]+)")
_URL_AUTH_RE = re.compile(r"^(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*://)(?P<user>[^:/@\s]+)(?::(?P<password>[^@\s]*))?@")
_GENERIC_DSN_AUTH_RE = re.compile(
    r"(?<!://)(?P<user>[A-Za-z0-9_.-]{1,64}):(?P<password>[^@\s\"'\\]{1,256})@(?P<host>\([^)]+\)|[A-Za-z0-9_.-]+(?::\d+)?)(?P<suffix>/[^\s\"']*)?"
)
_JSON_ASSIGN_RE = re.compile(
    r'(?i)"(?P<key>[^"]*(?:password|passwd|secret|token|authorization|api[_-]?key|access[_-]?key|private[_-]?key|uri|dsn|conn|connection)[^"]*)"\s*:\s*"(?P<value>[^"]*)"'
)
_PLAIN_ASSIGN_RE = re.compile(r"(?i)(password|secret|token|api[_-]?key)\s*[=:]\s*([^\s,;]+)")


@dataclass(frozen=True)
class SanitizedPayload:
    data: Any
    preview_text: str
    secret_candidates: tuple[SecretCandidate, ...]


def _redacted(kind: str) -> str:
    return f"<redacted:{kind}>"


def _sanitize_string(value: str, *, source_hint: str | None = None) -> tuple[str, list[SecretCandidate]]:
    candidates: list[SecretCandidate] = []
    sanitized = value
    stripped = sanitized.strip()

    if stripped.startswith(("{", "[")) and stripped.endswith(("}", "]")):
        try:
            embedded = json.loads(stripped)
        except Exception:
            embedded = None
        if isinstance(embedded, dict | list):
            sanitized_embedded, embedded_candidates = _sanitize_object(embedded, source_hint=source_hint)
            candidates.extend(embedded_candidates)
            return json.dumps(sanitized_embedded, ensure_ascii=False, sort_keys=True), candidates

    basic_match = _BASIC_RE.search(sanitized)
    if basic_match:
        token = basic_match.group(1)
        try:
            decoded = base64.b64decode(token).decode("utf-8")
        except Exception:
            decoded = ""
        if ":" in decoded:
            candidates.append(
                SecretCandidate(
                    secret_kind="basic_auth",
                    raw_value=decoded,
                    redacted_value="<redacted:basic_auth>",
                    source_hint=source_hint,
                )
            )
            sanitized = sanitized.replace(token, "<redacted:basic_auth>")

    url_match = _URL_AUTH_RE.match(sanitized)
    if url_match:
        raw_secret = f"{url_match.group('user')}:{url_match.group('password') or ''}"
        candidates.append(
            SecretCandidate(
                secret_kind="url_basic_auth",
                raw_value=raw_secret,
                redacted_value="<redacted:url_basic_auth>",
                source_hint=source_hint,
            )
        )
        parsed = urlparse(sanitized)
        sanitized = urlunparse(
            (
                parsed.scheme,
                f"<redacted:url_basic_auth>@{parsed.hostname or ''}{f':{parsed.port}' if parsed.port else ''}",
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment,
            )
        )

    def dsn_repl(match: re.Match[str]) -> str:
        raw_secret = f"{match.group('user')}:{match.group('password')}"
        candidates.append(
            SecretCandidate(
                secret_kind="dsn_auth",
                raw_value=raw_secret,
                redacted_value="<redacted:dsn_auth>",
                source_hint=source_hint,
            )
        )
        return f"<redacted:dsn_auth>@{match.group('host')}{match.group('suffix') or ''}"

    sanitized = _GENERIC_DSN_AUTH_RE.sub(dsn_repl, sanitized)

    if "://" in sanitized:
        parsed = urlparse(sanitized)
        if parsed.query:
            changed = False
            updated_query: list[tuple[str, str]] = []
            for key, item in parse_qsl(parsed.query, keep_blank_values=True):
                if _SECRET_KEY_RE.search(key):
                    candidates.append(
                        SecretCandidate(
                            secret_kind=key.lower(),
                            raw_value=item,
                            redacted_value=_redacted(key.lower()),
                            source_hint=source_hint,
                        )
                    )
                    updated_query.append((key, _redacted(key.lower())))
                    changed = True
                else:
                    updated_query.append((key, item))
            if changed:
                sanitized = urlunparse(
                    (
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        urlencode(updated_query),
                        parsed.fragment,
                    )
                )

    def json_repl(match: re.Match[str]) -> str:
        key = match.group("key")
        raw_value = match.group("value")
        kind = key.lower()
        candidates.append(
            SecretCandidate(
                secret_kind=kind,
                raw_value=raw_value,
                redacted_value=_redacted(kind),
                source_hint=source_hint,
            )
        )
        return f'"{key}": "{_redacted(kind)}"'

    sanitized = _JSON_ASSIGN_RE.sub(json_repl, sanitized)

    def repl(match: re.Match[str]) -> str:
        kind = match.group(1).lower()
        raw_value = match.group(2)
        candidates.append(
            SecretCandidate(
                secret_kind=kind, raw_value=raw_value, redacted_value=_redacted(kind), source_hint=source_hint
            )
        )
        return f"{match.group(1)}={_redacted(kind)}"

    sanitized = _PLAIN_ASSIGN_RE.sub(repl, sanitized)
    return sanitized, candidates


def _sanitize_object(value: Any, *, source_hint: str | None = None) -> tuple[Any, list[SecretCandidate]]:
    candidates: list[SecretCandidate] = []
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            nested_hint = f"{source_hint}.{key_text}" if source_hint else key_text
            if _SECRET_KEY_RE.search(key_text):
                if item is not None:
                    candidates.append(
                        SecretCandidate(
                            secret_kind=key_text.lower(),
                            raw_value=str(item),
                            redacted_value=_redacted(key_text.lower()),
                            source_hint=nested_hint,
                        )
                    )
                if isinstance(item, str):
                    nested_value, nested_candidates = _sanitize_string(item, source_hint=nested_hint)
                    candidates.extend(nested_candidates)
                    if nested_candidates:
                        result[key_text] = nested_value
                        continue
                result[key_text] = _redacted(key_text.lower())
                continue
            sanitized_item, nested_candidates = _sanitize_object(item, source_hint=nested_hint)
            result[key_text] = sanitized_item
            candidates.extend(nested_candidates)
        return result, candidates
    if isinstance(value, list):
        items: list[Any] = []
        for index, item in enumerate(value):
            nested_hint = f"{source_hint}[{index}]" if source_hint else f"[{index}]"
            sanitized_item, nested_candidates = _sanitize_object(item, source_hint=nested_hint)
            items.append(sanitized_item)
            candidates.extend(nested_candidates)
        return items, candidates
    if isinstance(value, str):
        return _sanitize_string(value, source_hint=source_hint)
    return value, candidates


def sanitize_payload(value: Any) -> SanitizedPayload:
    """Sanitize arbitrary JSON-like payload and collect secret refs."""
    sanitized_data, secret_candidates = _sanitize_object(value)
    if isinstance(sanitized_data, str):
        preview = sanitized_data
    else:
        preview = json.dumps(sanitized_data, ensure_ascii=False, sort_keys=True)
    return SanitizedPayload(data=sanitized_data, preview_text=preview[:512], secret_candidates=tuple(secret_candidates))
