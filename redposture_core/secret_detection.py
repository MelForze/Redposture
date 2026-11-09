"""Reusable, value-oriented secret detection primitives.

The engine deliberately does not decide which database columns should be read.
Callers provide every value in scope and this module recursively inspects nested
containers and JSON text while returning stable, fingerprinted matches.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import zlib
from collections.abc import Callable, Collection, Iterable, Mapping
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any
from urllib.parse import urlsplit

from .discovery_entropy import _PEM_BLOCK_RE as _PEM_BLOCK_RE
from .discovery_entropy import _WORD_RE as _WORD_RE
from .discovery_entropy import _entropy as _entropy
from .discovery_entropy import _looks_like_resource_route as _looks_like_resource_route
from .discovery_paths import literal_field_component
from .discovery_values import DiskBackedText
from .secret_fields import (
    _NON_SECRET_FIELD_RE as _NON_SECRET_FIELD_RE,
)
from .secret_fields import (
    _SECRET_KEY_RE as _SECRET_KEY_RE,
)
from .secret_fields import (
    _SECRET_METADATA_SUFFIXES as _SECRET_METADATA_SUFFIXES,
)
from .secret_fields import (
    _SECRET_SENTINEL_MASK_RE as _SECRET_SENTINEL_MASK_RE,
)
from .secret_fields import (
    _SECRET_SENTINELS as _SECRET_SENTINELS,
)
from .secret_fields import (
    _TEMPLATE_PLACEHOLDER_RE as _TEMPLATE_PLACEHOLDER_RE,
)
from .secret_fields import (
    _cached_normalized_secret_key as _cached_normalized_secret_key,
)
from .secret_fields import (
    _is_secret_sentinel as _is_secret_sentinel,
)
from .secret_fields import (
    _key_detector as _key_detector,
)
from .secret_fields import (
    _normalize_secret_key as _normalize_secret_key,
)
from .secret_fields import (
    _uncached_normalized_secret_key as _uncached_normalized_secret_key,
)
from .secret_fields import (
    is_secret_field_name as is_secret_field_name,
)
from .secret_fields import (
    is_secret_metadata_field as is_secret_metadata_field,
)
from .secret_literals import has_toml_assignment


@dataclass(frozen=True)
class SecretMatch:
    detector: str
    confidence: str
    object_path: str | DiskBackedText
    value: str | DiskBackedText
    rule_ids: tuple[str, ...] = field(default=(), compare=False)
    detector_aliases: tuple[str, ...] = field(default=(), compare=False)


def detector_matches(match: SecretMatch, enabled: Collection[str]) -> bool:
    return match.detector in enabled or any(alias in enabled for alias in match.detector_aliases)


_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("password", "high", re.compile(r"(?i)\b(?:password|passwd|pwd)[^\S\r\n]*[=:][^\S\r\n]*[\"']?([^\s,;\"']{4,})")),
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

# Necessary literal starts only: these select candidates, never confirm a
# secret. Keep shared starts together (access_token matches two detectors).
_PATTERN_STARTERS = (
    (r"password|passwd|pwd", ("password",)),
    (r"-----BEGIN", ("private_key", "certificate")),
    (r"bearer", ("bearer_token",)),
    (r"basic", ("basic_auth",)),
    (r"eyJ", ("jwt",)),
    (r"AKIA|ASIA|AIDA|AROA", ("aws_access_key",)),
    (r"gh[pousr]_|github_pat_", ("github_token",)),
    (r"glpat-", ("gitlab_token",)),
    (r"xox[baprs]-", ("slack_token",)),
    (r"(?:sk|rk)_(?:live|test)_", ("stripe_key",)),
    (r"sk-", ("api_token",)),
    (r"glsa_", ("grafana_token",)),
    (r"dop_v1_", ("digitalocean_token",)),
    (r"shpat_", ("shopify_token",)),
    (r"dckr_pat_", ("docker_token",)),
    (r"pypi-AgEI", ("pypi_token",)),
    (r"SG\.", ("sendgrid_token",)),
    (r"SK(?=[0-9a-f])", ("twilio_token",)),
    (r":AA", ("telegram_token",)),
    (r"https://", ("webhook",)),
    (r"\$", ("password_hash",)),
    (r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|clickhouse)://", ("connection_string",)),
    (r"user(?:name)?|login", ("credential_pair",)),
    (r"client[_-]?secret", ("client_secret",)),
    (r"(?:access|refresh)[_-]?token", ("access_token", "api_key")),
    (r"api[_-]?key|secret[_-]?key", ("api_key",)),
    (r"session(?:id)?|sid|auth_token", ("session_cookie",)),
)
_INDEXED_PATTERNS = _PATTERNS
_STARTER_RE = re.compile("|".join(f"(?P<t{i}>{start.lower()})" for i, (start, _) in enumerate(_PATTERN_STARTERS)))
_STARTER_INDICES = tuple(
    tuple(i for i, (name, _, _) in enumerate(_INDEXED_PATTERNS) if name in names) for _, names in _PATTERN_STARTERS
)
_UNINDEXED_PATTERNS = tuple(
    i for i, (name, _, _) in enumerate(_INDEXED_PATTERNS) if not any(name in names for _, names in _PATTERN_STARTERS)
)


def _candidate_patterns(text: str) -> tuple[tuple[str, str, re.Pattern[str]], ...]:
    # Case-fold only bounded ASCII strings. Unicode IGNORECASE has additional
    # equivalences (e.g. dotted I) which must retain the full original path.
    if _PATTERNS is not _INDEXED_PATTERNS or len(text) > 65_536 or not text.isascii():
        return _PATTERNS
    indices = set(_UNINDEXED_PATTERNS)
    for match in _STARTER_RE.finditer(text.lower()):
        assert match.lastgroup is not None
        indices.update(_STARTER_INDICES[int(match.lastgroup[1:])])
    return tuple(_INDEXED_PATTERNS[i] for i in sorted(indices))


_ASSIGNMENT_RE = re.compile(
    r"(?i)(?<![\w.])(?:--)?((?:[A-Za-z][A-Za-z0-9]{0,32}[._-])*"
    r"(?:password|passwd|pwd|passphrase|pass|credential|credentials|cred|creds|"
    r"client[_-]?secret|api[_-]?secret|apisecret|api[_-]?token|"
    r"auth[_-]?token|refresh[_-]?token|secret[_-]?key|apikey|secret|token))"
    r"[\"']?[^\S\r\n]*(?:=>|[:=])[^\S\r\n]*(?:[\"']([^\"'\s,;]+)[\"']|([^\s,;&<>]+))"
)
_SQL_PASSWORD_RE = re.compile(r"(?i)\b(?:WITH\s+)?PASSWORD\s+['\"]([^'\"\s;]{4,})['\"]")
_XML_ELEMENT_RE = re.compile(r"(?is)<([A-Za-z][\w:.-]{0,79})\b[^>]{0,2048}>([^<>]{4,4096})</\1\s*>")
_XML_TAG_RE = re.compile(r"<([A-Za-z][\w:.-]{0,79})\b([^<>]{0,2048})>", re.IGNORECASE)
_XML_ATTR_RE = re.compile(r"([A-Za-z][\w:.-]{0,79})\s*=\s*([\"'])(.*?)\2", re.DOTALL)
_MAX_DECODED_BYTES = 64 * 1024


def detector_names() -> tuple[str, ...]:
    from .discovery_rules import SCALAR_DETECTOR_TYPES

    return tuple(
        dict.fromkeys(
            [item[0] for item in _PATTERNS]
            + ["url_credentials", "generic_secret", "high_entropy", *SCALAR_DETECTOR_TYPES]
        )
    )


def fingerprint(value: str | DiskBackedText) -> str:
    if identity := getattr(value, "secret_digest", None):
        return identity
    if isinstance(value, DiskBackedText):
        value._readable()
        return value.digest
    return sha256(value.encode("utf-8", errors="surrogatepass")).hexdigest()


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


def _scan_text(text: str, path: str, enabled: set[str], *, field_name: str | None = None) -> list[SecretMatch]:
    # Scalar confirmation belongs to the same rules used by every product.
    # Keep legacy detector labels as API aliases, not a second validator.
    from .discovery_rules import analyze_value, classify_field_name

    found: list[SecretMatch] = []
    detections = analyze_value(
        text,
        path=field_name or path,
        field_classification=classify_field_name(field_name) if field_name is not None else None,
        allow_base64=False,
    )
    for detection in detections:
        if not detection.available:
            continue
        detector = detection.secret_type
        if field_name is not None and detection.field_name == field_name and "sensitive_field" in detection.detectors:
            detector = _key_detector(field_name)
        if detector == "secret":
            name = detection.field_name or path.rsplit(".", 1)[-1]
            detector = _key_detector(name) if is_secret_field_name(name) else "generic_secret"
        aliases = {detector, detection.secret_type}
        if (
            field_name is not None
            and detection.value == text
            and classify_field_name(field_name) in {"strong", "medium"}
        ):
            aliases.add(_key_detector(field_name))
        if "credential_uri" in detection.detectors:
            aliases.update(("connection_string", "url_credentials", "password"))
        if "connection_dsn" in detection.detectors:
            aliases.update(("connection_string", "password", "generic_secret"))
        if "basic_auth" in detection.detectors:
            aliases.update(("basic_auth", "password"))
        if "bearer_auth" in detection.detectors:
            aliases.add("bearer_token")
        if aliases & enabled:
            found.append(
                SecretMatch(
                    detector,
                    "high" if detection.score >= 75 else "medium" if detection.score >= 60 else "low",
                    path,
                    detection.value,
                    detection.detectors,
                    tuple(sorted(aliases - {detector})),
                )
            )
    if _PATTERNS is not _INDEXED_PATTERNS:
        # Compatibility for explicitly supplied private extension patterns.
        for name, confidence, pattern in _candidate_patterns(text):
            if name in enabled and name not in {item[0] for item in _INDEXED_PATTERNS}:
                for match in pattern.finditer(text):
                    found.append(
                        SecretMatch(name, confidence, path, match.group(1) if match.lastindex else match.group())
                    )
    return found


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
        if stripped.startswith("#cloud-config"):
            return decoded
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


def scan_disk_atomic_token(
    value: DiskBackedText, *, object_path: str, deadline: float | None = None
) -> list[SecretMatch]:
    """Classify supported complete atomic tokens with bounded regex inputs.

    Validation covers every character, not just a recognizable prefix. Unknown
    grammars are left to the caller's other readers rather than guessed by size.
    """
    first = next(value.iter_text_chunks(max_chars=1024), "")
    if value.byte_length <= 65_536 and re.match(r"(?:jdbc:)?[A-Za-z][A-Za-z0-9+.-]*://", first):
        # A small portion can spill an otherwise ordinary completed token to
        # disk. It must still receive every scalar rule, not just the subset
        # with dedicated unbounded validators below. This allocation has a
        # fixed ceiling independent of the source's total size.
        completed = "".join(value.iter_text_chunks())
        if re.fullmatch(r"(?:jdbc:)?[A-Za-z][A-Za-z0-9+.-]*://[^\s\"'<>]+", completed):
            return _scan_text(completed, object_path, set(detector_names()))
    from .discovery_dsn import dsn_carrier

    if dsn_carrier(value, deadline=deadline)[0]:
        return [
            SecretMatch(
                "connection_string", "high", object_path, value, ("connection_dsn",), ("password", "generic_secret")
            )
        ]
    from .discovery_credentials import valid_cookie_carrier

    if valid_cookie_carrier(value, deadline=deadline):
        return [SecretMatch("session_cookie", "high", object_path, value, ("cookie_carrier",))]
    if first.lower().startswith("basic"):
        from .discovery_credentials import valid_basic_carrier

        if valid_basic_carrier(value, deadline=deadline):
            return [
                SecretMatch("basic_auth", "high", object_path, value, ("basic_auth", "credential_pair"), ("password",))
            ]
    if "://" in first:
        from .discovery_uri import uri_carrier_kind

        kind = uri_carrier_kind(value, deadline=deadline)
        if kind is not None:
            return [
                SecretMatch(
                    kind,
                    "high",
                    object_path,
                    value,
                    ("credential_uri" if kind == "connection_string" else "signed_url",),
                    ("password", "url_credentials") if kind == "connection_string" else ("azure_sas_signature",),
                )
            ]
    pem = re.match(r"-----BEGIN ((?:[A-Z0-9 ]+ )?PRIVATE KEY|CERTIFICATE)-----", first)
    if pem is not None:
        if pem.group(1) == "CERTIFICATE":
            return []
        end = f"-----END {pem.group(1)}-----"
        tail = suffix = ""
        count = length = 0
        for chunk in value.iter_text_chunks():
            length += len(chunk)
            part = tail + chunk
            count += part.count(end)
            tail = part[-(len(end) - 1) :]
            suffix = (suffix + chunk)[-len(end) :]
        # The shorter overlap cannot itself contain an entire END marker.
        if count == 1 and suffix == end and length > len(pem.group()) + len(end):
            kind = "certificate" if pem.group(1) == "CERTIFICATE" else "private_key"
            return [SecretMatch(kind, "high", object_path, value, ("private_key_pem",))]
        return []
    if first.startswith("eyJ") or "." in first:
        from .discovery_validation import validated_disk_jose

        if jose_kind := validated_disk_jose(value, deadline=deadline):
            return [SecretMatch(jose_kind, "high", object_path, value, (f"{jose_kind}_structure",))]
    rules = (
        ("grafana_token", "glsa_", r"[A-Za-z0-9_-]+"),
        ("api_token", "sk-", r"[A-Za-z0-9_-]+"),
        ("digitalocean_token", "dop_v1_", r"[A-Za-z0-9]+"),
        ("shopify_token", "shpat_", r"[A-Za-z0-9]+"),
        ("docker_token", "dckr_pat_", r"[A-Za-z0-9_-]+"),
        ("pypi_token", "pypi-AgEI", r"[A-Za-z0-9_-]+"),
    )
    for detector, prefix, alphabet in rules:
        if not first.startswith(prefix):
            continue
        from .discovery_rules import _PROVIDER_TOKENS

        pattern = next(pattern for pattern, name in _PROVIDER_TOKENS if name == detector)
        if pattern.fullmatch(first) is None:
            return []
        remaining_prefix = len(prefix)
        for chunk in value.iter_text_chunks():
            offset = min(remaining_prefix, len(chunk))
            remaining_prefix -= offset
            body = chunk[offset:]
            if body and re.fullmatch(alphabet, body) is None:
                return []
        return [SecretMatch(detector, "high", object_path, value, ("provider_token_format",))]
    return []


def scan_value(
    value: Any,
    *,
    object_path: str = "$",
    enabled: Iterable[str] | None = None,
    _depth: int = 0,
    _decode_depth: int = 0,
    _on_incomplete: Callable[[str], None] | None = None,
    _field_name: str | None = None,
) -> list[SecretMatch]:
    """Inspect a scalar or nested value without dropping malformed JSON text."""

    if _depth > 32:
        if _on_incomplete is not None:
            _on_incomplete("max_depth")
        return []
    enabled_set = set(enabled or detector_names())
    if isinstance(value, Mapping):
        from .discovery_context import field_binding
        from .discovery_groups import credential_groups

        binding = field_binding(value)
        matches: list[SecretMatch] = []
        grouped_keys: set[str] = set()
        for group in credential_groups(value):
            try:
                grouped_value = group.value()
            except OSError:
                if _on_incomplete is None:
                    raise
                # Keep the parent's completed matches. The scalar fallback
                # can still expose readable fields, but the failed object
                # assembly must remain explicitly incomplete.
                _on_incomplete("storage_failure")
                continue
            grouped_keys.update(group.fields)
            match = SecretMatch(group.kind, "high", object_path, grouped_value, group.rules, group.aliases)
            if detector_matches(match, enabled_set):
                matches.append(match)
        for raw_key, nested in value.items():
            if raw_key in grouped_keys:
                continue
            key = str(raw_key)
            path = object_path + literal_field_component(key)
            child_matches = scan_value(
                nested,
                object_path=path,
                enabled=enabled_set,
                _depth=_depth + 1,
                _decode_depth=_decode_depth,
                _on_incomplete=_on_incomplete,
                _field_name=binding.field_name if binding is not None and raw_key == binding.key else key,
            )
            matches.extend(child_matches)
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
                    _on_incomplete=_on_incomplete,
                )
            )
        return matches
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
    elif isinstance(value, str):
        text = value
    elif (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and is_secret_field_name(_field_name or object_path.rsplit(".", 1)[-1])
    ):
        text = str(value)
    else:
        return []

    stripped = text.strip()
    from .discovery_dsn import dsn_carrier

    if not dsn_carrier(stripped)[1]:
        if _on_incomplete is not None:
            _on_incomplete("unterminated_connection_dsn")
        return []
    if ('"""' in text or "'''" in text) and has_toml_assignment(text, is_secret_field_name):
        # Triple-quoted assignments require one incremental literal grammar;
        # the small-string shortcut must not treat the first two quotes as an
        # empty single-quoted value and discard the rest of the literal.
        from .discovery_engine import _scan_text_chunks

        matches, complete = _scan_text_chunks((text,), object_path, 65_536, _decode_depth)
        if not complete and _on_incomplete is not None:
            _on_incomplete(getattr(matches, "incomplete_reason", None) or "invalid_literal")
        return [match for match in matches if detector_matches(match, enabled_set)]
    if stripped.startswith(("{", "[")):
        try:
            parsed = json.loads(stripped)
        except (TypeError, ValueError, json.JSONDecodeError):
            parsed = None
        if parsed is not None:
            return scan_value(
                parsed,
                object_path=object_path,
                enabled=enabled_set,
                _depth=_depth + 1,
                _decode_depth=_decode_depth,
                _on_incomplete=_on_incomplete,
            )
    if "," in text and "\n" in text:
        from .discovery_csv import CSVCell, CSVSecretStream

        csv_matches: list[SecretMatch] = []

        def csv_cell(cell: CSVCell) -> None:
            csv_matches.extend(
                scan_value(
                    cell.value,
                    object_path=f"{object_path}.csv[{cell.row}].{cell.name}",
                    enabled=enabled_set,
                    _depth=_depth + 1,
                    _decode_depth=_decode_depth,
                    _on_incomplete=_on_incomplete,
                    _field_name=str(cell.name),
                )
            )

        csv_reader = CSVSecretStream(csv_cell, _on_incomplete or (lambda _reason: None), portion=max(64, len(text)))
        try:
            csv_reader.feed(text)
            csv_reader.finish()
            if csv_reader.active:
                return csv_matches
        finally:
            csv_reader.close()
    matches = _scan_text(text, object_path, enabled_set, field_name=_field_name)
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
                    _on_incomplete=_on_incomplete,
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
    "detector_matches",
    "fingerprint",
    "is_secret_field_name",
    "scan_value",
]
