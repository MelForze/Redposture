"""Mapping-aware Elasticsearch/OpenSearch secret discovery.

The module intentionally owns no transport.  Callers inject a small synchronous
request callback, which keeps authentication, proxying and TLS policy in the
Elastic stage while making the discovery engine deterministic and testable.
"""

from __future__ import annotations

import base64
import binascii
import csv
import hashlib
import html
import json
import math
import operator
import re
import sqlite3
import tempfile
import threading
import time
import urllib.parse
import zlib
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from itertools import chain
from pathlib import Path
from typing import Any, Literal, SupportsIndex, TypeAlias, overload

from ...data_discovery import _scan_portioned_value
from ...discovery_encoded import compressed_text_prefix, mime_text_prefix
from ...discovery_json import DiskJSONDocument
from ...discovery_options import DEFAULT_DISCOVER_MAX_BYTES, DEFAULT_DISCOVER_TIME
from ...discovery_paths import Text, concat_discovery_text, json_discovery_path
from ...discovery_spool import SpoolingFindings, _DiskValueReferences, _slice_values
from ...discovery_values import DiskBackedText
from ...json_stream import JSONPath
from ...scheduler import NestedSchedulerCancelled
from ...secret_detection import is_secret_metadata_field
from ...secret_literals import AssignmentLiterals
from .value_stream import SpoolingSequence, disk_basic_password, disk_entropy, stable_json_chunks, validated_disk_jose

JsonObject: TypeAlias = dict[str, Any]
FieldClass: TypeAlias = Literal["strong", "medium", "excluded", "neutral"]
SurfaceStatus: TypeAlias = Literal["complete", "partial", "denied", "unsupported", "timeout", "error"]

DEFAULT_PAGE_SIZE = 200
DEFAULT_MAX_DOCUMENTS = 50_000
DEFAULT_MAX_SOURCE_BYTES = DEFAULT_DISCOVER_MAX_BYTES
DEFAULT_MAX_SECONDS = DEFAULT_DISCOVER_TIME
DEFAULT_MAX_FINDINGS = 10_000
DEFAULT_MAX_LOCATIONS = 100
MAX_QUERY_CLAUSES = 24
MAPPING_BATCH_SIZE = 20
MAX_PAGINATION_CONTEXT_RECOVERIES = 1
MAX_LEGACY_SEARCH_ADJUSTMENTS = 5
DISCOVER_WORKERS = 8

_STRONG_FIELDS = {
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
_AUTH_HEADER_RE = re.compile(r"(?i)\b(Basic|Bearer)\s+([A-Za-z0-9._~+/=-]{8,})")
_AZURE_SAS_RE = re.compile(r"(?i)(?:^|[?&])sig=([^&\s]{8,})")
_AZURE_ACCOUNT_KEY_RE = re.compile(r"(?i)(?:^|[;\s])AccountKey=([^;\s]{16,})")
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----[\s\S]+?-----END(?: [A-Z0-9]+)? PRIVATE KEY-----"
)
_KEY_VALUE_RE = re.compile(
    r"(?i)(?<![\w.])(?:--)?"
    r"((?:[A-Za-z][A-Za-z0-9]{0,32}[._-])*"
    r"(?:password|passwd|pwd|passphrase|credential|credentials|cred|creds|pass|"
    r"client[_-]?secret|api[_-]?secret|apisecret|api[_-]?token|"
    r"_?auth[_-]?token|refresh[_-]?token|secret[_-]?access[_-]?key|"
    r"secret[_-]?key|apikey))"
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
_SQL_ACCOUNT_TOKEN = r"(?:'(?:''|\\.|[^'\\])*'|\"(?:\"\"|\\.|[^\"\\])*\"|`(?:``|[^`])*`|[A-Za-z0-9_.$%+-]+)"
_SQL_IDENTIFIED_BY_RE = re.compile(
    r"(?i)(?<![\w.])(?:CREATE\s+USER\s+(?:IF\s+NOT\s+EXISTS\s+)?|ALTER\s+USER\s+(?:IF\s+EXISTS\s+)?)"
    + _SQL_ACCOUNT_TOKEN
    + r"(?:\s*@\s*"
    + _SQL_ACCOUNT_TOKEN
    + r")?\s+IDENTIFIED\s+BY\s+"
    + r"('(?:''|\\.|[^'\\])*'|\"(?:\"\"|\\.|[^\"\\])*\")(?=$|[\s;,])"
)
_XML_SECRET_RE = re.compile(r"(?is)<([A-Za-z][\w:.-]{0,79})\b[^>]{0,2048}>([^<>]{4,4096})</\1\s*>")
_TAG_RE = re.compile(r"<([A-Za-z][\w:.-]{0,79})\b([^<>]{0,2048})>", re.IGNORECASE)
_ATTR_RE = re.compile(r"([A-Za-z][\w:.-]{0,79})\s*=\s*([\"'])(.*?)\2", re.DOTALL)
_BLOB_TYPES = {"text", "keyword", "wildcard", "match_only_text", "flattened"}


@dataclass(frozen=True)
class DiscoverRequest:
    """A transport-independent HTTP request."""

    method: str
    path: str
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes | None = None
    stream_search: bool = False


@dataclass(frozen=True)
class DiscoverResponse:
    """Normalized callback result.

    ``truncated`` means the transport stopped reading at its response-size cap;
    it is distinct from Elasticsearch's ``hits.total.relation``.
    """

    status: int
    payload: bytes
    headers: Mapping[str, str] = field(default_factory=dict)
    error: str | None = None
    truncated: bool = False
    streamed_search: Any | None = None
    parsed_payload: Any | None = None


RawRequestResult: TypeAlias = (
    DiscoverResponse
    | tuple[int, bytes, dict[str, str], str | None]
    | tuple[int, bytes, dict[str, str], str | None, bool]
)
RequestFn: TypeAlias = Callable[[DiscoverRequest], RawRequestResult]


@dataclass(frozen=True)
class DiscoverOptions:
    page_size: int = DEFAULT_PAGE_SIZE
    max_documents: int | None = None
    max_source_bytes: int | None = None
    max_seconds: float = DEFAULT_MAX_SECONDS
    max_findings: int | None = None
    max_locations: int = DEFAULT_MAX_LOCATIONS
    mapping_batch_size: int = MAPPING_BATCH_SIZE
    max_depth: int = 32
    max_array_items: int | None = None
    max_scalar_bytes: int = 256 * 1024
    max_embedded_json_bytes: int = 64 * 1024
    pit_keep_alive: str = "2m"


@dataclass(frozen=True)
class MappedField:
    index: str
    path: str
    field_type: str
    classification: FieldClass
    nested_path: str | None = None
    indexed: bool = True
    stored: bool = False
    doc_values: bool = True
    kind: str = "field"
    config_path: str | None = None

    def to_dict(self) -> JsonObject:
        return asdict(self)


@dataclass(frozen=True)
class FindingLocation:
    source_kind: str
    object: str
    path: Text
    index: str | None = None
    id: str | None = None

    def to_dict(self) -> JsonObject:
        return {
            key: value
            for key in ("source_kind", "object", "path", "index", "id")
            if (value := getattr(self, key)) is not None
        }


@dataclass(frozen=True)
class DetectedSecret:
    value: str | DiskBackedText
    secret_type: str
    score: int
    detectors: tuple[str, ...]
    available: bool = True


@dataclass
class Finding:
    fingerprint: str
    value: str | DiskBackedText
    secret_type: str
    confidence: str
    score: int
    detectors: list[str]
    occurrence_count: int
    locations: list[FindingLocation]

    def to_dict(self) -> JsonObject:
        return {
            "fingerprint": self.fingerprint,
            "value": self.value,
            "secret_type": self.secret_type,
            "confidence": self.confidence,
            "score": self.score,
            "detectors": list(self.detectors),
            "occurrence_count": self.occurrence_count,
            "locations": [location.to_dict() for location in self.locations],
        }


def _encode_detection(detection: DetectedSecret) -> JsonObject:
    return {
        "value": detection.value,
        "secret_type": detection.secret_type,
        "score": detection.score,
        "detectors": list(detection.detectors),
        "available": detection.available,
    }


def _decode_detection(record: Mapping[str, Any]) -> DetectedSecret:
    return DetectedSecret(
        record["value"], record["secret_type"], record["score"], tuple(record["detectors"]), record["available"]
    )


def _detection_size(detection: DetectedSecret) -> int:
    return detection.value.__sizeof__() + 256


def _detection_list() -> SpoolingSequence[DetectedSecret]:
    return SpoolingSequence(encode=_encode_detection, decode=_decode_detection, estimate=_detection_size)


def _located_detection_list() -> SpoolingSequence[tuple[DetectedSecret, FindingLocation]]:
    def encode(item: tuple[DetectedSecret, FindingLocation]) -> JsonObject:
        return {"detection": _encode_detection(item[0]), "location": item[1].to_dict()}

    def decode(record: Mapping[str, Any]) -> tuple[DetectedSecret, FindingLocation]:
        return _decode_detection(record["detection"]), FindingLocation(**record["location"])

    return SpoolingSequence(
        encode=encode, decode=decode, estimate=lambda item: _detection_size(item[0]) + item[1].path.__sizeof__() + 256
    )


@dataclass
class ScanResult:
    detections: list[tuple[DetectedSecret, FindingLocation]] = field(default_factory=_located_detection_list)
    suppressed_indicators: int = 0
    truncated_reasons: list[str] = field(default_factory=list)


@dataclass
class SurfaceCoverage:
    status: SurfaceStatus = "complete"
    objects_attempted: int = 0
    objects_scanned: int = 0
    error: str | None = None
    error_detail: JsonObject | None = None

    def to_dict(self) -> JsonObject:
        return {key: value for key, value in asdict(self).items() if value is not None}


@dataclass
class DiscoverCoverage:
    indices_enumerated: int = 0
    indices_scanned: int = 0
    indices_closed: int = 0
    indices_denied: int = 0
    indices_failed: int = 0
    pages_scanned: int = 0
    documents_scanned: int = 0
    source_bytes_scanned: int = 0
    query_candidates: int = 0
    timed_out: bool = False
    shard_failures: list[JsonObject] = field(default_factory=list)
    missing_source_documents: int = 0
    source_disabled_indices: list[str] = field(default_factory=list)
    source_filtered_indices: list[str] = field(default_factory=list)
    duplicate_documents: int = 0
    suppressed_indicators: int = 0
    locations_dropped: int = 0
    truncated: bool = False
    truncated_reasons: list[str] = field(default_factory=list)
    surfaces: dict[str, SurfaceCoverage] = field(default_factory=dict)
    elapsed_ms: int = 0
    limits: JsonObject = field(default_factory=dict)
    scope: JsonObject = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)

    def mark_truncated(self, reason: str) -> None:
        self.truncated = True
        if reason not in self.truncated_reasons:
            self.truncated_reasons.append(reason)

    def to_dict(self) -> JsonObject:
        result = asdict(self)
        incomplete_surfaces = any(surface.status != "complete" for surface in self.surfaces.values())
        open_indices = max(0, self.indices_enumerated - self.indices_closed)
        accounted_indices = self.indices_scanned + self.indices_denied + self.indices_failed
        result["complete"] = (
            not self.truncated
            and not self.timed_out
            and self.indices_closed == 0
            and self.indices_denied == 0
            and self.indices_failed == 0
            and self.missing_source_documents == 0
            and accounted_indices >= open_indices
            and not incomplete_surfaces
        )
        result["status"] = "complete" if result["complete"] else "partial"
        result["surfaces"] = {name: value.to_dict() for name, value in self.surfaces.items()}
        return result


@dataclass
class DiscoverReport:
    findings: list[Finding]
    coverage: DiscoverCoverage
    legacy_results: list[JsonObject]
    error: str | None = None
    error_detail: JsonObject | None = None
    schema_version: int = 2

    def to_dict(self) -> JsonObject:
        if isinstance(self.findings, _SpoolingElasticFindingList):
            serialized_findings: list[JsonObject] = self.findings.to_dict_spool()
        else:
            serialized_findings = [finding.to_dict() for finding in self.findings]
        return {
            "discover_schema_version": self.schema_version,
            "discover_findings": serialized_findings,
            "discover_coverage": self.coverage.to_dict(),
            "discover_results": self.legacy_results,
            "discover_error": self.error,
            "discover_error_detail": self.error_detail,
        }


@dataclass(frozen=True)
class IndexInfo:
    name: str
    status: str = "open"
    data_stream: str | None = None
    aliases: tuple[str, ...] = ()


def _confidence(score: int) -> str:
    if score >= 90:
        return "very_high"
    if score >= 75:
        return "high"
    return "medium"


def normalize_field_name(value: str) -> str:
    """Normalize dotted, snake, kebab and camel-case field names."""

    text = re.sub(r"\[\d*]", "", str(value).strip())
    text = _CAMEL_BOUNDARY_RE.sub("_", text)
    text = re.sub(r"[^A-Za-z0-9]+", "_", text)
    return re.sub(r"_+", "_", text).strip("_").lower()


def classify_field(value: str) -> FieldClass:
    """Classify a mapping/JSON path without treating generic IDs as secrets."""

    segments = [segment for segment in re.split(r"[./]+", str(value)) if segment]
    leaf = normalize_field_name(segments[-1] if segments else value)
    parts = [part for part in leaf.split("_") if part]
    if leaf in _EXCLUDED_FIELDS:
        return "excluded"
    if is_secret_metadata_field(leaf):
        return "excluded"
    if {"public", "key"}.issubset(parts) or {"api", "key", "id"}.issubset(parts):
        return "excluded"
    if leaf.endswith(("_id", "_count", "_hash", "_checksum", "_policy")):
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
    if leaf in {"value", "data", "content", "material"}:
        for ancestor in reversed(segments[:-1]):
            ancestor_class = classify_field(ancestor)
            if ancestor_class in {"strong", "medium"}:
                return ancestor_class
    return "neutral"


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
            result = "secret"
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


def extract_mapping_fields(payload: Mapping[str, Any], index_name: str | None = None) -> list[MappedField]:
    """Flatten mappings into searchable fields and configuration locations."""

    extracted: list[MappedField] = []

    def append_config(index: str, pointer: str, kind: str) -> None:
        extracted.append(
            MappedField(
                index=index,
                path=pointer,
                field_type="object",
                classification=classify_field(pointer),
                indexed=False,
                kind=kind,
                config_path=pointer,
            )
        )

    def walk_properties(
        index: str,
        properties: Mapping[str, Any],
        *,
        prefix: str = "",
        nested_path: str | None = None,
    ) -> None:
        for raw_name, raw_definition in properties.items():
            if not isinstance(raw_definition, Mapping):
                continue
            name = str(raw_name)
            path = f"{prefix}.{name}" if prefix else name
            field_type = str(raw_definition.get("type") or ("object" if "properties" in raw_definition else ""))
            current_nested = path if field_type == "nested" else nested_path
            extracted.append(
                MappedField(
                    index=index,
                    path=path,
                    field_type=field_type or "object",
                    classification=classify_field(path),
                    nested_path=current_nested,
                    indexed=raw_definition.get("index") is not False,
                    stored=raw_definition.get("store") is True,
                    doc_values=raw_definition.get("doc_values") is not False
                    and field_type not in {"object", "nested", "text", "match_only_text"},
                )
            )
            if isinstance(raw_definition.get("meta"), Mapping):
                append_config(index, f"/properties/{path.replace('.', '/properties/')}/meta", "field_meta")
            child_properties = raw_definition.get("properties")
            if isinstance(child_properties, Mapping):
                walk_properties(index, child_properties, prefix=path, nested_path=current_nested)
            multi_fields = raw_definition.get("fields")
            if isinstance(multi_fields, Mapping):
                walk_properties(index, multi_fields, prefix=path, nested_path=current_nested)

    possible_indices: Iterable[tuple[str, Any]]
    if index_name is not None:
        possible_indices = ((index_name, payload),)
    elif "mappings" in payload and isinstance(payload.get("mappings"), Mapping):
        possible_indices = (("", payload),)
    else:
        possible_indices = ((str(name), definition) for name, definition in payload.items())

    for index, raw_index_definition in possible_indices:
        if not isinstance(raw_index_definition, Mapping):
            continue
        mappings_raw = raw_index_definition.get("mappings", raw_index_definition)
        if not isinstance(mappings_raw, Mapping):
            continue
        properties = mappings_raw.get("properties")
        if isinstance(properties, Mapping):
            walk_properties(index, properties)
        runtime = mappings_raw.get("runtime")
        if isinstance(runtime, Mapping):
            for runtime_name, definition in runtime.items():
                field_type = ""
                if isinstance(definition, Mapping):
                    field_type = str(definition.get("type") or "")
                extracted.append(
                    MappedField(
                        index=index,
                        path=str(runtime_name),
                        field_type=field_type or "runtime",
                        classification=classify_field(str(runtime_name)),
                        indexed=True,
                        stored=False,
                        doc_values=True,
                        kind="runtime",
                        config_path=f"/runtime/{runtime_name}",
                    )
                )
        derived = mappings_raw.get("derived")
        if isinstance(derived, Mapping):
            for derived_name in derived:
                extracted.append(
                    MappedField(
                        index=index,
                        path=str(derived_name),
                        field_type="derived",
                        classification=classify_field(str(derived_name)),
                        indexed=True,
                        stored=False,
                        doc_values=True,
                        kind="derived",
                        config_path=f"/derived/{derived_name}",
                    )
                )
        if isinstance(mappings_raw.get("_meta"), Mapping):
            append_config(index, "/_meta", "mapping_meta")
        dynamic_templates = mappings_raw.get("dynamic_templates")
        if isinstance(dynamic_templates, list):
            for offset, _template in enumerate(dynamic_templates):
                append_config(index, f"/dynamic_templates/{offset}", "dynamic_template")
    return extracted


def _field_path(item: MappedField | str) -> str:
    return item.path if isinstance(item, MappedField) else str(item)


def build_targeted_query(fields: Sequence[MappedField | str], *, size: int = DEFAULT_PAGE_SIZE) -> JsonObject:
    """Build an ``exists`` query with no query-parser syntax."""

    clauses: list[JsonObject] = []
    seen: set[tuple[str, str | None]] = set()
    for field_item in fields:
        if isinstance(field_item, MappedField):
            if (
                field_item.classification not in {"strong", "medium"}
                or field_item.kind != "field"
                or not field_item.indexed
            ):
                continue
            path = field_item.path
            nested_path = field_item.nested_path
        else:
            path = str(field_item)
            nested_path = None
        key = (path, nested_path)
        if not path or key in seen:
            continue
        seen.add(key)
        clause: JsonObject = {"exists": {"field": path}}
        if nested_path:
            clause = {
                "nested": {
                    "path": nested_path,
                    "query": clause,
                    "ignore_unmapped": True,
                }
            }
        clauses.append(clause)
        if len(clauses) >= MAX_QUERY_CLAUSES:
            break
    query: JsonObject
    if clauses:
        query = {"bool": {"should": clauses, "minimum_should_match": 1}}
    else:
        query = {"match_none": {}}
    body: JsonObject = {
        "size": max(1, int(size)),
        "track_total_hits": True,
        "query": query,
        "sort": [{"_shard_doc": "asc"}],
    }
    selected_paths = list(dict.fromkeys(_field_path(item) for item in fields if _field_path(item)))
    if selected_paths:
        body["_source"] = {"includes": selected_paths}
        doc_value_paths = [
            _field_path(item)
            for item in fields
            if not isinstance(item, MappedField) or (item.indexed and item.doc_values)
        ]
        stored_paths = [item.path for item in fields if isinstance(item, MappedField) and item.stored]
        if doc_value_paths:
            body["fields"] = list(dict.fromkeys(doc_value_paths))
        if stored_paths:
            body["stored_fields"] = list(dict.fromkeys(stored_paths))
    return body


def _eligible_signature_fields(fields: Sequence[MappedField | str]) -> list[tuple[str, str | None]]:
    eligible: list[tuple[str, str | None]] = []
    for item in fields:
        path = _field_path(item)
        nested_path = item.nested_path if isinstance(item, MappedField) else None
        candidate = (path, nested_path)
        if not path or candidate in eligible:
            continue
        if isinstance(item, MappedField) and item.field_type not in _BLOB_TYPES:
            continue
        if isinstance(item, MappedField) and (item.kind != "field" or not item.indexed):
            continue
        eligible.append(candidate)
    return eligible


def build_signature_queries(
    fields: Sequence[MappedField | str],
    *,
    size: int = DEFAULT_PAGE_SIZE,
) -> list[JsonObject]:
    """Build bounded strong-marker queries without silently dropping mapped fields."""

    eligible = _eligible_signature_fields(fields)
    phrases = (
        "PRIVATE KEY",
        "Bearer ",
        "Basic ",
        "client_secret",
        "secret_access_key",
        "password=",
        "password:",
        "api_token",
        "refresh_token",
        "connection_string",
        "service_account",
        "dockerconfigjson",
    )
    clauses: list[JsonObject] = []
    if eligible:
        groups: dict[str | None, list[str]] = {}
        for path, nested_path in eligible:
            groups.setdefault(nested_path, []).append(path)
        for nested_path, paths in groups.items():
            for offset in range(0, len(paths), 64):
                path_batch = paths[offset : offset + 64]
                for phrase in phrases:
                    clause: JsonObject = {
                        "multi_match": {
                            "query": phrase,
                            "fields": path_batch,
                            "type": "phrase",
                            "lenient": True,
                        }
                    }
                    if nested_path:
                        clause = {
                            "nested": {
                                "path": nested_path,
                                "query": clause,
                                "ignore_unmapped": True,
                            }
                        }
                    clauses.append(clause)

    if not clauses:
        return [
            {
                "size": max(1, int(size)),
                "track_total_hits": True,
                "query": {"match_none": {}},
                "sort": [{"_shard_doc": "asc"}],
            }
        ]

    queries: list[JsonObject] = []
    for offset in range(0, len(clauses), MAX_QUERY_CLAUSES):
        clause_batch = clauses[offset : offset + MAX_QUERY_CLAUSES]
        paths = list(dict.fromkeys(value for clause in clause_batch for value in _query_clause_fields(clause)))
        body: JsonObject = {
            "size": max(1, int(size)),
            "track_total_hits": True,
            "query": {"bool": {"should": clause_batch, "minimum_should_match": 1}},
            "sort": [{"_shard_doc": "asc"}],
        }
        mapped_by_path = {item.path: item for item in fields if isinstance(item, MappedField) and item.kind == "field"}
        doc_value_paths = [
            path for path in paths if (mapped := mapped_by_path.get(path)) is not None and mapped.doc_values
        ]
        stored_paths = [path for path in paths if (mapped := mapped_by_path.get(path)) is not None and mapped.stored]
        if doc_value_paths:
            body["fields"] = doc_value_paths
        if stored_paths:
            body["stored_fields"] = stored_paths
        queries.append(body)
    return queries


def _query_clause_fields(clause: Mapping[str, Any]) -> list[str]:
    nested = clause.get("nested")
    if isinstance(nested, Mapping):
        query = nested.get("query")
        return _query_clause_fields(query) if isinstance(query, Mapping) else []
    multi_match = clause.get("multi_match")
    fields = multi_match.get("fields") if isinstance(multi_match, Mapping) else None
    return [str(value) for value in fields] if isinstance(fields, list) else []


def build_signature_query(fields: Sequence[MappedField | str], *, size: int = DEFAULT_PAGE_SIZE) -> JsonObject:
    """Return the first bounded signature query for compatibility callers."""

    return build_signature_queries(fields, size=size)[0]


def _looks_placeholder(value: str) -> bool:
    text = value.strip()
    return not text or _PLACEHOLDER_RE.fullmatch(text) is not None


def _plausible_opaque_secret(value: str) -> bool:
    text = value.strip()
    if len(text) < 12 or len(text) > 256 * 1024:
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


def _candidate(value: str | DiskBackedText, secret_type: str, score: int, *detectors: str) -> DetectedSecret:
    return DetectedSecret(
        value=value,
        secret_type=secret_type,
        score=min(100, max(0, score)),
        detectors=tuple(dict.fromkeys(detectors)),
    )


def _secret_key_kind(value: str) -> str | None:
    name = normalize_field_name(value)

    def ends_with_segment(suffix: str) -> bool:
        return name == suffix or name.endswith(f"_{suffix}")

    if any(ends_with_segment(suffix) for suffix in ("password", "passwd", "pwd", "passphrase", "pass")):
        return "password"
    if any(ends_with_segment(suffix) for suffix in _SECRET_KEY_SUFFIXES):
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


_DISK_BEARER_PREFIX_RE = re.compile(r"(?i)^\s*(?:Authorization:\s*)?Bearer\s+")
_DISK_BEARER_PART_RE = re.compile(r"[A-Za-z0-9._~+/=-]*")


def _disk_bearer_token(value: DiskBackedText) -> tuple[DiskBackedText | None, bool]:
    """Recognize a whole Bearer scalar and retain only its token on disk."""
    chunks = value.iter_text_chunks()
    first = next(chunks, "")
    prefix = _DISK_BEARER_PREFIX_RE.match(first)
    if prefix is None:
        return None, False
    token = DiskBackedText()
    ended = False
    retained = False
    try:
        for part in chain((first[prefix.end() :],), chunks):
            if ended:
                if not part.isspace():
                    return None, False
                continue
            token_end = _DISK_BEARER_PART_RE.match(part)
            assert token_end is not None
            accepted = token_end.end()
            if accepted:
                token.append_text(part[:accepted])
            tail = part[accepted:]
            if tail:
                if not tail.isspace():
                    return None, False
                ended = True
        token.finish()
        if token.byte_length < 12 or token.obvious_placeholder:
            return None, True
        retained = True
        return token, True
    finally:
        if not retained:
            token.close()


def analyze_value(
    value: Any,
    *,
    path: str = "",
    field_classification: FieldClass | None = None,
    allow_base64: bool = True,
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

    detections: list[DetectedSecret] = []
    literals = AssignmentLiterals(text, lambda name: _secret_key_kind(name) is not None)
    for assignment_literal in literals.items:
        kind = _secret_key_kind(assignment_literal.name)
        if kind and assignment_literal.value and not _looks_placeholder(assignment_literal.value):
            detections.append(_candidate(assignment_literal.value, kind, 85, "credential_pair", "sensitive_field"))
    for match in _PRIVATE_KEY_RE.finditer(text):
        detections.append(_candidate(match.group(0), "private_key", 100, "private_key_pem"))
    for match in _JWE_RE.finditer(text):
        token = match.group(1)
        if _validated_jwe(token):
            detections.append(_candidate(token, "jwe", 95, "jwe_structure"))
    for match in _JWT_RE.finditer(text):
        token = match.group(1)
        if _validated_jwt(token):
            detections.append(_candidate(token, "jwt", 95, "jwt_structure"))
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
            detections.append(_candidate(match.group(1), secret_type, score, detector))
    for regex, secret_type in _PROVIDER_TOKENS:
        for match in regex.finditer(text):
            detections.append(_candidate(match.group(1), secret_type, 96, "provider_token_format"))
    for match in _AUTH_HEADER_RE.finditer(text):
        kind = match.group(1).lower()
        token = match.group(2)
        if kind == "basic":
            password = _decode_basic(token)
            if password:
                detections.append(_candidate(password, "password", 92, "basic_auth", "credential_pair"))
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
            detections.append(_candidate(secret, kind, 85, "credential_pair", "sensitive_field"))
    for match in _SQL_PASSWORD_RE.finditer(text):
        if not _looks_placeholder(match.group(1)):
            detections.append(_candidate(match.group(1), "password", 85, "sql_password"))
    for match in _SQL_IDENTIFIED_BY_RE.finditer(text):
        literal = match.group(1)
        quote = literal[0]
        # Default MySQL string-literal escapes. SQL modes are not available
        # when scanning stored text; NO_BACKSLASH_ESCAPES is not inferred.
        escapes = {"0": "\0", "b": "\b", "n": "\n", "r": "\r", "t": "\t", "Z": "\x1a", "%": r"\%", "_": r"\_"}
        secret = re.sub(
            r"\\([\s\S])|" + re.escape(quote * 2),
            lambda escaped, escapes=escapes, quote=quote: (
                escapes.get(escaped.group(1), escaped.group(1)) if escaped.group(1) else quote
            ),
            literal[1:-1],
        )
        if len(secret) >= 4 and not _looks_placeholder(secret):
            detections.append(_candidate(secret, "password", 85, "sql_password"))
    if "\n" in text and "," in text and len(text) <= 64 * 1024:
        try:
            rows = csv.reader(text.splitlines()[:101])
            headers = next(rows)
            secret_columns = [(offset, _secret_key_kind(name)) for offset, name in enumerate(headers)]
            for row in rows:
                for offset, kind in secret_columns:
                    if kind and offset < len(row) and not _looks_placeholder(row[offset]):
                        detections.append(_candidate(row[offset], kind, 82, "csv_secret_column"))
        except (csv.Error, StopIteration):
            pass
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
                detections.append(_candidate(signature, "azure_sas_signature", 96, "azure_sas"))
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

    parsed = urllib.parse.urlsplit(stripped)
    if parsed.scheme and parsed.hostname and parsed.password is not None:
        detections.append(
            _candidate(
                urllib.parse.unquote(parsed.password),
                "password",
                92,
                "credential_uri",
                "credential_pair",
            )
        )

    if field_class in {"strong", "medium"} and len(stripped.encode("utf-8", errors="replace")) <= 256 * 1024:
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
        if field_class == "medium" and not _plausible_opaque_secret(stripped):
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
            detections.append(_candidate(stripped, secret_type, base_score, *detectors))

    unique: dict[tuple[str, str | DiskBackedText], DetectedSecret] = {}
    for detection in detections:
        key = (detection.secret_type, detection.value)
        previous = unique.get(key)
        if previous is None or detection.score > previous.score:
            unique[key] = detection
    return list(unique.values())


def _analyze_disk_value(
    value: DiskBackedText, *, path: str, deadline: float | None = None
) -> tuple[list[DetectedSecret], bool]:
    """Use bounded readers while retaining Elastic's confirmation policy."""
    if value.obvious_placeholder:
        return [], True
    jose = validated_disk_jose(value, deadline=deadline)
    if jose is not None:
        return [_candidate(value, jose, 95, f"{jose}_structure")], True
    matches, _bytes, complete = _scan_portioned_value(value, "$", 65_536, _deadline=deadline)
    detections = _detection_list()
    confirmed_provider_types = {
        "api_token",
        "grafana_token",
        "digitalocean_token",
        "shopify_token",
        "docker_token",
        "pypi_token",
    }
    try:
        for match in matches:
            raw = match.value
            if isinstance(raw, DiskBackedText):
                if raw.obvious_placeholder:
                    continue
                if match.detector == "jwt":
                    kind = validated_disk_jose(raw, deadline=deadline)
                    if kind is not None:
                        detections.append(_candidate(raw, kind, 95, f"{kind}_structure"))
                elif match.detector in confirmed_provider_types:
                    detections.append(_candidate(raw, match.detector, 96, "provider_token_format"))
                elif match.detector in {
                    "password",
                    "client_secret",
                    "access_token",
                    "api_key",
                    "generic_secret",
                    "session_cookie",
                }:
                    key = (
                        _disk_field_hint(match.object_path, deadline)
                        if isinstance(match.object_path, DiskBackedText)
                        else match.object_path.rsplit(".", 1)[-1]
                    )
                    field_class = classify_field(key)
                    kind = "password" if match.detector == "password" else (_secret_key_kind(key) or "secret")
                    if field_class == "strong" or match.detector == "password":
                        detections.append(_candidate(raw, kind, 85, "credential_pair", "sensitive_field"))
                    elif field_class == "medium":
                        entropy, classes = disk_entropy(raw, deadline=deadline)
                        if entropy >= 3.0 and (classes >= 2 or raw.byte_length >= 24):
                            detections.append(_candidate(raw, kind, 73 if entropy >= 3.5 else 68, "sensitive_field"))
                elif match.detector == "private_key":
                    detections.append(_candidate(raw, "private_key", 100, "private_key_pem"))
                elif match.detector == "bearer_token":
                    detections.append(_candidate(raw, "bearer_token", 90, "bearer_auth"))
                elif match.detector == "basic_auth":
                    password = disk_basic_password(raw, deadline=deadline)
                    if password is not None:
                        detections.append(_candidate(password, "password", 92, "basic_auth", "credential_pair"))
                elif match.detector != "certificate":
                    complete = False
                continue
            # Confirm small common-reader candidates through Elastic's own rules;
            # a common JWT or AWS-shaped ID alone is not sufficient evidence.
            key = (
                _disk_field_hint(match.object_path, deadline)
                if isinstance(match.object_path, DiskBackedText)
                else match.object_path.rsplit(".", 1)[-1]
            )
            hint = "password" if match.detector == "password" else key
            scalar = (
                f"Bearer {raw}"
                if match.detector == "bearer_token"
                else f"Basic {raw}"
                if match.detector == "basic_auth"
                else raw
            )
            detections.extend(analyze_value(scalar, path=hint, field_classification=classify_field(hint)))
    except OSError:
        detections.incomplete_reason = "storage_failure"
        return detections, False
    if not detections:
        field_class = classify_field(path)
        if field_class == "strong":
            return [_candidate(value, _secret_key_kind(path) or "secret", 85, "sensitive_field")], True
        if field_class == "medium":
            entropy, classes = disk_entropy(value, deadline=deadline)
            if entropy >= 3.0 and (classes >= 2 or value.byte_length >= 24):
                return [
                    _candidate(
                        value, _secret_key_kind(path) or "secret", 73 if entropy >= 3.5 else 68, "sensitive_field"
                    )
                ], True
            return [], True
    return detections, complete


def _needs_disk_scan(value: Any) -> bool:
    return isinstance(value, DiskBackedText) or (
        isinstance(value, str)
        and (
            len(value) > 65_536
            or compressed_text_prefix(value)
            or mime_text_prefix(value)
            or (value.lstrip().startswith("<") and ">" in value[:256] and "</" in value[-256:])
        )
    )


class _SpoolingElasticFindingList(list[Finding]):
    """Sorted, lazy view over the accumulator's SQLite records."""

    def __init__(self, owner: FindingAccumulator) -> None:
        super().__init__()
        self._owner = owner

    def __len__(self) -> int:
        return self._owner._count

    def __iter__(self) -> Iterator[Finding]:
        with self._owner._lock:
            assert self._owner._db is not None
            self._owner._db.commit()
            cursor = self._owner._db.execute(
                "SELECT payload FROM findings ORDER BY score DESC, secret_type, fingerprint"
            )
            for (payload,) in cursor:
                item = self._owner._decode_disk_refs(json.loads(payload))
                item["value"] = self._owner._restore_value(item["fingerprint"], item["value"])
                yield Finding(
                    fingerprint=item["fingerprint"],
                    value=item["value"],
                    secret_type=item["secret_type"],
                    confidence=item["confidence"],
                    score=item["score"],
                    detectors=item["detectors"],
                    occurrence_count=item["occurrence_count"],
                    locations=[FindingLocation(**location) for location in item["locations"]],
                )

    @overload
    def __getitem__(self, index: SupportsIndex, /) -> Finding: ...

    @overload
    def __getitem__(self, index: slice, /) -> list[Finding]: ...

    def __getitem__(self, index: SupportsIndex | slice, /) -> Finding | list[Finding]:
        if isinstance(index, slice):
            return _slice_values(self, index)
        position = operator.index(index)
        if position < 0:
            position += len(self)
        if not 0 <= position < len(self):
            raise IndexError(position)
        with self._owner._lock:
            assert self._owner._db is not None
            row = self._owner._db.execute(
                "SELECT fingerprint FROM findings ORDER BY score DESC,secret_type,fingerprint LIMIT 1 OFFSET ?",
                (position,),
            ).fetchone()
            assert row is not None
            finding = self._owner._stored_finding(row[0])
            assert finding is not None
            return finding

    def __reversed__(self) -> Iterator[Finding]:
        # Explicit reverse slices retain only the requested prefix.
        with self._owner._lock:
            assert self._owner._db is not None
            for (identity,) in self._owner._db.execute(
                "SELECT fingerprint FROM findings ORDER BY score ASC,secret_type DESC,fingerprint DESC"
            ):
                finding = self._owner._stored_finding(identity)
                assert finding is not None
                yield finding

    def to_dict_spool(self) -> SpoolingFindings:
        result = SpoolingFindings()
        for finding in self:
            result.add(finding.to_dict(), identity=(finding.secret_type, finding.fingerprint))
        result.finish()
        return result


class FindingAccumulator(_DiskValueReferences):
    """Secret-level deduplication with bounded location retention."""

    def __init__(
        self,
        max_findings: int | None = None,
        max_locations: int = DEFAULT_MAX_LOCATIONS,
        on_finding: Callable[[Finding], None] | None = None,
        spill_threshold: int = 4096,
    ) -> None:
        self.max_findings = None if max_findings is None else max(0, int(max_findings))
        self.max_locations = max(1, int(max_locations))
        self._items: dict[str, Finding] = {}
        self._retained_value_bytes = 0
        self._spill_threshold = max(1, int(spill_threshold))
        self._temporary: tempfile.TemporaryDirectory[str] | None = None
        self._db: sqlite3.Connection | None = None
        self._count = 0
        self.limit_reached = False
        self.locations_dropped = 0
        self._lock = threading.RLock()
        self._on_finding = on_finding
        self._disk_values: dict[str, DiskBackedText] = {}
        self._disk_refs = {}
        self._spool_refs = {}

    def __del__(self) -> None:
        database = getattr(self, "_db", None)
        if database is not None:
            database.close()
        temporary = getattr(self, "_temporary", None)
        if temporary is not None:
            temporary.cleanup()

    @staticmethod
    def fingerprint(secret_type: str, value: str | DiskBackedText) -> str:
        hasher = hashlib.sha256()
        hasher.update(f"{secret_type}\0".encode())
        if isinstance(value, DiskBackedText):
            for chunk in value.iter_text_chunks():
                hasher.update(chunk.encode("utf-8"))
        else:
            hasher.update(value.encode("utf-8", errors="replace"))
        return f"sha256:{hasher.hexdigest()}"

    def _serialize_finding(self, finding: Finding) -> str:
        payload = finding.to_dict()
        if isinstance(finding.value, DiskBackedText):
            self._disk_values[finding.fingerprint] = finding.value
            payload["value"] = {"_disk_value": finding.fingerprint}
        pending: dict[str, Any] = {}
        encoded = self._encode_disk_refs(payload, pending)
        result = json.dumps(encoded, ensure_ascii=False)
        self._commit_refs(pending)
        return result

    def _restore_value(self, fingerprint: str, value: Any) -> str | DiskBackedText:
        if isinstance(value, dict) and value.get("_disk_value") == fingerprint:
            return self._disk_values[fingerprint]
        return str(value)

    def _spill(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="redposture-elastic-findings-")
        db = sqlite3.connect(Path(temporary.name) / "findings.sqlite3", check_same_thread=False, isolation_level=None)
        try:
            db.execute("PRAGMA journal_mode=MEMORY")
            db.execute("PRAGMA synchronous=OFF")
            db.execute(
                "CREATE TABLE findings (fingerprint TEXT PRIMARY KEY, score INTEGER NOT NULL, "
                "secret_type TEXT NOT NULL, payload TEXT NOT NULL)"
            )
            db.executemany(
                "INSERT INTO findings VALUES (?, ?, ?, ?)",
                (
                    (finding.fingerprint, finding.score, finding.secret_type, self._serialize_finding(finding))
                    for finding in self._items.values()
                ),
            )
        except sqlite3.Error as exc:
            db.close()
            temporary.cleanup()
            raise OSError(f"Elastic finding storage failure: {exc}") from exc
        self._temporary, self._db = temporary, db
        self._items.clear()
        self._retained_value_bytes = 0

    def _stored_finding(self, fingerprint: str) -> Finding | None:
        assert self._db is not None
        row = self._db.execute("SELECT payload FROM findings WHERE fingerprint=?", (fingerprint,)).fetchone()
        if row is None:
            return None
        item = self._decode_disk_refs(json.loads(row[0]))
        item["value"] = self._restore_value(fingerprint, item["value"])
        return Finding(
            fingerprint=item["fingerprint"],
            value=item["value"],
            secret_type=item["secret_type"],
            confidence=item["confidence"],
            score=item["score"],
            detectors=item["detectors"],
            occurrence_count=item["occurrence_count"],
            locations=[FindingLocation(**location) for location in item["locations"]],
        )

    def _save_finding(self, finding: Finding) -> None:
        assert self._db is not None
        try:
            self._db.execute(
                "INSERT OR REPLACE INTO findings VALUES (?, ?, ?, ?)",
                (
                    finding.fingerprint,
                    finding.score,
                    finding.secret_type,
                    self._serialize_finding(finding),
                ),
            )

        except sqlite3.Error as exc:
            raise OSError(f"Elastic finding storage failure: {exc}") from exc

    def add(self, detection: DetectedSecret, location: FindingLocation) -> bool:
        if not detection.available or detection.score < 55:
            return False
        if isinstance(location.path, DiskBackedText) and not isinstance(detection.value, DiskBackedText):
            value = DiskBackedText()
            try:
                value.append_text(detection.value)
                value.finish()
            except BaseException:
                value.close()
                raise
            detection = DetectedSecret(value, detection.secret_type, detection.score, detection.detectors)
        created: Finding | None = None
        with self._lock:
            fingerprint = self.fingerprint(detection.secret_type, detection.value)
            existing = self._stored_finding(fingerprint) if self._db is not None else self._items.get(fingerprint)
            if existing is not None:
                if isinstance(detection.value, DiskBackedText) and detection.value is not existing.value:
                    detection.value.close()
                existing.score = max(existing.score, detection.score)
                existing.confidence = _confidence(existing.score)
                existing.detectors = sorted(set(existing.detectors) | set(detection.detectors))
                if location not in existing.locations:
                    existing.occurrence_count += 1
                    if len(existing.locations) < self.max_locations:
                        existing.locations.append(location)
                    else:
                        self.locations_dropped += 1
                if self._db is not None:
                    self._save_finding(existing)
                return True
            if self.max_findings is not None and self._count >= self.max_findings:
                self.limit_reached = True
                if isinstance(detection.value, DiskBackedText):
                    detection.value.close()
                return False
            created = Finding(
                fingerprint=fingerprint,
                value=detection.value,
                secret_type=detection.secret_type,
                confidence=_confidence(detection.score),
                score=detection.score,
                detectors=sorted(set(detection.detectors)),
                occurrence_count=1,
                locations=[location],
            )
            if self._db is None and (
                isinstance(created.value, DiskBackedText)
                or self._count >= self._spill_threshold
                or self._retained_value_bytes + created.value.__sizeof__() > 4 * 1024 * 1024
            ):
                self._spill()
            if self._db is not None:
                self._save_finding(created)
            else:
                self._items[fingerprint] = created
                self._retained_value_bytes += created.value.__sizeof__()
            self._count += 1
        if created is not None and self._on_finding is not None:
            self._on_finding(created)
        return True

    def findings(self) -> list[Finding]:
        with self._lock:
            if self._db is not None:
                return _SpoolingElasticFindingList(self)
            return sorted(self._items.values(), key=lambda item: (-item.score, item.secret_type, item.fingerprint))

    def __len__(self) -> int:
        with self._lock:
            return self._count


class _DocumentLedger:
    """Deduplicate document and candidate IDs without retaining all IDs in RAM."""

    def __init__(self, *, spill_threshold: int = 4096) -> None:
        self._threshold = max(1, spill_threshold)
        self._seen: dict[tuple[str, str], bool] = {}
        self._payloads: set[tuple[str, str, str]] = set()
        self._missing: set[tuple[str, str]] = set()
        self._candidates: set[tuple[str, str]] = set()
        self._candidate_counts: dict[str, int] = {}
        self._temporary: tempfile.TemporaryDirectory[str] | None = None
        self._db: sqlite3.Connection | None = None
        self._seen_count = 0

    def __del__(self) -> None:
        database = getattr(self, "_db", None)
        if database is not None:
            database.close()
        temporary = getattr(self, "_temporary", None)
        if temporary is not None:
            temporary.cleanup()

    def _spill(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="redposture-elastic-docs-")
        db = sqlite3.connect(Path(temporary.name) / "documents.sqlite3", isolation_level=None)
        try:
            db.execute("PRAGMA journal_mode=MEMORY")
            db.execute("PRAGMA synchronous=OFF")
            db.executescript(
                "CREATE TABLE seen (idx TEXT, doc_id TEXT, complete INTEGER, PRIMARY KEY(idx, doc_id));"
                "CREATE TABLE payloads (idx TEXT, doc_id TEXT, fingerprint TEXT, PRIMARY KEY(idx, doc_id, fingerprint));"
                "CREATE TABLE missing (idx TEXT, doc_id TEXT, PRIMARY KEY(idx, doc_id));"
                "CREATE TABLE candidates (idx TEXT, doc_id TEXT, PRIMARY KEY(idx, doc_id));"
            )
            db.executemany(
                "INSERT INTO seen VALUES (?, ?, ?)",
                ((index, doc_id, int(complete)) for (index, doc_id), complete in self._seen.items()),
            )
            db.executemany("INSERT INTO payloads VALUES (?, ?, ?)", self._payloads)
            db.executemany("INSERT INTO missing VALUES (?, ?)", self._missing)
            db.executemany("INSERT INTO candidates VALUES (?, ?)", self._candidates)
        except sqlite3.Error as exc:
            db.close()
            temporary.cleanup()
            raise OSError(f"Elastic document storage failure: {exc}") from exc
        self._temporary, self._db = temporary, db
        self._seen.clear()
        self._payloads.clear()
        self._missing.clear()
        self._candidates.clear()
        self._candidate_counts.clear()

    def _maybe_spill(self) -> None:
        if sum(map(len, (self._seen, self._payloads, self._missing, self._candidates))) > self._threshold:
            self._spill()

    def _execute(self, query: str, parameters: tuple[Any, ...]) -> sqlite3.Cursor:
        assert self._db is not None
        try:
            return self._db.execute(query, parameters)
        except sqlite3.Error as exc:
            raise OSError(f"Elastic document storage failure: {exc}") from exc

    def seen(self, key: tuple[str, str]) -> bool | None:
        if self._db is None:
            return self._seen.get(key)
        row = self._execute("SELECT complete FROM seen WHERE idx=? AND doc_id=?", key).fetchone()
        return None if row is None else bool(row[0])

    def mark_seen(self, key: tuple[str, str], complete: bool) -> None:
        previous = self.seen(key)
        if self._db is None:
            self._seen[key] = complete
        else:
            self._execute("INSERT OR REPLACE INTO seen VALUES (?, ?, ?)", (*key, int(complete)))
        if previous is None:
            self._seen_count += 1
        if self._db is None:
            self._maybe_spill()

    def has_payload(self, key: tuple[str, str], fingerprint: str) -> bool:
        if self._db is None:
            return (*key, fingerprint) in self._payloads
        return (
            self._execute(
                "SELECT 1 FROM payloads WHERE idx=? AND doc_id=? AND fingerprint=?", (*key, fingerprint)
            ).fetchone()
            is not None
        )

    def add_payload(self, key: tuple[str, str], fingerprint: str) -> None:
        if self._db is None:
            self._payloads.add((*key, fingerprint))
            self._maybe_spill()
        else:
            self._execute("INSERT OR IGNORE INTO payloads VALUES (?, ?, ?)", (*key, fingerprint))

    def add_missing(self, key: tuple[str, str]) -> bool:
        if self._db is None:
            if key in self._missing:
                return False
            self._missing.add(key)
            self._maybe_spill()
            return True
        return bool(self._execute("INSERT OR IGNORE INTO missing VALUES (?, ?)", key).rowcount)

    def add_candidate(self, key: tuple[str, str]) -> bool:
        if self._db is None:
            if key in self._candidates:
                return False
            self._candidates.add(key)
            self._candidate_counts[key[0]] = self._candidate_counts.get(key[0], 0) + 1
            self._maybe_spill()
            return True
        return bool(self._execute("INSERT OR IGNORE INTO candidates VALUES (?, ?)", key).rowcount)

    def candidate_count(self, index: str) -> int:
        if self._db is not None:
            return int(self._execute("SELECT COUNT(*) FROM candidates WHERE idx=?", (index,)).fetchone()[0])
        return self._candidate_counts.get(index, 0)

    def __bool__(self) -> bool:
        return self._seen_count > 0


def _json_pointer_escape(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def scan_value_tree(
    value: Any,
    *,
    source_kind: str,
    object_name: str,
    index: str | None = None,
    document_id: str | None = None,
    path: str = "",
    options: DiscoverOptions | None = None,
    deadline: float | None = None,
) -> ScanResult:
    """Recursively scan JSON-like data and embedded JSON strings."""

    effective_options = options or DiscoverOptions()
    deadline = deadline if deadline is not None else time.monotonic() + effective_options.max_seconds
    result = ScanResult()

    def add_reason(reason: str) -> None:
        if reason not in result.truncated_reasons:
            result.truncated_reasons.append(reason)

    def walk(current: Any, pointer: Text, depth: int, key_hint: str, base64_decoded: bool = False) -> None:
        if time.monotonic() >= deadline:
            add_reason("max_seconds")
            return
        if depth > effective_options.max_depth:
            add_reason("max_depth")
            return
        if isinstance(current, Mapping):
            processed_value_key: str | None = None
            semantic_names = {
                "aws_access_key_id",
                "aws_secret_access_key",
                "secret_access_key",
                "field",
                "target_field",
                "name",
                "key",
                "kind",
                "type",
                "value",
            }
            normalized_items = {
                normalized: (key, child)
                for key, child in current.items()
                if (
                    normalized := (
                        _disk_field_hint(key, deadline, normalized_name=True)
                        if isinstance(key, DiskBackedText)
                        else normalize_field_name(str(key))
                    )
                )
                in semantic_names
            }
            aws_access_item = normalized_items.get("aws_access_key_id")
            aws_secret_item = normalized_items.get("aws_secret_access_key")
            if aws_secret_item is None:
                aws_secret_item = normalized_items.get("secret_access_key")
            aws_access = aws_access_item[1] if aws_access_item else None
            aws_secret = aws_secret_item[1] if aws_secret_item else None
            if isinstance(aws_access, str) and isinstance(aws_secret, str) and _AWS_ACCESS_RE.fullmatch(aws_access):
                if _AWS_SECRET_RE.fullmatch(aws_secret) and not _looks_placeholder(aws_secret):
                    secret_key = aws_secret_item[0] if aws_secret_item else "aws_secret_access_key"
                    result.detections.append(
                        (
                            _candidate(
                                aws_secret,
                                "aws_secret_access_key",
                                99,
                                "aws_credential_pair",
                                "sensitive_field",
                            ),
                            FindingLocation(
                                source_kind=source_kind,
                                object=object_name,
                                index=index,
                                id=document_id,
                                path=json_discovery_path((secret_key,), pointer, style="pointer"),
                            ),
                        )
                    )
            field_item = (
                normalized_items.get("field")
                or normalized_items.get("target_field")
                or normalized_items.get("name")
                or normalized_items.get("key")
                or normalized_items.get("kind")
                or normalized_items.get("type")
            )
            value_item = normalized_items.get("value")
            if (
                field_item is not None
                and value_item is not None
                and isinstance(field_item[1], str)
                and not isinstance(value_item[1], (Mapping, list, tuple))
            ):
                semantic_path = field_item[1]
                if _needs_disk_scan(value_item[1]):
                    walk(
                        value_item[1],
                        json_discovery_path((value_item[0],), pointer, style="pointer"),
                        depth + 1,
                        semantic_path,
                        base64_decoded,
                    )
                    processed_value_key = value_item[0]
                    semantic_detections = []
                else:
                    semantic_detections = analyze_value(
                        value_item[1], path=semantic_path, field_classification=classify_field(semantic_path)
                    )
                for detection in semantic_detections:
                    if detection.available:
                        result.detections.append(
                            (
                                detection,
                                FindingLocation(
                                    source_kind=source_kind,
                                    object=object_name,
                                    index=index,
                                    id=document_id,
                                    path=json_discovery_path((value_item[0],), pointer, style="pointer"),
                                ),
                            )
                        )
                    else:
                        result.suppressed_indicators += 1
            for raw_key, child in current.items():
                key = _disk_field_hint(raw_key, deadline) if isinstance(raw_key, DiskBackedText) else str(raw_key)
                if "max_seconds" in result.truncated_reasons:
                    break
                if raw_key == processed_value_key:
                    continue
                child_hint = f"{key_hint}.{key}" if key_hint else key
                walk(
                    child,
                    json_discovery_path((raw_key,), pointer, style="pointer"),
                    depth + 1,
                    child_hint,
                    base64_decoded,
                )
            return
        if isinstance(current, (list, tuple)):
            if effective_options.max_array_items is not None and len(current) > effective_options.max_array_items:
                add_reason("max_array_items")
            selected = (
                current if effective_options.max_array_items is None else current[: effective_options.max_array_items]
            )
            for offset, child in enumerate(selected):
                walk(child, concat_discovery_text(pointer, f"/{offset}"), depth + 1, key_hint, base64_decoded)
            return
        classification_path = key_hint or (
            _disk_field_hint(pointer, deadline) if isinstance(pointer, DiskBackedText) else pointer
        )
        if _needs_disk_scan(current):
            disk = current if isinstance(current, DiskBackedText) else DiskBackedText()
            try:
                if isinstance(current, str):
                    for offset in range(0, len(current), 65_536):
                        if time.monotonic() >= deadline:
                            add_reason("max_seconds")
                            return
                        disk.append_text(current[offset : offset + 65_536])
                    disk.finish()
                detections, complete = _analyze_disk_value(disk, path=classification_path, deadline=deadline)
                if not complete:
                    add_reason(getattr(detections, "incomplete_reason", None) or "streamed_scalar_unverified")
                location = FindingLocation(
                    source_kind=source_kind, object=object_name, index=index, id=document_id, path=pointer or "/"
                )
                result.detections.extend((detection, location) for detection in detections)
            except TimeoutError:
                add_reason("max_seconds")
            finally:
                if isinstance(current, str) and not any(
                    detection.value is disk for detection, _location in result.detections
                ):
                    disk.close()
            return
        if isinstance(current, (bytes, bytearray)):
            scalar_text = bytes(current).decode("utf-8", errors="replace")
        elif isinstance(current, (str, int, float)) and not isinstance(current, bool):
            scalar_text = str(current)
        else:
            return
        scalar_size = len(scalar_text.encode("utf-8", errors="replace"))
        # This scalar is already materialized by the caller. A byte window
        # here would only discard a complete, available credential. Network
        # responses large enough to need bounded memory use StreamedSearchPage.
        location = FindingLocation(
            source_kind=source_kind,
            object=object_name,
            index=index,
            id=document_id,
            path=pointer or "/",
        )
        detections = analyze_value(
            scalar_text,
            path=classification_path,
            field_classification=classify_field(classification_path),
            allow_base64=not base64_decoded,
        )
        decoded_json: dict[str, Any] | list[Any] | None = None
        if not base64_decoded and classify_field(classification_path) in {"strong", "medium"}:
            decoded = _decode_credential_base64(scalar_text)
            if decoded and len(decoded.encode("utf-8")) <= effective_options.max_embedded_json_bytes:
                try:
                    parsed_decoded = json.loads(decoded)
                except (TypeError, ValueError):
                    parsed_decoded = None
                if isinstance(parsed_decoded, (dict, list)):
                    decoded_json = parsed_decoded
        for detection in detections:
            if decoded_json is not None and detection.secret_type == "encoded_credentials":
                continue
            if detection.available:
                result.detections.append((detection, location))
            else:
                result.suppressed_indicators += 1
        if decoded_json is not None and depth < effective_options.max_depth:
            walk(decoded_json, pointer, depth + 1, key_hint, True)
        if not base64_decoded and scalar_size <= effective_options.max_embedded_json_bytes:
            decoded_structured = _decode_structured_blob(scalar_text, effective_options.max_embedded_json_bytes)
            if decoded_structured and depth < effective_options.max_depth:
                try:
                    decoded_value = json.loads(decoded_structured)
                except ValueError:
                    decoded_value = decoded_structured
                walk(decoded_value, pointer, depth + 1, key_hint, True)
        if not base64_decoded and scalar_size <= effective_options.max_embedded_json_bytes:

            def unescape(part: str) -> str:
                part = part.replace('\\"', '"')
                return re.sub(r"\\u([0-9a-fA-F]{4})", lambda match: chr(int(match.group(1), 16)), part)

            # Unescape an outer encoded log/JSON representation, never the
            # contents of an already recognized raw assignment literal.
            protected = AssignmentLiterals(scalar_text, lambda name: _secret_key_kind(name) is not None)
            pieces: list[str] = []
            offset = 0
            for literal in protected.items:
                pieces.extend((unescape(scalar_text[offset : literal.start]), scalar_text[literal.start : literal.end]))
                offset = literal.end
            pieces.append(unescape(scalar_text[offset:]))
            unescaped = "".join(pieces)
            if unescaped != scalar_text and depth < effective_options.max_depth:
                walk(unescaped, pointer, depth + 1, key_hint, True)
        stripped = scalar_text.lstrip()
        if (
            stripped.startswith(("{", "["))
            and scalar_size <= effective_options.max_embedded_json_bytes
            and depth < effective_options.max_depth
        ):
            try:
                embedded = json.loads(scalar_text)
            except (TypeError, ValueError):
                return
            if isinstance(embedded, (dict, list)):
                walk(embedded, pointer, depth + 1, key_hint, base64_decoded)

    try:
        walk(value, path, 0, "")
    except OSError:
        add_reason("storage_failure")
    return result


class DiscoveryBudget:
    """Target-wide document/time limits and a per-source byte portion bound."""

    def __init__(
        self,
        options: DiscoverOptions | None = None,
        *,
        monotonic: Callable[[], float] = time.monotonic,
        started_at: float | None = None,
    ) -> None:
        self.options = options or DiscoverOptions()
        self._monotonic = monotonic
        self.started_at = monotonic() if started_at is None else started_at
        self.documents = 0
        self.source_bytes = 0
        self.reasons: list[str] = []
        self._lock = threading.RLock()

    def _add_reason(self, reason: str) -> None:
        if reason not in self.reasons:
            self.reasons.append(reason)

    def stop(self, reason: str) -> None:
        """Stop future work after a target-wide limit is proven exhausted."""

        with self._lock:
            self._add_reason(reason)

    def check(self, *, findings: int = 0) -> bool:
        with self._lock:
            if self.options.max_documents is not None and self.documents > self.options.max_documents:
                self._add_reason("max_documents")
            if self._monotonic() - self.started_at >= self.options.max_seconds:
                self._add_reason("max_seconds")
            if self.options.max_findings is not None and findings > self.options.max_findings:
                self._add_reason("max_findings")
            return not self.reasons

    def consume_document(self, source_bytes: int, *, findings: int = 0) -> bool:
        with self._lock:
            if not self.check(findings=findings):
                return False
            proposed_bytes = self.source_bytes + max(0, int(source_bytes))
            if self.options.max_documents is not None and self.documents + 1 > self.options.max_documents:
                self._add_reason("max_documents")
                return False
            if self.options.max_source_bytes is not None and source_bytes > self.options.max_source_bytes:
                self._add_reason("max_source_bytes")
                return False
            self.documents += 1
            self.source_bytes = proposed_bytes
            return True

    def consume_source_bytes(self, source_bytes: int, *, findings: int = 0) -> bool:
        """Account richer re-fetches of an already counted unique document."""

        with self._lock:
            if not self.check(findings=findings):
                return False
            proposed_bytes = self.source_bytes + max(0, int(source_bytes))
            if self.options.max_source_bytes is not None and source_bytes > self.options.max_source_bytes:
                self._add_reason("max_source_bytes")
                return False
            self.source_bytes = proposed_bytes
            return True

    @property
    def stopped(self) -> bool:
        with self._lock:
            return bool(self.reasons)


def _normalize_request_result(result: RawRequestResult) -> DiscoverResponse:
    if isinstance(result, DiscoverResponse):
        return result
    if len(result) == 4:
        status, payload, headers, error = result
        return DiscoverResponse(status=status, payload=payload, headers=headers, error=error)
    status, payload, headers, error, truncated = result
    return DiscoverResponse(
        status=status,
        payload=payload,
        headers=headers,
        error=error,
        truncated=bool(truncated),
    )


def _load_json(payload: bytes) -> Any:
    try:
        if len(payload) > 256 * 1024:
            document = DiskJSONDocument()
            try:
                for offset in range(0, len(payload), 65_536):
                    document.feed(payload[offset : offset + 65_536])
                return document.finish()
            finally:
                document.close()
        return json.loads(payload.decode("utf-8", errors="replace"))
    except (TypeError, ValueError):
        return None


def _error_detail(response: DiscoverResponse, parsed: Any = None) -> JsonObject:
    if response.error:
        return {
            "status": 0,
            "type": "transport_error",
            "reason": response.error,
            "root_cause": [],
        }
    detail: JsonObject = {
        "status": response.status,
        "type": "http_error",
        "reason": f"status={response.status}",
        "root_cause": [],
    }
    if not isinstance(parsed, Mapping):
        parsed = _load_json(response.payload)
    if not isinstance(parsed, Mapping):
        return detail
    error = parsed.get("error")
    if isinstance(error, str):
        detail["reason"] = error
        return detail
    if not isinstance(error, Mapping):
        return detail
    if error.get("type"):
        detail["type"] = str(error.get("type"))
    if error.get("reason"):
        detail["reason"] = str(error.get("reason"))
    root_cause = error.get("root_cause")
    if isinstance(root_cause, list):
        detail["root_cause"] = [
            {
                "type": str(item.get("type") or ""),
                "reason": str(item.get("reason") or ""),
            }
            for item in root_cause
            if isinstance(item, Mapping)
        ]
    caused_by = error.get("caused_by")
    if isinstance(caused_by, Mapping):
        detail["caused_by"] = {
            "type": str(caused_by.get("type") or ""),
            "reason": str(caused_by.get("reason") or ""),
        }
    return detail


def _closed_search_page(response: DiscoverResponse) -> bool:
    """A proxy may close an oversized page before returning an HTTP status."""

    if response.status != 0 or not response.error:
        return False
    error = response.error.lower()
    return any(
        marker in error
        for marker in ("remote end closed", "connection reset", "incomplete read", "incompleteread", "unexpected eof")
    )


def _is_missing_search_context(response: DiscoverResponse, parsed: Any = None) -> bool:
    """Return whether a failed search lost its server-side PIT/scroll context.

    Elasticsearch and OpenSearch commonly wrap ``search_context_missing_exception``
    in ``search_phase_execution_exception``.  Some releases instead return a
    ``resource_not_found_exception`` whose reason mentions a PIT.  Restrict the
    textual fallback to search/PIT context wording so an unrelated 404 (for
    example a deleted index) is not retried as pagination expiry.
    """

    if response.error or response.status not in {400, 404, 500, 503}:
        return False
    if not isinstance(parsed, Mapping):
        parsed = _load_json(response.payload)
    if not isinstance(parsed, Mapping):
        return False

    pending: list[Any] = [parsed.get("error", parsed)]
    while pending:
        value = pending.pop()
        if isinstance(value, Mapping):
            error_type = str(value.get("type") or "").strip().lower()
            reason = str(value.get("reason") or "").strip().lower()
            if error_type in {
                "search_context_missing_exception",
                "point_in_time_missing_exception",
            }:
                return True
            if "no search context found" in reason:
                return True
            mentions_context = (
                "search context" in reason or "point in time" in reason or re.search(r"\bpit\b", reason) is not None
            )
            if mentions_context and any(marker in reason for marker in ("missing", "not found", "expired")):
                return True
            pending.extend(value.values())
        elif isinstance(value, (list, tuple)):
            pending.extend(value)
    return False


def _legacy_search_adjustment(
    response: DiscoverResponse,
    parsed: Any,
    body: Mapping[str, Any],
    path: str,
    legacy_path: str,
) -> tuple[JsonObject, str, tuple[str, ...]] | None:
    """Remove only optional modern search elements explicitly rejected by 1.x.

    The response must be a parse/unknown-element HTTP 400 and name the exact
    request element.  This deliberately avoids replaying arbitrary bad queries
    and authorization/transport failures.
    """

    if response.error or response.status != 400:
        return None
    error_value = parsed.get("error") if isinstance(parsed, Mapping) else parsed
    error_text = json.dumps(error_value, ensure_ascii=False, default=str).lower()
    compatibility_markers = (
        "no parser for element",
        "unknown key",
        "unknown field",
        "unknown parameter",
        "unrecognized parameter",
        "not supported",
        "unsupported",
    )
    if not any(marker in error_text for marker in compatibility_markers):
        return None

    adjusted = dict(body)
    changes: list[str] = []
    for name in ("track_total_hits", "stored_fields", "docvalue_fields", "runtime_mappings"):
        if name in adjusted and name in error_text:
            adjusted.pop(name, None)
            changes.append(name)
    adjusted_path = path
    if path != legacy_path and "expand_wildcards" in error_text:
        adjusted_path = legacy_path
        changes.append("expand_wildcards")
    if not changes:
        return None
    return adjusted, adjusted_path, tuple(changes)


def _surface_status(response: DiscoverResponse) -> SurfaceStatus:
    if response.status in {401, 403}:
        return "denied"
    if response.status in {404, 405, 501}:
        return "unsupported"
    if response.error:
        lowered = response.error.lower()
        return "timeout" if "timed out" in lowered or "timeout" in lowered else "error"
    if response.truncated:
        return "partial"
    return "error"


def _quote_indices(indices: Sequence[str]) -> str:
    return ",".join(urllib.parse.quote(index, safe="") for index in indices)


def _extract_mapping_configuration(payload: Mapping[str, Any]) -> JsonObject:
    """Return only mapping definitions which may themselves contain values."""

    result: JsonObject = {}

    def field_configuration(properties: Mapping[str, Any]) -> JsonObject:
        selected: JsonObject = {}
        for raw_name, raw_definition in properties.items():
            if not isinstance(raw_definition, Mapping):
                continue
            definition: JsonObject = {}
            if isinstance(raw_definition.get("meta"), Mapping):
                definition["meta"] = dict(raw_definition["meta"])
            children = raw_definition.get("properties")
            if isinstance(children, Mapping):
                nested = field_configuration(children)
                if nested:
                    definition["properties"] = nested
            fields = raw_definition.get("fields")
            if isinstance(fields, Mapping):
                nested_fields = field_configuration(fields)
                if nested_fields:
                    definition["fields"] = nested_fields
            if definition:
                selected[str(raw_name)] = definition
        return selected

    for raw_index, raw_definition in payload.items():
        if not isinstance(raw_definition, Mapping):
            continue
        mappings = raw_definition.get("mappings", raw_definition)
        if not isinstance(mappings, Mapping):
            continue
        selected_mapping: JsonObject = {}
        for name in ("_meta", "runtime", "derived", "dynamic_templates"):
            value = mappings.get(name)
            if isinstance(value, (Mapping, list)):
                selected_mapping[name] = value
        properties = mappings.get("properties")
        if isinstance(properties, Mapping):
            selected_properties = field_configuration(properties)
            if selected_properties:
                selected_mapping["properties"] = selected_properties
        if selected_mapping:
            result[str(raw_index)] = selected_mapping
    return result


def _mapping_source_policy(payload: Mapping[str, Any], index: str) -> tuple[bool, bool]:
    """Return whether mapping-level ``_source`` is disabled or filtered."""

    raw_index = payload.get(index)
    if not isinstance(raw_index, Mapping):
        return False, False
    mappings = raw_index.get("mappings", raw_index)
    if not isinstance(mappings, Mapping):
        return False, False
    source = mappings.get("_source")
    if not isinstance(source, Mapping):
        return False, False
    disabled = source.get("enabled") is False
    filtered = any(
        source.get(name) not in (None, [], (), {}) for name in ("includes", "include", "excludes", "exclude")
    )
    return disabled, filtered


class DiscoverEngine:
    """Run mapping-aware, bounded discovery against one API target."""

    def __init__(
        self,
        request: RequestFn,
        *,
        vendor: str = "compatible",
        options: DiscoverOptions | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        started_at: float | None = None,
        nested_scheduler: Any | None = None,
        scheduler_key: Any | None = None,
        on_finding: Callable[[Finding], None] | None = None,
    ) -> None:
        self.request_callback = request
        self.vendor = vendor.strip().lower()
        if self.vendor not in {"elasticsearch", "opensearch"}:
            self.vendor = "compatible"
        self.options = options or DiscoverOptions()
        self.monotonic = monotonic
        self.nested_scheduler = nested_scheduler
        self.scheduler_key = scheduler_key
        self.budget = DiscoveryBudget(self.options, monotonic=monotonic, started_at=started_at)
        self.coverage = DiscoverCoverage(
            limits={
                "max_documents": self.options.max_documents,
                "max_source_bytes": self.options.max_source_bytes,
                "max_seconds": self.options.max_seconds,
                "max_findings": self.options.max_findings,
                "max_depth": self.options.max_depth,
                "max_array_items": self.options.max_array_items,
                "max_scalar_bytes": self.options.max_scalar_bytes,
                "max_embedded_json_bytes": self.options.max_embedded_json_bytes,
            },
            scope={
                "documents": "open and hidden indices plus resolved data-stream backing indices",
                "configuration": [
                    "cluster_settings",
                    "node_settings",
                    "index_settings",
                    "mappings",
                    "index_templates",
                    "component_templates",
                    "legacy_templates",
                    "ingest_pipelines",
                ],
            },
            limitations=[
                "secure keystore settings are not readable through the API",
                "closed indices, snapshots, Watcher, connectors, Alerting, Notifications and stored scripts are not scanned",
                "FLS/DLS and current authorization can hide documents or fields",
            ],
        )
        self.accumulator = FindingAccumulator(
            max_findings=self.options.max_findings,
            max_locations=self.options.max_locations,
            on_finding=on_finding,
        )
        self._documents = _DocumentLedger()
        self._legacy_by_index: dict[str, JsonObject] = {}

    @staticmethod
    def _merge_index_coverage(target: DiscoverCoverage, source: DiscoverCoverage) -> None:
        target.pages_scanned += source.pages_scanned
        target.query_candidates += source.query_candidates
        target.shard_failures.extend(source.shard_failures)
        target.missing_source_documents += source.missing_source_documents
        target.duplicate_documents += source.duplicate_documents
        target.suppressed_indicators += source.suppressed_indicators
        target.timed_out = target.timed_out or source.timed_out
        for reason in source.truncated_reasons:
            target.mark_truncated(reason)

    def _scan_index_isolated(
        self, item: tuple[str, tuple[MappedField, ...]]
    ) -> tuple[str, JsonObject, DiscoverCoverage, bool, bool]:
        index, fields = item
        child = DiscoverEngine(
            self.request_callback,
            vendor=self.vendor,
            options=self.options,
            monotonic=self.monotonic,
            nested_scheduler=self.nested_scheduler,
        )
        child.budget = self.budget
        child.accumulator = self.accumulator
        attempted = not child.budget.stopped
        if not attempted:
            return index, {}, child.coverage, False, False
        child._scan_index(index, fields)
        legacy = child._legacy_result(index)
        scanned = bool(child._documents) or int(legacy.get("total_hits") or 0) == 0
        return index, legacy, child.coverage, scanned, True

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: Mapping[str, Any] | list[Any] | None = None,
        cleanup: bool = False,
        stream_search: bool = False,
    ) -> tuple[DiscoverResponse, Any]:
        if bool(getattr(self.nested_scheduler, "cancelled", False)):
            raise NestedSchedulerCancelled("Elastic discovery cancelled")
        if not cleanup and not self.budget.check(findings=len(self.accumulator)):
            return (
                DiscoverResponse(status=0, payload=b"", error="discover budget exhausted"),
                None,
            )
        headers: dict[str, str] = {}
        encoded: bytes | None = None
        if body is not None:
            headers["Content-Type"] = "application/json; charset=utf-8"
            encoded = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        try:
            raw_result = self.request_callback(
                DiscoverRequest(method=method, path=path, headers=headers, body=encoded, stream_search=stream_search)
            )
            response = _normalize_request_result(raw_result)
        except Exception as exc:  # transport adapters are user/integration code
            response = DiscoverResponse(
                status=0,
                payload=b"",
                error=str(exc).strip() or exc.__class__.__name__,
            )
        try:
            parsed = (
                response.streamed_search.summary()
                if response.streamed_search is not None
                else response.parsed_payload
                if response.parsed_payload is not None
                else _load_json(response.payload)
                if response.payload
                else None
            )
        except (ValueError, OSError) as exc:
            if response.streamed_search is not None:
                response.streamed_search.close()
            response = DiscoverResponse(status=0, payload=b"", error=str(exc), truncated=True)
            parsed = None
        return response, parsed

    @staticmethod
    def _new_legacy_result(index: str) -> JsonObject:
        return {
            "index": index,
            "total_hits": 0,
            "total_hits_relation": "exact",
            "shown_hits": 0,
            "truncated": False,
            "hits": [],
            "error": None,
            "error_detail": None,
            "retried": False,
            "retry_chunks": 0,
            "partial_error_details": [],
        }

    def _legacy_result(self, index: str) -> JsonObject:
        return self._legacy_by_index.setdefault(index, self._new_legacy_result(index))

    def _record_index_error(
        self,
        index: str,
        response: DiscoverResponse,
        parsed: Any,
        *,
        prefix: str = "search",
    ) -> None:
        legacy = self._legacy_result(index)
        detail = _error_detail(response, parsed)
        reason = str(detail.get("reason") or f"status={response.status}")
        legacy["error"] = f"{prefix}: {reason}"
        legacy["error_detail"] = detail
        partial_errors = legacy.get("partial_error_details")
        if isinstance(partial_errors, list):
            partial_errors.append(detail)
        legacy["total_hits_relation"] = "lower_bound"
        legacy["truncated"] = True

    def _record_pagination_recovery(
        self,
        index: str,
        response: DiscoverResponse,
        parsed: Any,
        *,
        operation: str,
        attempt: int,
    ) -> None:
        """Keep recovered context failures observable without making them terminal."""

        legacy = self._legacy_result(index)
        detail = dict(_error_detail(response, parsed))
        detail["operation"] = operation
        detail["recovery_attempt"] = attempt
        partial_errors = legacy.get("partial_error_details")
        if isinstance(partial_errors, list):
            partial_errors.append(detail)
        legacy["retried"] = True
        legacy["retry_chunks"] = int(legacy.get("retry_chunks") or 0) + 1

    def _clear_pit_fallback_error(self, index: str) -> None:
        """Clear a terminal PIT error after scroll/single-page fallback succeeds."""

        legacy = self._legacy_result(index)
        if str(legacy.get("error") or "").startswith(("PIT search:", "PIT reopen:")):
            legacy["error"] = None
            legacy["error_detail"] = None

    def _request_search_with_legacy_fallback(
        self,
        index: str,
        body: JsonObject,
        path: str,
        legacy_path: str,
        *,
        operation: str,
    ) -> tuple[DiscoverResponse, Any, JsonObject, str]:
        """Issue an initial search with bounded, error-driven ES 1.x fixes."""

        effective_body = dict(body)
        effective_path = path
        for attempt in range(1, MAX_LEGACY_SEARCH_ADJUSTMENTS + 2):
            response, parsed = self._request("POST", effective_path, body=effective_body)
            if response.status == 200 and isinstance(parsed, Mapping):
                return response, parsed, effective_body, effective_path
            if attempt > MAX_LEGACY_SEARCH_ADJUSTMENTS:
                return response, parsed, effective_body, effective_path
            adjustment = _legacy_search_adjustment(
                response,
                parsed,
                effective_body,
                effective_path,
                legacy_path,
            )
            if adjustment is None:
                return response, parsed, effective_body, effective_path
            self._record_pagination_recovery(
                index,
                response,
                parsed,
                operation=operation,
                attempt=attempt,
            )
            effective_body, effective_path, _changes = adjustment
        raise AssertionError("unreachable legacy search retry loop")

    def _set_surface_failure(
        self,
        name: str,
        response: DiscoverResponse,
        parsed: Any,
        *,
        attempted: int = 1,
    ) -> None:
        surface = self.coverage.surfaces.setdefault(name, SurfaceCoverage())
        surface.objects_attempted += attempted
        status = _surface_status(response)
        if surface.status == "complete" or status in {"denied", "timeout", "error"}:
            surface.status = status
        detail = _error_detail(response, parsed)
        surface.error = str(detail.get("reason") or response.error or f"status={response.status}")
        surface.error_detail = detail
        if status == "timeout":
            self.coverage.timed_out = True

    def _scan_configuration(
        self,
        name: str,
        payload: Any,
        *,
        object_name: str,
        source_kind: str,
        index: str | None = None,
        count_object: bool = True,
    ) -> None:
        surface = self.coverage.surfaces.setdefault(name, SurfaceCoverage())
        if count_object:
            surface.objects_attempted += 1
        scan = scan_value_tree(
            payload,
            source_kind=source_kind,
            object_name=object_name,
            index=index,
            options=self.options,
            deadline=self.budget.started_at + self.options.max_seconds,
        )
        for detection, location in scan.detections:
            try:
                self.accumulator.add(detection, location)
            except OSError:
                self.coverage.mark_truncated(f"{name}:storage_failure")
                surface.status = "partial"
                break
            if self.accumulator.limit_reached:
                self.budget.stop("max_findings")
                break
        self.coverage.suppressed_indicators += scan.suppressed_indicators
        for reason in scan.truncated_reasons:
            self.coverage.mark_truncated(f"{name}:{reason}")
            surface.status = "partial"
        if count_object:
            surface.objects_scanned += 1

    def _parse_resolve_inventory(self, parsed: Any) -> list[IndexInfo] | None:
        if not isinstance(parsed, Mapping):
            return None
        # Only explicit inventory arrays can establish an empty inventory.
        inventory_fields = {"indices", "aliases", "data_streams"}.intersection(parsed)
        if not inventory_fields or any(not isinstance(parsed[name], list) for name in inventory_fields):
            return None

        def valid_name(value: Any) -> bool:
            return isinstance(value, str) and bool(value.strip())

        # A partially malformed inventory cannot prove enumeration complete.
        # Optional metadata may be omitted, but present structural fields must
        # be usable before any entries are accepted as authoritative.
        for field_name in inventory_fields:
            for item in parsed[field_name]:
                if not isinstance(item, Mapping) or not valid_name(item.get("name")):
                    return None
                string_arrays: tuple[str, ...] = ("attributes", "aliases") if field_name == "indices" else ()
                if field_name == "aliases":
                    if "indices" not in item:
                        return None
                    string_arrays = ("indices",)
                for array_name in string_arrays:
                    if array_name in item:
                        values = item[array_name]
                        if not isinstance(values, list) or any(not valid_name(value) for value in values):
                            return None
                if field_name == "data_streams" and "backing_indices" in item:
                    backing_values = item["backing_indices"]
                    if not isinstance(backing_values, list):
                        return None
                    for backing_value in backing_values:
                        name = backing_value.get("name") if isinstance(backing_value, Mapping) else backing_value
                        if not valid_name(name):
                            return None
        inventory: dict[str, IndexInfo] = {}
        indices = parsed.get("indices")
        if isinstance(indices, list):
            for item in indices:
                if not isinstance(item, Mapping):
                    continue
                name = str(item.get("name") or "").strip()
                if not name:
                    continue
                attributes = item.get("attributes")
                attribute_values = (
                    {str(value).lower() for value in attributes} if isinstance(attributes, list) else set()
                )
                status = "closed" if "closed" in attribute_values else "open"
                aliases_raw = item.get("aliases")
                aliases = (
                    tuple(str(alias) for alias in aliases_raw if str(alias)) if isinstance(aliases_raw, list) else ()
                )
                data_stream = str(item.get("data_stream") or "") or None
                inventory[name] = IndexInfo(
                    name=name,
                    status=status,
                    aliases=aliases,
                    data_stream=data_stream,
                )
        alias_entries = parsed.get("aliases")
        if isinstance(alias_entries, list):
            for alias in alias_entries:
                alias_name = alias["name"]
                for name in alias["indices"]:
                    existing = inventory.get(name)
                    existing_aliases = existing.aliases if existing else ()
                    inventory[name] = IndexInfo(
                        name=name,
                        status=existing.status if existing else "open",
                        aliases=tuple(dict.fromkeys((*existing_aliases, alias_name))),
                        data_stream=existing.data_stream if existing else None,
                    )
        data_streams = parsed.get("data_streams")
        if isinstance(data_streams, list):
            for stream in data_streams:
                if not isinstance(stream, Mapping):
                    continue
                stream_name = str(stream.get("name") or "") or None
                backing = stream.get("backing_indices")
                added = False
                if isinstance(backing, list):
                    for raw_backing in backing:
                        if isinstance(raw_backing, Mapping):
                            name = str(raw_backing.get("name") or "")
                        else:
                            name = str(raw_backing)
                        if not name:
                            continue
                        added = True
                        existing = inventory.get(name)
                        inventory[name] = IndexInfo(
                            name=name,
                            status=existing.status if existing else "open",
                            aliases=existing.aliases if existing else (),
                            data_stream=stream_name,
                        )
                if not added and stream_name and stream_name not in inventory:
                    inventory[stream_name] = IndexInfo(name=stream_name, data_stream=stream_name)
        return sorted(inventory.values(), key=lambda item: item.name)

    def _parse_cat_inventory(self, parsed: Any) -> list[IndexInfo] | None:
        if not isinstance(parsed, list):
            return None
        inventory: dict[str, IndexInfo] = {}
        for item in parsed:
            if not isinstance(item, Mapping):
                continue
            name = str(item.get("index") or "").strip()
            if not name:
                continue
            status = str(item.get("status") or "open").strip().lower()
            inventory[name] = IndexInfo(
                name=name,
                status="closed" if status in {"close", "closed"} else "open",
            )
        return sorted(inventory.values(), key=lambda item: item.name)

    def _parse_mapping_inventory(self, parsed: Any) -> list[IndexInfo] | None:
        """Extract indices visible to the authenticated identity from mappings.

        Restricted OpenSearch roles commonly allow reading documents and index
        metadata while denying the cluster-level resolve and CAT APIs.  The
        mapping endpoint is index-scoped, so it can still enumerate precisely
        the indices that the supplied identity is allowed to discover.
        """

        if not isinstance(parsed, Mapping) or "error" in parsed:
            return None
        return sorted(
            (
                IndexInfo(name=str(name), status="open")
                for name, definition in parsed.items()
                if str(name).strip() and isinstance(definition, Mapping)
            ),
            key=lambda item: item.name,
        )

    def _inventory(self) -> tuple[list[IndexInfo], str | None, JsonObject | None]:
        surface = self.coverage.surfaces.setdefault("index_inventory", SurfaceCoverage())
        surface.objects_attempted += 1
        resolve_path = "/_resolve/index/*?expand_wildcards=all"
        response, parsed = self._request("GET", resolve_path)
        inventory = self._parse_resolve_inventory(parsed) if response.status == 200 else None
        if inventory is not None and not response.truncated:
            surface.objects_scanned += 1
            return inventory, None, None

        cat_response, cat_parsed = self._request("GET", "/_cat/indices?format=json&expand_wildcards=all&h=index,status")
        cat_inventory = self._parse_cat_inventory(cat_parsed) if cat_response.status == 200 else None
        if cat_inventory is not None and not cat_response.truncated:
            surface.objects_scanned += 1
            return cat_inventory, None, None

        # Elasticsearch 1.x predates ``expand_wildcards`` on this CAT API.
        # Retry only syntax/API incompatibility; authorization failures and
        # transport errors remain authoritative and are never hidden.
        if cat_response.status in {400, 404}:
            for legacy_path in (
                "/_cat/indices?format=json&h=index,status",
                "/_cat/indices?format=json",
            ):
                legacy_response, legacy_parsed = self._request("GET", legacy_path)
                legacy_inventory = self._parse_cat_inventory(legacy_parsed) if legacy_response.status == 200 else None
                if legacy_inventory is not None and not legacy_response.truncated:
                    surface.objects_scanned += 1
                    return legacy_inventory, None, None
                cat_response, cat_parsed = legacy_response, legacy_parsed
                if legacy_response.status not in {400, 404}:
                    break

        # OpenSearch security roles often deny both resolve and CAT despite
        # granting index-level read access. Mapping enumeration is read-only
        # and naturally filters the response to indices visible to the caller.
        mapping_response, mapping_parsed = self._request("GET", "/_mapping?filter_path=*.mappings")
        mapping_inventory = self._parse_mapping_inventory(mapping_parsed) if mapping_response.status == 200 else None
        if mapping_inventory is not None and not mapping_response.truncated:
            surface.objects_scanned += 1
            return mapping_inventory, None, None

        if response.truncated or cat_response.truncated or mapping_response.truncated:
            surface.status = "partial"
            self.coverage.mark_truncated("index_inventory:response_size_cap")
        failed_response = mapping_response
        failed_parsed = mapping_parsed
        for candidate_response, candidate_parsed in ((cat_response, cat_parsed), (response, parsed)):
            if candidate_response.status in {401, 403} or candidate_response.error:
                failed_response = candidate_response
                failed_parsed = candidate_parsed
                break
        self._set_surface_failure("index_inventory", failed_response, failed_parsed, attempted=0)
        detail = _error_detail(failed_response, failed_parsed)
        return [], str(detail.get("reason") or "failed to enumerate indices"), detail

    def _fetch_index_resource(
        self,
        indices: Sequence[str],
        *,
        suffix: str,
        surface_name: str,
        legacy_suffix: str | None = None,
    ) -> JsonObject:
        merged: JsonObject = {}
        surface = self.coverage.surfaces.setdefault(surface_name, SurfaceCoverage())
        requested = set(indices)
        scanned: set[str] = set()
        surface.objects_attempted += len(requested)
        use_legacy_suffix = False

        def fetch(batch: Sequence[str]) -> None:
            nonlocal use_legacy_suffix
            if not batch or self.budget.stopped:
                return
            selected_suffix = legacy_suffix if use_legacy_suffix and legacy_suffix else suffix
            path = f"/{_quote_indices(batch)}/{selected_suffix}"
            response, parsed = self._request("GET", path)
            if legacy_suffix and not use_legacy_suffix and response.status in {400, 404} and not response.error:
                legacy_path = f"/{_quote_indices(batch)}/{legacy_suffix}"
                legacy_response, legacy_parsed = self._request("GET", legacy_path)
                if legacy_response.status == 200 and isinstance(legacy_parsed, Mapping):
                    use_legacy_suffix = True
                response, parsed = legacy_response, legacy_parsed
            valid = response.status == 200 and isinstance(parsed, Mapping)
            if valid:
                for key, value in parsed.items():
                    merged[str(key)] = value
                returned = {str(key) for key in parsed if str(key) in set(batch)}
                if not response.truncated:
                    scanned.update(returned)
                    missing = [index for index in batch if index not in returned]
                    if not missing:
                        return
                    if len(missing) > 1:
                        midpoint = len(missing) // 2
                        fetch(missing[:midpoint])
                        fetch(missing[midpoint:])
                    else:
                        surface.status = "partial"
                        surface.error = f"response omitted index {missing[0]}"
                        surface.error_detail = {
                            "status": response.status,
                            "type": "incomplete_index_resource",
                            "reason": surface.error,
                            "root_cause": [],
                        }
                    return
            split_worthy = (
                response.truncated
                or response.status in {413, 414, 429, 500, 502, 503, 504}
                or (response.status == 200 and not isinstance(parsed, Mapping))
            )
            if split_worthy and len(batch) > 1:
                midpoint = len(batch) // 2
                fetch(batch[:midpoint])
                fetch(batch[midpoint:])
                return
            if valid and response.truncated:
                self.coverage.mark_truncated(f"{surface_name}:response_size_cap")
                surface.status = "partial"
                return
            if not valid:
                self._set_surface_failure(surface_name, response, parsed, attempted=0)

        batch_size = max(1, int(self.options.mapping_batch_size))
        for offset in range(0, len(indices), batch_size):
            fetch(indices[offset : offset + batch_size])
        surface.objects_scanned += len(scanned)
        if scanned != requested and scanned:
            surface.status = "partial"
        return merged

    def _scan_remote_surface(self, name: str, path: str) -> None:
        surface = self.coverage.surfaces.setdefault(name, SurfaceCoverage())
        response, parsed = self._request("GET", path)
        if (
            name == "ingest_pipelines"
            and self.vendor == "opensearch"
            and response.status == 404
            and not response.truncated
            and parsed == {}
        ):
            # OpenSearch 2.19 returns 404 with an empty object for the list
            # endpoint before any pipeline exists; after one is created the
            # same endpoint returns 200 and the named pipeline. Do not treat
            # this verified empty collection as an unreadable source.
            surface.objects_attempted += 1
            surface.objects_scanned += 1
            return
        if response.status != 200 or not isinstance(parsed, (Mapping, list)):
            self._set_surface_failure(name, response, parsed)
            return
        if response.truncated:
            surface.status = "partial"
            self.coverage.mark_truncated(f"{name}:response_size_cap")
        objects: list[tuple[str, Any]] = []
        if name in {"ingest_pipelines", "legacy_templates"} and isinstance(parsed, Mapping):
            objects = [(str(object_name), value) for object_name, value in parsed.items()]
        elif name == "node_settings" and isinstance(parsed, Mapping):
            nodes = parsed.get("nodes")
            if isinstance(nodes, Mapping):
                objects = [(str(node_id), value) for node_id, value in nodes.items()]
        elif name in {"index_templates", "component_templates"} and isinstance(parsed, Mapping):
            collection_name = name
            collection = parsed.get(collection_name)
            if isinstance(collection, list):
                for offset, item in enumerate(collection):
                    if not isinstance(item, Mapping):
                        continue
                    object_name = str(item.get("name") or f"{collection_name}/{offset}")
                    objects.append((object_name, item))
        if not objects:
            objects = [(path.split("?", 1)[0], parsed)]
        for object_name, value in objects:
            self._scan_configuration(
                name,
                value,
                object_name=object_name,
                source_kind=name,
            )

    @staticmethod
    def _total_hits(hits: Mapping[str, Any]) -> tuple[int, str]:
        total = hits.get("total")
        if isinstance(total, int):
            return total, "exact"
        if isinstance(total, Mapping):
            value = total.get("value")
            relation = str(total.get("relation") or "eq")
            return int(value) if isinstance(value, int) else 0, "lower_bound" if relation != "eq" else "exact"
        return 0, "unknown"

    def _process_hit(
        self,
        index: str,
        hit: Mapping[str, Any],
        *,
        candidate: bool,
        payload_complete: bool,
    ) -> None:
        document_index = str(hit.get("_index") or index)
        document_id = str(hit.get("_id") or "")
        source = hit.get("_source")
        fields = hit.get("fields")
        stored_fields = hit.get("stored_fields")
        if document_id:
            key = (document_index, document_id)
        else:
            stable = json.dumps(
                {"source": source, "fields": fields, "stored_fields": stored_fields},
                ensure_ascii=False,
                sort_keys=True,
                default=str,
            )
            key = (document_index, hashlib.sha256(stable.encode("utf-8")).hexdigest())

        if candidate and self._documents.add_candidate(key):
            self.coverage.query_candidates += 1
            legacy = self._legacy_result(index)
            legacy_hits = legacy.get("hits")
            if isinstance(legacy_hits, list) and len(legacy_hits) < self.options.page_size:
                legacy_hits.append(
                    {
                        "index": document_index,
                        "id": document_id,
                        "source": source if isinstance(source, (dict, list)) else {},
                    }
                )
        previous_completeness = self._documents.seen(key)
        if previous_completeness is True:
            self.coverage.duplicate_documents += 1
            return

        payloads: list[tuple[str, Any]] = []
        source_is_available = isinstance(source, (Mapping, list, str, int, float)) and not isinstance(source, bool)
        if source_is_available:
            payloads.append(("", source))
        if isinstance(fields, Mapping):
            payloads.append(("/fields", fields))
        if isinstance(stored_fields, Mapping):
            payloads.append(("/stored_fields", stored_fields))
        if not payloads:
            if previous_completeness is None:
                if not self.budget.consume_document(0, findings=len(self.accumulator)):
                    return
                self._documents.mark_seen(key, False)
            else:
                self.coverage.duplicate_documents += 1
            if self._documents.add_missing(key):
                self.coverage.missing_source_documents += 1
                self.coverage.mark_truncated(f"document:{document_index}:source_unavailable")
            return
        payload_hasher = hashlib.sha256()
        for part in stable_json_chunks(payloads):
            payload_hasher.update(part.encode("utf-8"))
        payload_fingerprint = payload_hasher.hexdigest()
        if self._documents.has_payload(key, payload_fingerprint):
            self.coverage.duplicate_documents += 1
            return
        source_bytes = sum(len(part.encode("utf-8")) for _path, value in payloads for part in stable_json_chunks(value))
        if previous_completeness is None:
            accepted = self.budget.consume_document(source_bytes, findings=len(self.accumulator))
        else:
            accepted = self.budget.consume_source_bytes(source_bytes, findings=len(self.accumulator))
        if not accepted:
            return
        self._documents.add_payload(key, payload_fingerprint)
        if payload_complete and not source_is_available and self._documents.add_missing(key):
            self.coverage.missing_source_documents += 1
            self.coverage.mark_truncated(f"document:{document_index}:source_unavailable")
        self._documents.mark_seen(key, bool(previous_completeness) or (payload_complete and source_is_available))
        self.coverage.documents_scanned = self.budget.documents
        self.coverage.source_bytes_scanned = self.budget.source_bytes
        object_name = f"{document_index}/{document_id or key[1]}"
        for base_path, value in payloads:
            scan = scan_value_tree(
                value,
                source_kind="document",
                object_name=object_name,
                index=document_index,
                document_id=document_id or None,
                path=base_path,
                options=self.options,
                deadline=self.budget.started_at + self.options.max_seconds,
            )
            for detection, location in scan.detections:
                try:
                    self.accumulator.add(detection, location)
                except OSError:
                    self.coverage.mark_truncated("document:storage_failure")
                    self._documents.mark_seen(key, False)
                    break
                if self.accumulator.limit_reached:
                    self.budget.stop("max_findings")
                    break
            self.coverage.suppressed_indicators += scan.suppressed_indicators
            for reason in scan.truncated_reasons:
                self.coverage.mark_truncated(f"document:{reason}")
            if self.budget.stopped:
                break

    def _consume_search_page(
        self,
        index: str,
        response: DiscoverResponse,
        parsed: Any,
        *,
        candidate: bool,
        payload_complete: bool,
    ) -> tuple[list[Mapping[str, Any]], list[Any] | None, str | None]:
        if response.status != 200 or not isinstance(parsed, Mapping):
            self._record_index_error(index, response, parsed)
            return [], None, None
        if response.truncated:
            self.coverage.mark_truncated(f"search:{index}:response_size_cap")
            self._legacy_result(index)["total_hits_relation"] = "lower_bound"
        if parsed.get("timed_out") is True:
            self.coverage.timed_out = True
            self.coverage.mark_truncated(f"search:{index}:timed_out")
        shards = parsed.get("_shards")
        if isinstance(shards, Mapping) and int(shards.get("failed") or 0) > 0:
            failures = shards.get("failures")
            if isinstance(failures, list):
                self.coverage.shard_failures.extend(
                    dict(failure) for failure in failures if isinstance(failure, Mapping)
                )
            else:
                self.coverage.shard_failures.append({"index": index, "failed": int(shards.get("failed") or 0)})
            self.coverage.mark_truncated(f"search:{index}:shard_failures")
        hits_container = parsed.get("hits")
        if not isinstance(hits_container, Mapping):
            self._record_index_error(
                index,
                DiscoverResponse(status=200, payload=response.payload, error="invalid search hits payload"),
                parsed,
            )
            return [], None, None
        _total, relation = self._total_hits(hits_container)
        if candidate and relation != "exact":
            self._legacy_result(index)["total_hits_relation"] = relation
        raw_hits = hits_container.get("hits")
        hits = [hit for hit in raw_hits if isinstance(hit, Mapping)] if isinstance(raw_hits, list) else []
        self.coverage.pages_scanned += 1
        stream = response.streamed_search
        try:
            for hit in hits:
                if self.budget.stopped:
                    break
                if stream is None:
                    self._process_hit(index, hit, candidate=candidate, payload_complete=payload_complete)
                    continue
                stream.deadline = self.budget.started_at + self.options.max_seconds
                source = stream.compact_source()
                mutable_hit = dict(hit)
                mutable_hit["_source"] = source
                document_index = str(mutable_hit.get("_index") or index)
                document_id = str(mutable_hit.get("_id") or "")
                self._process_hit(index, mutable_hit, candidate=candidate, payload_complete=False)
                object_name = f"{document_index}/{document_id}"

                def on_segment(
                    path: JSONPath,
                    segment: str,
                    object_name: str = object_name,
                    document_index: str = document_index,
                    document_id: str = document_id,
                ) -> None:
                    if not self.budget.check(findings=len(self.accumulator)):
                        return
                    pointer = json_discovery_path(path[4:], "", style="pointer")
                    location = FindingLocation(
                        source_kind="document",
                        object=object_name,
                        index=document_index,
                        id=document_id or None,
                        path=pointer or "/",
                    )
                    for detection in analyze_value(
                        segment,
                        path="",
                        field_classification=classify_field(""),
                        allow_base64=False,
                    ):
                        if detection.available:
                            self.accumulator.add(detection, location)
                        else:
                            self.coverage.suppressed_indicators += 1

                def on_scalar(
                    path: JSONPath,
                    value: DiskBackedText,
                    object_name: str = object_name,
                    document_index: str = document_index,
                    document_id: str = document_id,
                    source: Any = source,
                ) -> bool:
                    if not self.budget.check(findings=len(self.accumulator)):
                        return False
                    relative = path[4:]
                    field_name = ".".join(
                        _disk_field_hint(component, self.budget.started_at + self.options.max_seconds)
                        if isinstance(component, DiskBackedText)
                        else str(component)
                        for component in relative
                    )
                    parent = source
                    for component in relative[:-1]:
                        try:
                            parent = parent[component]
                        except (KeyError, IndexError, TypeError):
                            parent = None
                            break
                    if relative and relative[-1] == "value" and isinstance(parent, Mapping):
                        semantic = next(
                            (
                                parent[key]
                                for key in ("field", "target_field", "name", "key", "kind", "type")
                                if parent.get(key)
                            ),
                            None,
                        )
                        if isinstance(semantic, str):
                            field_name = semantic
                    pointer = json_discovery_path(relative, "", style="pointer")
                    location = FindingLocation(
                        source_kind="document",
                        object=object_name,
                        index=document_index,
                        id=document_id or None,
                        path=pointer or "/",
                    )
                    try:
                        detections, complete = _analyze_disk_value(
                            value, path=field_name, deadline=self.budget.started_at + self.options.max_seconds
                        )
                    except TimeoutError:
                        self.budget.stop("max_seconds")
                        return False
                    retained = False
                    for detection in detections:
                        retained |= detection.value is value
                        self.accumulator.add(detection, location)
                        if self.accumulator.limit_reached:
                            self.budget.stop("max_findings")
                            complete = False
                            break
                    if not retained:
                        value.close()
                    return complete

                scanned_complete = stream.scan_large_fields(on_segment, on_scalar=on_scalar)
                complete = scanned_complete and not response.truncated
                if hit.get("_stream_extra_fields"):
                    complete = False
                if any(
                    classify_field(
                        ".".join(
                            _disk_field_hint(component, self.budget.started_at + self.options.max_seconds)
                            if isinstance(component, DiskBackedText)
                            else str(component)
                            for component in path[4:]
                        )
                    )
                    in {"strong", "medium"}
                    or path[-1] == "value"
                    for path in stream.large_paths - stream.resolved_paths
                ):
                    complete = False
                compact_bytes = sum(len(part.encode("utf-8")) for part in stable_json_chunks(source))
                additional_bytes = max(0, stream.source_bytes - compact_bytes)
                if additional_bytes:
                    complete = (
                        self.budget.consume_source_bytes(additional_bytes, findings=len(self.accumulator)) and complete
                    )
                self.coverage.source_bytes_scanned = self.budget.source_bytes
                if complete and document_id and not self.budget.stopped:
                    self._documents.mark_seen((document_index, document_id), True)
                else:
                    self.coverage.mark_truncated(f"document:{document_index}:streamed_scalar_unverified")
        except (ValueError, OSError) as exc:
            self.coverage.mark_truncated(f"search:{index}:stream_error")
            self._legacy_result(index)["error_detail"] = str(exc)
        finally:
            if stream is not None:
                stream.close()
        last_sort: list[Any] | None = None
        if hits:
            raw_sort = hits[-1].get("sort")
            if isinstance(raw_sort, list):
                last_sort = list(raw_sort)
        pit_id_raw = parsed.get("pit_id") or parsed.get("id")
        pit_id = str(pit_id_raw) if isinstance(pit_id_raw, str) and pit_id_raw else None
        return hits, last_sort, pit_id

    def _open_pit(self, index: str) -> tuple[str | None, DiscoverResponse, Any]:
        quoted = urllib.parse.quote(index, safe="")
        keep_alive = urllib.parse.quote(self.options.pit_keep_alive, safe="")
        if self.vendor == "opensearch":
            path = f"/{quoted}/_search/point_in_time?keep_alive={keep_alive}&allow_partial_pit_creation=false"
        else:
            path = f"/{quoted}/_pit?keep_alive={keep_alive}"
        response, parsed = self._request("POST", path)
        pit_id: str | None = None
        if response.status in {200, 201} and isinstance(parsed, Mapping):
            raw_id = parsed.get("id") or parsed.get("pit_id")
            if isinstance(raw_id, str) and raw_id:
                pit_id = raw_id
        return pit_id, response, parsed

    def _close_pit(self, pit_id: str) -> None:
        if self.vendor == "opensearch":
            body: JsonObject = {"pit_id": [pit_id]}
            path = "/_search/point_in_time"
        else:
            body = {"id": pit_id}
            path = "/_pit"
        self._request("DELETE", path, body=body, cleanup=True)

    def _paginate_pit(
        self,
        index: str,
        query: JsonObject,
        *,
        candidate: bool,
        pit_id: str,
        payload_complete: bool,
    ) -> bool:
        current_pit = pit_id
        search_after: list[Any] | None = None
        previous_sort: list[Any] | None = None
        successful_pages = 0
        context_recoveries = 0
        page_size = self.options.page_size
        pending_truncated: tuple[DiscoverResponse, Any] | None = None
        try:
            while not self.budget.stopped:
                body = dict(query)
                body["size"] = page_size
                body["sort"] = [{"_shard_doc": "asc"}]
                body["pit"] = {"id": current_pit, "keep_alive": self.options.pit_keep_alive}
                if search_after is not None:
                    body["search_after"] = search_after
                    body["track_total_hits"] = False
                response, parsed = self._request("POST", "/_search", body=body)
                if (response.truncated or _closed_search_page(response)) and page_size > 1:
                    # A large page is not evidence that any single document is
                    # unreadable. Retry the same cursor with fewer hits.
                    hits_container = parsed.get("hits") if isinstance(parsed, Mapping) else None
                    if (
                        pending_truncated is None
                        and response.status == 200
                        and isinstance(hits_container, Mapping)
                        and isinstance(hits_container.get("hits"), list)
                        and hits_container["hits"]
                    ):
                        pending_truncated = (response, parsed)
                    page_size = max(1, page_size // 2)
                    continue
                if response.status != 200 or not isinstance(parsed, Mapping):
                    if pending_truncated is not None:
                        self._consume_search_page(
                            index,
                            *pending_truncated,
                            candidate=candidate,
                            payload_complete=False,
                        )
                        pending_truncated = None
                    if response.truncated:
                        self.coverage.mark_truncated(f"search:{index}:response_size_cap")
                    if (
                        _is_missing_search_context(response, parsed)
                        and context_recoveries < MAX_PAGINATION_CONTEXT_RECOVERIES
                    ):
                        context_recoveries += 1
                        self._record_pagination_recovery(
                            index,
                            response,
                            parsed,
                            operation="pit",
                            attempt=context_recoveries,
                        )
                        expired_pit = current_pit
                        current_pit = ""
                        self._close_pit(expired_pit)
                        reopened_pit, reopen_response, reopen_parsed = self._open_pit(index)
                        if not reopened_pit:
                            self._record_pagination_recovery(
                                index,
                                reopen_response,
                                reopen_parsed,
                                operation="pit_reopen",
                                attempt=context_recoveries,
                            )
                            return False
                        current_pit = reopened_pit
                        # ``_shard_doc`` sort values belong to the old PIT.  A
                        # restart from page one is the only safe continuation;
                        # document/finding deduplication keeps it exact-once.
                        search_after = None
                        previous_sort = None
                        successful_pages = 0
                        continue
                    if successful_pages or _is_missing_search_context(response, parsed):
                        self._record_index_error(index, response, parsed, prefix="PIT search")
                    return False
                successful_pages += 1
                hits, last_sort, returned_pit = self._consume_search_page(
                    index,
                    response,
                    parsed,
                    candidate=candidate,
                    payload_complete=payload_complete,
                )
                if returned_pit:
                    current_pit = returned_pit
                if not hits:
                    if pending_truncated is not None:
                        self._consume_search_page(
                            index,
                            *pending_truncated,
                            candidate=candidate,
                            payload_complete=False,
                        )
                    return True
                pending_truncated = None
                if last_sort is None or last_sort == previous_sort:
                    self.coverage.mark_truncated(f"search:{index}:unstable_search_after")
                    return True
                previous_sort = last_sort
                search_after = last_sort
            return True
        finally:
            if current_pit:
                self._close_pit(current_pit)

    def _clear_scroll(self, scroll_id: str) -> None:
        self._request(
            "DELETE",
            "/_search/scroll",
            body={"scroll_id": [scroll_id]},
            cleanup=True,
        )

    def _paginate_scroll(
        self,
        index: str,
        query: JsonObject,
        *,
        candidate: bool,
        payload_complete: bool,
    ) -> bool:
        quoted = urllib.parse.quote(index, safe="")
        keep_alive = urllib.parse.quote(self.options.pit_keep_alive, safe="")
        body = dict(query)
        page_size = self.options.page_size
        body["size"] = page_size
        body["sort"] = ["_doc"]
        search_path = f"/{quoted}/_search?scroll={keep_alive}&expand_wildcards=open"
        legacy_search_path = f"/{quoted}/_search?scroll={keep_alive}"
        scroll_id = ""
        context_recoveries = 0
        started = False
        pending_truncated: tuple[DiscoverResponse, Any] | None = None
        try:
            while not self.budget.stopped:
                response, parsed, body, search_path = self._request_search_with_legacy_fallback(
                    index,
                    body,
                    search_path,
                    legacy_search_path,
                    operation="legacy_scroll_search",
                )
                if (response.truncated or _closed_search_page(response)) and page_size > 1:
                    hits_container = parsed.get("hits") if isinstance(parsed, Mapping) else None
                    if (
                        pending_truncated is None
                        and response.status == 200
                        and isinstance(hits_container, Mapping)
                        and isinstance(hits_container.get("hits"), list)
                        and hits_container["hits"]
                    ):
                        pending_truncated = (response, parsed)
                    page_size = max(1, page_size // 2)
                    body["size"] = page_size
                    continue
                if response.status != 200 or not isinstance(parsed, Mapping):
                    if pending_truncated is not None:
                        self._consume_search_page(
                            index, *pending_truncated, candidate=candidate, payload_complete=False
                        )
                        pending_truncated = None
                    if response.truncated:
                        self.coverage.mark_truncated(f"search:{index}:response_size_cap")
                    if started:
                        self._record_index_error(index, response, parsed, prefix="scroll restart")
                        return True
                    return False
                started = True
                scroll_id_raw = parsed.get("_scroll_id")
                scroll_id = str(scroll_id_raw) if isinstance(scroll_id_raw, str) and scroll_id_raw else ""
                hits, _last_sort, _pit = self._consume_search_page(
                    index,
                    response,
                    parsed,
                    candidate=candidate,
                    payload_complete=payload_complete,
                )
                if not hits and pending_truncated is not None:
                    self._consume_search_page(index, *pending_truncated, candidate=candidate, payload_complete=False)
                    pending_truncated = None
                elif hits:
                    pending_truncated = None
                if hits and not scroll_id:
                    self.coverage.mark_truncated(f"search:{index}:scroll_id_missing")
                    self._legacy_result(index)["total_hits_relation"] = "lower_bound"
                    self._legacy_result(index)["truncated"] = True
                    return True

                restart = False
                while hits and scroll_id and not self.budget.stopped:
                    response, parsed = self._request(
                        "POST",
                        "/_search/scroll",
                        body={"scroll": self.options.pit_keep_alive, "scroll_id": scroll_id},
                        stream_search=page_size == 1,
                    )
                    if (response.truncated or _closed_search_page(response)) and page_size > 1:
                        hits_container = parsed.get("hits") if isinstance(parsed, Mapping) else None
                        if (
                            pending_truncated is None
                            and response.status == 200
                            and isinstance(hits_container, Mapping)
                            and isinstance(hits_container.get("hits"), list)
                            and hits_container["hits"]
                        ):
                            pending_truncated = (response, parsed)
                        page_size = max(1, page_size // 2)
                        self._clear_scroll(scroll_id)
                        scroll_id = ""
                        body = dict(query)
                        body["size"] = page_size
                        body["sort"] = ["_doc"]
                        started = False
                        restart = True
                        break
                    if response.status != 200 or not isinstance(parsed, Mapping):
                        if pending_truncated is not None:
                            self._consume_search_page(
                                index, *pending_truncated, candidate=candidate, payload_complete=False
                            )
                            pending_truncated = None
                        if response.truncated:
                            self.coverage.mark_truncated(f"search:{index}:response_size_cap")
                        if (
                            _is_missing_search_context(response, parsed)
                            and context_recoveries < MAX_PAGINATION_CONTEXT_RECOVERIES
                        ):
                            context_recoveries += 1
                            self._record_pagination_recovery(
                                index,
                                response,
                                parsed,
                                operation="scroll",
                                attempt=context_recoveries,
                            )
                            expired_scroll = scroll_id
                            scroll_id = ""
                            self._clear_scroll(expired_scroll)
                            restart = True
                            break
                        self._record_index_error(index, response, parsed, prefix="scroll")
                        return True
                    new_scroll_id = parsed.get("_scroll_id")
                    if isinstance(new_scroll_id, str) and new_scroll_id:
                        scroll_id = new_scroll_id
                    hits, _last_sort, _pit = self._consume_search_page(
                        index,
                        response,
                        parsed,
                        candidate=candidate,
                        payload_complete=payload_complete,
                    )
                    if not hits and pending_truncated is not None:
                        self._consume_search_page(
                            index, *pending_truncated, candidate=candidate, payload_complete=False
                        )
                        pending_truncated = None
                    elif hits:
                        pending_truncated = None
                if restart:
                    continue
                if not self.budget.stopped:
                    self._clear_pit_fallback_error(index)
                return True
            return True
        finally:
            if scroll_id:
                self._clear_scroll(scroll_id)

    def _single_page(
        self,
        index: str,
        query: JsonObject,
        *,
        candidate: bool,
        payload_complete: bool,
    ) -> None:
        quoted = urllib.parse.quote(index, safe="")
        body = dict(query)
        body["size"] = self.options.page_size
        body.pop("sort", None)
        pending_truncated: tuple[DiscoverResponse, Any] | None = None
        while True:
            response, parsed, body, _effective_path = self._request_search_with_legacy_fallback(
                index,
                body,
                f"/{quoted}/_search?expand_wildcards=open",
                f"/{quoted}/_search",
                operation="legacy_single_page_search",
            )
            if not (response.truncated or _closed_search_page(response)) or int(body.get("size") or 1) <= 1:
                break
            hits_container = parsed.get("hits") if isinstance(parsed, Mapping) else None
            if (
                pending_truncated is None
                and response.status == 200
                and isinstance(hits_container, Mapping)
                and isinstance(hits_container.get("hits"), list)
                and hits_container["hits"]
            ):
                pending_truncated = (response, parsed)
            body["size"] = max(1, int(body["size"]) // 2)
        hits, _sort, _pit = self._consume_search_page(
            index,
            response,
            parsed,
            candidate=candidate,
            payload_complete=payload_complete,
        )
        if not hits and pending_truncated is not None:
            self._consume_search_page(index, *pending_truncated, candidate=candidate, payload_complete=False)
        hits_container = parsed.get("hits") if isinstance(parsed, Mapping) else None
        valid_hits_payload = isinstance(hits_container, Mapping) and isinstance(hits_container.get("hits"), list)
        if response.status == 200 and valid_hits_payload:
            self._clear_pit_fallback_error(index)
            self.coverage.mark_truncated(f"search:{index}:pagination_unavailable")

    def _search_query(self, index: str, query: JsonObject, *, candidate: bool) -> None:
        if self.budget.stopped:
            return
        source_spec = query.get("_source", True)
        payload_complete = source_spec is True
        pit_id, _pit_response, _pit_parsed = self._open_pit(index)
        if pit_id and self._paginate_pit(
            index,
            query,
            candidate=candidate,
            pit_id=pit_id,
            payload_complete=payload_complete,
        ):
            return
        if self._paginate_scroll(
            index,
            query,
            candidate=candidate,
            payload_complete=payload_complete,
        ):
            return
        self._single_page(
            index,
            query,
            candidate=candidate,
            payload_complete=payload_complete,
        )

    def _scan_index(self, index: str, fields: Sequence[MappedField]) -> None:
        legacy = self._legacy_result(index)
        sensitive = [item for item in fields if item.classification in {"strong", "medium"} and item.kind == "field"]
        for offset in range(0, len(sensitive), MAX_QUERY_CLAUSES):
            self._search_query(
                index,
                build_targeted_query(
                    sensitive[offset : offset + MAX_QUERY_CLAUSES],
                    size=self.options.page_size,
                ),
                candidate=True,
            )
            if self.budget.stopped:
                break
        if not self.budget.stopped:
            blobs = [item for item in fields if item.field_type in _BLOB_TYPES and item.indexed]
            for signature in build_signature_queries(blobs, size=self.options.page_size):
                query = signature.get("query")
                if isinstance(query, Mapping) and "match_none" not in query:
                    self._search_query(index, signature, candidate=True)
                if self.budget.stopped:
                    break
        if not self.budget.stopped:
            concrete_fields = [
                item
                for item in fields
                if item.kind == "field" and item.indexed and item.field_type not in {"object", "nested"}
            ]
            doc_value_paths = list(dict.fromkeys(item.path for item in concrete_fields if item.doc_values))[:128]
            stored_paths = list(dict.fromkeys(item.path for item in concrete_fields if item.stored))[:128]
            sweep_body: JsonObject = {
                "size": self.options.page_size,
                "track_total_hits": True,
                "query": {"match_all": {}},
                "sort": [{"_shard_doc": "asc"}],
                "_source": True,
            }
            if doc_value_paths:
                sweep_body["fields"] = doc_value_paths
            if stored_paths:
                sweep_body["stored_fields"] = stored_paths
            self._search_query(
                index,
                sweep_body,
                candidate=False,
            )
        candidate_count = self._documents.candidate_count(index)
        legacy["total_hits"] = candidate_count
        hits = legacy.get("hits")
        shown = len(hits) if isinstance(hits, list) else 0
        legacy["shown_hits"] = shown
        relation = str(legacy.get("total_hits_relation") or "exact")
        legacy["truncated"] = bool(legacy.get("truncated")) or candidate_count > shown or relation != "exact"

    def _finalize(self) -> DiscoverReport:
        for reason in self.budget.reasons:
            self.coverage.mark_truncated(reason)
        if "max_seconds" in self.budget.reasons:
            self.coverage.timed_out = True
        if self.accumulator.limit_reached:
            self.coverage.mark_truncated("max_findings")
        self.coverage.locations_dropped = self.accumulator.locations_dropped
        if self.accumulator.locations_dropped:
            self.coverage.mark_truncated("max_locations")
        self.coverage.documents_scanned = self.budget.documents
        self.coverage.source_bytes_scanned = self.budget.source_bytes
        self.coverage.elapsed_ms = max(0, int((self.monotonic() - self.budget.started_at) * 1000))
        return DiscoverReport(
            findings=self.accumulator.findings(),
            coverage=self.coverage,
            legacy_results=[self._legacy_by_index[name] for name in sorted(self._legacy_by_index)],
        )

    def run(self) -> DiscoverReport:
        """Run all independent read-only surfaces and return a serializable report."""

        inventory, inventory_error, inventory_detail = self._inventory()
        self.coverage.indices_enumerated = len(inventory)
        open_indices = [item.name for item in inventory if item.status != "closed"]
        self.coverage.indices_closed = len(inventory) - len(open_indices)

        mappings: JsonObject = {}
        settings: JsonObject = {}
        if open_indices and not self.budget.stopped:
            mappings = self._fetch_index_resource(
                open_indices,
                suffix="_mapping?expand_wildcards=open,hidden",
                surface_name="mappings",
                legacy_suffix="_mapping",
            )
            settings = self._fetch_index_resource(
                open_indices,
                suffix="_settings?expand_wildcards=open,hidden&flat_settings=false&include_defaults=false",
                surface_name="index_settings",
                legacy_suffix="_settings",
            )

        mapping_configuration = _extract_mapping_configuration(mappings)
        if mapping_configuration:
            self._scan_configuration(
                "mapping_configuration",
                mapping_configuration,
                object_name="_mapping",
                source_kind="mapping_configuration",
            )
        else:
            self.coverage.surfaces.setdefault("mapping_configuration", SurfaceCoverage())
        for index in open_indices:
            source_disabled, source_filtered = _mapping_source_policy(mappings, index)
            if source_disabled:
                self.coverage.source_disabled_indices.append(index)
                self.coverage.mark_truncated(f"document:{index}:source_disabled")
            if source_filtered:
                self.coverage.source_filtered_indices.append(index)
                self.coverage.mark_truncated(f"document:{index}:source_filtered")
        for index, value in settings.items():
            self._scan_configuration(
                "index_settings",
                value,
                object_name=f"{index}/_settings",
                source_kind="index_settings",
                index=index,
                count_object=False,
            )

        for name, path in (
            ("cluster_settings", "/_cluster/settings?flat_settings=false&include_defaults=false"),
            ("node_settings", "/_nodes/settings?flat_settings=false"),
            ("index_templates", "/_index_template"),
            ("component_templates", "/_component_template"),
            ("legacy_templates", "/_template"),
            ("ingest_pipelines", "/_ingest/pipeline"),
        ):
            if self.budget.stopped:
                break
            self._scan_remote_surface(name, path)

        mapped_fields = extract_mapping_fields(mappings)
        fields_by_index: dict[str, list[MappedField]] = {index: [] for index in open_indices}
        for mapped_field in mapped_fields:
            if mapped_field.index in fields_by_index:
                fields_by_index[mapped_field.index].append(mapped_field)

        index_items = [(index, tuple(fields_by_index.get(index, []))) for index in open_indices]
        if self.nested_scheduler is None:
            completed_indices = ((item, self._scan_index_isolated(item)) for item in index_items)
        else:
            completed_indices = self.nested_scheduler.iter_completed(
                index_items,
                self._scan_index_isolated,
                key=self.scheduler_key,
                per_key_limit=DISCOVER_WORKERS,
            )
        indexed_results: dict[str, tuple[JsonObject, DiscoverCoverage, bool]] = {}
        for _item, (index, legacy, index_coverage, scanned, attempted) in completed_indices:
            if attempted:
                indexed_results[index] = (legacy, index_coverage, scanned)

        for index in open_indices:
            outcome = indexed_results.get(index)
            if outcome is None:
                continue
            legacy, index_coverage, scanned = outcome
            self._legacy_by_index[index] = legacy
            self._merge_index_coverage(self.coverage, index_coverage)
            if legacy.get("error"):
                detail = legacy.get("error_detail")
                status = int(detail.get("status") or 0) if isinstance(detail, Mapping) else 0
                if status in {401, 403}:
                    self.coverage.indices_denied += 1
                else:
                    self.coverage.indices_failed += 1
            elif scanned:
                self.coverage.indices_scanned += 1

        report = self._finalize()
        scanned_non_inventory_surface = any(
            name != "index_inventory" and surface.objects_scanned > 0
            for name, surface in self.coverage.surfaces.items()
        )
        if inventory_error and not scanned_non_inventory_surface and not report.findings:
            report.error = inventory_error
            report.error_detail = inventory_detail
        return report


def run_discovery(
    request: RequestFn,
    *,
    vendor: str = "compatible",
    options: DiscoverOptions | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    started_at: float | None = None,
    nested_scheduler: Any | None = None,
    scheduler_key: Any | None = None,
    on_finding: Callable[[Finding], None] | None = None,
) -> DiscoverReport:
    """Convenience entry point used by the Elastic stage."""

    return DiscoverEngine(
        request,
        vendor=vendor,
        options=options,
        monotonic=monotonic,
        started_at=started_at,
        nested_scheduler=nested_scheduler,
        scheduler_key=scheduler_key,
        on_finding=on_finding,
    ).run()


__all__ = [
    "DEFAULT_MAX_DOCUMENTS",
    "DEFAULT_MAX_FINDINGS",
    "DEFAULT_MAX_SECONDS",
    "DEFAULT_MAX_SOURCE_BYTES",
    "DEFAULT_PAGE_SIZE",
    "DISCOVER_WORKERS",
    "DiscoverCoverage",
    "DiscoverEngine",
    "DiscoverOptions",
    "DiscoverReport",
    "DiscoverRequest",
    "DiscoverResponse",
    "DetectedSecret",
    "DiscoveryBudget",
    "Finding",
    "FindingAccumulator",
    "FindingLocation",
    "MappedField",
    "RequestFn",
    "ScanResult",
    "SurfaceCoverage",
    "analyze_value",
    "build_signature_queries",
    "build_signature_query",
    "build_targeted_query",
    "classify_field",
    "extract_mapping_fields",
    "normalize_field_name",
    "run_discovery",
    "scan_value_tree",
]
