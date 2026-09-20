"""Offline, version-only CVE enumeration for confirmed audit services.

The runtime deliberately performs no network I/O here.  The bundled catalog is
reviewed and shipped with Redposture so a scan never discloses product/version
fingerprints to a third-party vulnerability service.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import date
from functools import lru_cache
from importlib.resources import files
from typing import Any


class CveCatalogError(ValueError):
    """The bundled CVE catalog is missing or violates its schema."""


@dataclass(frozen=True)
class DetectedProduct:
    product_key: str
    name: str
    version: str | None
    confidence: str = "confirmed"

    def to_dict(self) -> dict[str, Any]:
        normalized = normalized_version_text(self.version, product_key=self.product_key)
        return {
            "product_key": self.product_key,
            "name": self.name,
            "version": self.version,
            "normalized_version": normalized,
            "confidence": self.confidence,
        }


ProductResolver = Callable[[Mapping[str, Any]], list[DetectedProduct]]


@dataclass(frozen=True)
class CveCatalog:
    version: str
    entries: tuple[dict[str, Any], ...]


_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_VECTOR_REQUIRED = ("AV:N", "UI:N")
_ALLOWED_PRIVILEGES_REQUIRED = {"N", "L"}
_ALLOWED_IMPACTS = {
    "rce",
    "command_execution",
    "auth_bypass",
    "account_takeover",
    "file_read",
    "file_write",
    "ssrf",
}
_VERSION_TOKEN_RE = re.compile(r"^(?:v)?(\d+(?:[._]\d+){1,5})(.*)$", re.IGNORECASE)
_MINIO_RELEASE_RE = re.compile(
    r"(?:RELEASE[.-])?(\d{4})[-_.](\d{2})[-_.](\d{2})(?:T(\d{2})[-_.](\d{2})[-_.](\d{2})Z?)?", re.I
)
_PRERELEASE_RE = re.compile(r"^[-_.]?(dev|alpha|a|beta|b|rc|pre|preview)(?:[-_.]?(\d+))?", re.IGNORECASE)
_ORACLE_RELEASE_RE = re.compile(r"^(?:v)?(\d{2})c$", re.IGNORECASE)
_IGNORED_VERSION_SUFFIX_RE = re.compile(
    r"^(?:\+[0-9A-Za-z.-]+|-(?:ce|ee)(?:\.[0-9A-Za-z.-]+)?|\s+.*|\s*\(.*\))$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class _ParsedVersion:
    numbers: tuple[int, ...]
    prerelease: tuple[int, int] | None = None


def _catalog_path() -> Any:
    return files("redposture_core").joinpath("data/cve_catalog.json")


def _nonempty_text(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise CveCatalogError(f"CVE catalog field {field!r} must be non-empty")
    return text


def _validate_range(item: Any, cve_id: str) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise CveCatalogError(f"{cve_id}: affected range must be an object")
    if not any(item.get(key) is not None for key in ("introduced", "fixed", "last_affected")):
        raise CveCatalogError(f"{cve_id}: affected range has no boundary")
    scheme = str(item.get("scheme") or "numeric").strip().lower()
    if scheme not in {"numeric", "minio_release", "oracle"}:
        raise CveCatalogError(f"{cve_id}: unsupported version scheme {scheme!r}")
    if item.get("fixed") is not None and item.get("last_affected") is not None:
        raise CveCatalogError(f"{cve_id}: affected range cannot contain both fixed and last_affected")
    parsed: dict[str, _ParsedVersion] = {}
    for boundary in ("introduced", "fixed", "last_affected"):
        raw = item.get(boundary)
        if raw is None:
            continue
        value = _parse_version(str(raw), scheme)
        if value is None:
            raise CveCatalogError(f"{cve_id}: invalid {boundary} version {raw!r}")
        parsed[boundary] = value
    if "introduced" in parsed and "fixed" in parsed and _compare_versions(parsed["introduced"], parsed["fixed"]) >= 0:
        raise CveCatalogError(f"{cve_id}: introduced version must be lower than fixed version")
    if (
        "introduced" in parsed
        and "last_affected" in parsed
        and _compare_versions(parsed["introduced"], parsed["last_affected"]) > 0
    ):
        raise CveCatalogError(f"{cve_id}: introduced version must not exceed last_affected")
    normalized = dict(item)
    normalized["scheme"] = scheme
    return normalized


def _affected_ranges_overlap(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    """Return whether two inclusive-lower ranges share at least one version."""
    left_scheme = str(left.get("scheme") or "numeric")
    right_scheme = str(right.get("scheme") or "numeric")
    if left_scheme != right_scheme:
        return False

    def boundary(item: Mapping[str, Any], name: str) -> _ParsedVersion | None:
        raw = item.get(name)
        return _parse_version(str(raw), left_scheme) if raw is not None else None

    left_lower = boundary(left, "introduced")
    right_lower = boundary(right, "introduced")
    lower = left_lower
    if lower is None or (right_lower is not None and _compare_versions(right_lower, lower) > 0):
        lower = right_lower

    left_upper_name = "fixed" if left.get("fixed") is not None else "last_affected"
    right_upper_name = "fixed" if right.get("fixed") is not None else "last_affected"
    left_upper = boundary(left, left_upper_name)
    right_upper = boundary(right, right_upper_name)
    upper = left_upper
    upper_exclusive = left_upper_name == "fixed"
    if upper is None or (right_upper is not None and _compare_versions(right_upper, upper) < 0):
        upper = right_upper
        upper_exclusive = right_upper_name == "fixed"
    elif right_upper is not None and _compare_versions(right_upper, upper) == 0:
        upper_exclusive = upper_exclusive or right_upper_name == "fixed"

    if lower is None or upper is None:
        return True
    comparison = _compare_versions(lower, upper)
    return comparison < 0 or (comparison == 0 and not upper_exclusive)


def _validate_entry(raw: Any, seen: set[tuple[str, str]]) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise CveCatalogError("CVE catalog entry must be an object")
    cve_id = _nonempty_text(raw.get("id"), "id").upper()
    product = _nonempty_text(raw.get("product"), "product")
    if not _CVE_RE.fullmatch(cve_id):
        raise CveCatalogError(f"invalid CVE identifier: {cve_id}")
    key = (cve_id, product)
    if key in seen:
        raise CveCatalogError(f"duplicate CVE/product entry: {cve_id}/{product}")
    seen.add(key)
    severity = _nonempty_text(raw.get("severity"), "severity").upper()
    score = raw.get("score")
    if severity not in {"HIGH", "CRITICAL"} or not isinstance(score, (int, float)) or float(score) < 7.0:
        raise CveCatalogError(f"{cve_id}: only High/Critical scores are allowed")
    if (severity == "HIGH" and float(score) >= 9.0) or (severity == "CRITICAL" and float(score) < 9.0):
        raise CveCatalogError(f"{cve_id}: severity does not match the CVSS score")
    vector = _nonempty_text(raw.get("vector"), "vector").upper()
    if not vector.startswith(("CVSS:4.0/", "CVSS:3.1/", "CVSS:3.0/")):
        raise CveCatalogError(f"{cve_id}: unsupported CVSS vector version")
    vector_parts = vector.split("/")
    if not all(metric in vector_parts for metric in _VECTOR_REQUIRED):
        raise CveCatalogError(f"{cve_id}: vector must contain AV:N and UI:N")
    privilege_metrics = [part for part in vector_parts if part.startswith("PR:")]
    if len(privilege_metrics) != 1 or privilege_metrics[0].removeprefix("PR:") not in _ALLOWED_PRIVILEGES_REQUIRED:
        raise CveCatalogError(f"{cve_id}: vector must contain exactly one of PR:N or PR:L")
    impact = _nonempty_text(raw.get("impact"), "impact").lower()
    if impact not in _ALLOWED_IMPACTS:
        raise CveCatalogError(f"{cve_id}: unsupported impact {impact!r}")
    ranges = raw.get("affected")
    if not isinstance(ranges, list) or not ranges:
        raise CveCatalogError(f"{cve_id}: at least one affected range is required")
    references = raw.get("references")
    if (
        not isinstance(references, list)
        or not references
        or not all(str(ref).startswith("https://") for ref in references)
    ):
        raise CveCatalogError(f"{cve_id}: HTTPS references are required")
    validated_ranges = [_validate_range(item, cve_id) for item in ranges]
    range_keys = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in validated_ranges]
    if len(range_keys) != len(set(range_keys)):
        raise CveCatalogError(f"{cve_id}: duplicate affected range")
    for index, left in enumerate(validated_ranges):
        for right in validated_ranges[index + 1 :]:
            if _affected_ranges_overlap(left, right):
                raise CveCatalogError(f"{cve_id}: affected ranges must not overlap")
    verified_at = _nonempty_text(raw.get("verified_at"), "verified_at")
    try:
        date.fromisoformat(verified_at)
    except ValueError as exc:
        raise CveCatalogError(f"{cve_id}: verified_at must use YYYY-MM-DD") from exc
    entry = dict(raw)
    entry.update(
        {
            "id": cve_id,
            "product": product,
            "severity": severity,
            "score": float(score),
            "vector": vector,
            "privileges_required": privilege_metrics[0].removeprefix("PR:"),
            "impact": impact,
            "affected": validated_ranges,
            "title": _nonempty_text(raw.get("title"), "title"),
            "references": [str(ref) for ref in references],
            "verified_at": verified_at,
        }
    )
    return entry


@lru_cache(maxsize=1)
def load_catalog() -> CveCatalog:
    try:
        raw = json.loads(_catalog_path().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CveCatalogError(f"failed to load bundled CVE catalog: {exc}") from exc
    if not isinstance(raw, dict):
        raise CveCatalogError("CVE catalog root must be an object")
    if raw.get("schema_version") != 1:
        raise CveCatalogError("unsupported CVE catalog schema version")
    version = _nonempty_text(raw.get("catalog_version"), "catalog_version")
    entries_raw = raw.get("entries")
    if not isinstance(entries_raw, list):
        raise CveCatalogError("CVE catalog entries must be a list")
    seen: set[tuple[str, str]] = set()
    entries = tuple(_validate_entry(item, seen) for item in entries_raw)
    return CveCatalog(version=version, entries=entries)


def _clean_version(value: Any) -> str | None:
    if not isinstance(value, (str, int, float)):
        return None
    text = str(value).strip()
    return text if text and text != "-" else None


def _numeric_version(value: str) -> tuple[int, ...] | None:
    parsed = _parse_numeric_version(value)
    return parsed.numbers if parsed is not None else None


def _parse_numeric_version(value: str) -> _ParsedVersion | None:
    match = _VERSION_TOKEN_RE.match(value.strip())
    if not match:
        return None
    numbers = tuple(int(part) for part in re.split(r"[._]", match.group(1)))
    suffix = match.group(2)
    if not suffix:
        return _ParsedVersion(numbers)
    prerelease_match = _PRERELEASE_RE.match(suffix)
    if prerelease_match:
        remainder = suffix[prerelease_match.end() :]
        if remainder and not (remainder.startswith("+") or _IGNORED_VERSION_SUFFIX_RE.fullmatch(remainder)):
            return None
        stage = prerelease_match.group(1).lower()
        stage_rank = 0 if stage == "dev" else 1 if stage in {"alpha", "a"} else 2 if stage in {"beta", "b"} else 3
        return _ParsedVersion(numbers, (stage_rank, int(prerelease_match.group(2) or 0)))
    if re.fullmatch(r"-\d+", suffix):
        return _ParsedVersion((*numbers, int(suffix[1:])))
    if _IGNORED_VERSION_SUFFIX_RE.fullmatch(suffix):
        return _ParsedVersion(numbers)
    return None


def _minio_version(value: str) -> tuple[int, ...] | None:
    match = _MINIO_RELEASE_RE.search(value.strip())
    if not match:
        return None
    return tuple(int(part or 0) for part in match.groups())


def normalize_version(value: str, scheme: str = "numeric") -> tuple[int, ...] | None:
    parsed = _parse_version(value, scheme)
    return parsed.numbers if parsed is not None else None


def _parse_version(value: str, scheme: str) -> _ParsedVersion | None:
    if scheme == "minio_release":
        numbers = _minio_version(value)
        return _ParsedVersion(numbers) if numbers is not None else None
    if scheme == "oracle":
        oracle_release = _ORACLE_RELEASE_RE.fullmatch(value.strip())
        if oracle_release:
            return _ParsedVersion((int(oracle_release.group(1)), 0, 0, 0, 0))
    return _parse_numeric_version(value)


def _compare_versions(left: _ParsedVersion, right: _ParsedVersion) -> int:
    width = max(len(left.numbers), len(right.numbers))
    lhs = left.numbers + (0,) * (width - len(left.numbers))
    rhs = right.numbers + (0,) * (width - len(right.numbers))
    numeric_result = (lhs > rhs) - (lhs < rhs)
    if numeric_result:
        return numeric_result
    if left.prerelease is None and right.prerelease is None:
        return 0
    if left.prerelease is None:
        return 1
    if right.prerelease is None:
        return -1
    return (left.prerelease > right.prerelease) - (left.prerelease < right.prerelease)


def version_in_range(version: str, affected: Mapping[str, Any]) -> bool | None:
    scheme = str(affected.get("scheme") or "numeric")
    parsed = _parse_version(version, scheme)
    if parsed is None:
        return None
    introduced_raw = affected.get("introduced")
    fixed_raw = affected.get("fixed")
    last_raw = affected.get("last_affected")
    introduced = _parse_version(str(introduced_raw), scheme) if introduced_raw is not None else None
    fixed = _parse_version(str(fixed_raw), scheme) if fixed_raw is not None else None
    last = _parse_version(str(last_raw), scheme) if last_raw is not None else None
    if introduced_raw is not None and introduced is None:
        return None
    if fixed_raw is not None and fixed is None:
        return None
    if last_raw is not None and last is None:
        return None
    if introduced is not None and _compare_versions(parsed, introduced) < 0:
        return False
    if fixed is not None and _compare_versions(parsed, fixed) >= 0:
        return False
    if last is not None and _compare_versions(parsed, last) > 0:
        return False
    return True


def normalized_version_text(value: str | None, *, product_key: str) -> str | None:
    if not value:
        return None
    scheme = _version_scheme(product_key)
    parsed = _parse_version(value, scheme)
    if parsed is None:
        return None
    if scheme == "minio_release":
        return str(value).strip()
    base = ".".join(str(part) for part in parsed.numbers)
    if parsed.prerelease is None:
        return base
    stage = {0: "dev", 1: "alpha", 2: "beta", 3: "rc"}[parsed.prerelease[0]]
    return f"{base}-{stage}{parsed.prerelease[1]}"


def _version_scheme(product_key: str) -> str:
    if product_key == "minio":
        return "minio_release"
    if product_key == "oracle_database":
        return "oracle"
    return "numeric"


def _product(product_key: str, name: str, version: Any, *, confidence: str = "confirmed") -> DetectedProduct:
    return DetectedProduct(product_key, name, _clean_version(version), confidence)


def _nested_version(payload: Mapping[str, Any], field: str, *keys: str) -> str | None:
    value = payload.get(field)
    if not isinstance(value, Mapping):
        return None
    for key in keys:
        version = _clean_version(value.get(key))
        if version:
            return version
    return None


def resolve_products(module: str, payload: Mapping[str, Any]) -> list[DetectedProduct]:
    module = str(module).strip().lower()
    version_fields: dict[str, tuple[str, str, str]] = {
        "airflow": ("apache_airflow", "Apache Airflow", "version"),
        "clickhouse": ("clickhouse", "ClickHouse", "server_version"),
        "consul": ("hashicorp_consul", "HashiCorp Consul", "version"),
        "docker": ("docker_engine", "Docker Engine", "server_version"),
        "etcd": ("etcd", "etcd", "server_version"),
        "gitlab": ("gitlab", "GitLab", "version"),
        "grafana": ("grafana", "Grafana", "server_version"),
        "kubeapi": ("kubernetes", "Kubernetes", "version"),
        "minio": ("minio", "MinIO", "version"),
        "mongodb": ("mongodb", "MongoDB", "server_version"),
        "oracle": ("oracle_database", "Oracle Database", "server_version"),
        "postgres": ("postgresql", "PostgreSQL", "server_version"),
        "proxmox": ("proxmox_ve", "Proxmox VE", "version"),
        "qdrant": ("qdrant", "Qdrant", "version"),
        "rabbitmq": ("rabbitmq", "RabbitMQ", "version"),
    }
    if module in version_fields:
        key, name, field = version_fields[module]
        return [_product(key, name, payload.get(field))]
    if module == "elastic":
        vendor = str(payload.get("vendor") or "").strip().lower()
        if vendor == "opensearch":
            return [_product("opensearch", "OpenSearch", payload.get("server_version"))]
        if vendor == "elasticsearch":
            return [_product("elasticsearch", "Elasticsearch", payload.get("server_version"))]
        return []
    if module == "redis":
        implementation = str(payload.get("implementation") or "redis").strip().lower()
        if implementation == "valkey" or payload.get("valkey_version"):
            return [_product("valkey", "Valkey", payload.get("valkey_version") or payload.get("server_version"))]
        return [_product("redis", "Redis", payload.get("redis_version") or payload.get("server_version"))]
    if module in {"zookeeper", "keeper"}:
        is_keeper = payload.get("is_keeper") is True or module == "keeper"
        return [
            _product(
                "clickhouse_keeper" if is_keeper else "apache_zookeeper",
                "ClickHouse Keeper" if is_keeper else "Apache ZooKeeper",
                payload.get("version"),
            )
        ]
    if module == "registry":
        products: list[DetectedProduct] = []
        if payload.get("is_harbor") is True:
            products.append(
                _product("harbor", "Harbor", _nested_version(payload, "harbor_info", "harbor_version", "version"))
            )
        if payload.get("is_nexus") is True:
            products.append(
                _product(
                    "nexus_repository", "Nexus Repository", _nested_version(payload, "nexus_info", "version", "release")
                )
            )
        if payload.get("is_gitlab") is True:
            products.append(_product("gitlab", "GitLab", _nested_version(payload, "gitlab_info", "version")))
        return products
    return []


def _range_text(affected: Mapping[str, Any]) -> str:
    parts: list[str] = []
    if affected.get("introduced") is not None:
        parts.append(f">={affected['introduced']}")
    if affected.get("fixed") is not None:
        parts.append(f"<{affected['fixed']}")
    if affected.get("last_affected") is not None:
        parts.append(f"<={affected['last_affected']}")
    return ",".join(parts)


def _additional_evidence(module: str, payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Normalize module-specific checks that intentionally fall outside the catalog policy."""
    if module != "qdrant":
        return []
    assessment = payload.get("ghsa_f632_vm87_2m2f")
    if not isinstance(assessment, Mapping):
        return []
    return [
        {
            "id": str(assessment.get("cve") or "CVE-2026-25628"),
            "advisory_id": str(assessment.get("id") or "GHSA-f632-vm87-2m2f"),
            "title": "Arbitrary file write via /logger endpoint",
            "endpoint": str(assessment.get("endpoint") or "/logger"),
            "detected_version": _clean_version(assessment.get("version")),
            "affected_range": str(assessment.get("affected_range") or ">=1.9.3,<1.15.6"),
            "version_affected": assessment.get("version_affected"),
            "endpoint_reachable": assessment.get("logger_reachable"),
            "endpoint_blocked": assessment.get("logger_blocked"),
            "assessment": str(assessment.get("assessment") or "unknown"),
            "catalog_eligible": True,
            "catalog_access_condition": "requires_low_privileges",
        }
    ]


def enumerate_record(
    module: str,
    payload: Mapping[str, Any],
    *,
    catalog: CveCatalog,
    confirmed: bool,
    resolver: ProductResolver | None = None,
    credentials_provided: bool = False,
) -> dict[str, Any]:
    evidence = _additional_evidence(module, payload)
    if not confirmed:
        return {
            "status": "unsupported",
            "reason": "service_not_confirmed",
            "catalog_version": catalog.version,
            "products": [],
            "findings": [],
            "additional_evidence": evidence,
        }
    if module == "kafka":
        return {
            "status": "unsupported",
            "reason": "unsupported_version_detection",
            "catalog_version": catalog.version,
            "products": [],
            "findings": [],
            "additional_evidence": evidence,
        }
    if module == "grpc":
        return {
            "status": "unsupported",
            "reason": "unsupported_product_detection",
            "catalog_version": catalog.version,
            "products": [],
            "findings": [],
            "additional_evidence": evidence,
        }
    products = (resolver or (lambda value: resolve_products(module, value)))(payload)
    if not products:
        return {
            "status": "unsupported",
            "reason": "unsupported_product_detection",
            "catalog_version": catalog.version,
            "products": [],
            "findings": [],
            "additional_evidence": evidence,
        }
    findings: list[dict[str, Any]] = []
    has_unknown_version = False
    low_privilege_basis = (
        "anonymous_access"
        if payload.get("auth_required") is False
        else "provided_credentials"
        if credentials_provided
        else None
    )
    for product in products:
        if not product.version or normalize_version(product.version, _version_scheme(product.product_key)) is None:
            has_unknown_version = True
            continue
        for entry in catalog.entries:
            if entry["product"] != product.product_key:
                continue
            for affected in entry["affected"]:
                matched = version_in_range(product.version, affected)
                if matched is True:
                    privileges_required = str(entry.get("privileges_required") or "N")
                    if privileges_required == "L" and low_privilege_basis is None:
                        break
                    findings.append(
                        {
                            "id": entry["id"],
                            "title": entry["title"],
                            "product": product.product_key,
                            "detected_version": product.version,
                            "severity": entry["severity"],
                            "score": entry["score"],
                            "vector": entry["vector"],
                            "privileges_required": privileges_required,
                            "access_basis": "network" if privileges_required == "N" else low_privilege_basis,
                            "impact": entry["impact"],
                            "affected_range": _range_text(affected),
                            "fixed_version": affected.get("fixed"),
                            "references": list(entry["references"]),
                        }
                    )
                    break
    findings.sort(key=_finding_recency_key)
    status = "matched" if findings else "version_unknown" if has_unknown_version else "no_matches"
    return {
        "status": status,
        "catalog_version": catalog.version,
        "products": [product.to_dict() for product in products],
        "findings": findings,
        "additional_evidence": evidence,
    }


def _finding_recency_key(item: Mapping[str, Any]) -> tuple[int, int, str]:
    """Sort catalog findings from the newest CVE identifier to the oldest."""
    cve_id = str(item.get("id") or "")
    match = _CVE_RE.fullmatch(cve_id)
    if match is None:
        return (0, 0, cve_id)
    _prefix, year, sequence = cve_id.split("-", maxsplit=2)
    return (-int(year), -int(sequence), str(item.get("product") or ""))


def render_finding_lines(payload: Mapping[str, Any], *, label: str, host: str, port: int) -> list[str]:
    enumeration = payload.get("cve_enumeration")
    if not isinstance(enumeration, Mapping):
        return []
    findings = enumeration.get("findings")
    if not isinstance(findings, list):
        return []
    prefix = f"{label:<15}\t{host:<15}\t{int(port):<5}\t"
    lines: list[str] = []
    for finding in findings:
        if not isinstance(finding, Mapping):
            continue
        lines.append(
            f"{prefix}[!] {finding.get('id')} potentially affected "
            f"({finding.get('severity')} {float(finding.get('score') or 0):g}) {finding.get('title')}"
        )
    return lines


__all__ = [
    "CveCatalog",
    "CveCatalogError",
    "DetectedProduct",
    "ProductResolver",
    "enumerate_record",
    "load_catalog",
    "normalize_version",
    "render_finding_lines",
    "resolve_products",
    "version_in_range",
]
