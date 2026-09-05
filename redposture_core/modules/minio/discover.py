"""Two-stage MinIO secret discovery: object-name prioritisation + bounded
content inspection, feeding the shared secret_detection engine.

Bounded by object size, per-object bytes, total bytes, object count and a time
budget. Never reads unbounded object storage; partial coverage is reported.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any

from ...clients.minio_api import MinioClient
from ...secret_detection import mask_secret, scan_value
from .enumerate import ObjectInfo

# Stage 1: interesting-by-name substrings / suffixes. A match makes the key a
# *candidate*, not a finding.
_CANDIDATE_SUFFIXES = (
    ".env",
    ".pem",
    ".key",
    ".pfx",
    ".p12",
    ".jks",
    ".kdbx",
    ".tfstate",
    ".yaml",
    ".yml",
    ".json",
    ".xml",
    ".ini",
    ".properties",
    ".sql",
    ".zip",
    ".tar",
    ".gz",
    ".tgz",
    ".bak",
)
_CANDIDATE_SUBSTRINGS = (
    "credential",
    "secret",
    "config",
    "backup",
    "dump",
    "password",
    "id_rsa",
    "id_ed25519",
    "kubeconfig",
    ".kube/config",
    ".aws/credentials",
    ".dockercfg",
    "docker/config",
    "connection",
    "token",
)


def is_candidate_key(key: str) -> str | None:
    """Return a candidate reason label if the object key looks interesting."""
    lowered = key.lower()
    for suffix in _CANDIDATE_SUFFIXES:
        if lowered.endswith(suffix):
            return f"suffix:{suffix}"
    for sub in _CANDIDATE_SUBSTRINGS:
        if sub in lowered:
            return f"name:{sub}"
    return None


# Text carried from one chunk into the next so a secret straddling a chunk
# boundary is still matched (chunked reads would otherwise split it).
_CHUNK_OVERLAP = 512
# Internal ranged-read size — kept memory-bounded and deliberately NOT a CLI flag.
_DEFAULT_CHUNK = 8 * 1024 * 1024


@dataclass
class Budget:
    # Two operator-facing knobs: how many objects to inspect (`max_objects`) and how
    # many bytes to read from each (`max_object_size`, read in `chunk_size` ranged
    # reads — larger objects are scanned in chunks, never skipped). `chunk_size` is an
    # internal memory bound, not a CLI flag.
    max_object_size: int = 100 * 1024 * 1024
    max_objects: int = 1000
    time_budget: float = 30.0
    chunk_size: int = _DEFAULT_CHUNK
    _started: float = field(default_factory=time.monotonic)

    def expired(self) -> bool:
        return (time.monotonic() - self._started) >= self.time_budget


@dataclass
class DiscoverResult:
    findings: list[dict[str, Any]] = field(default_factory=list)
    candidates: list[dict[str, Any]] = field(default_factory=list)
    objects_scanned: int = 0
    bytes_read: int = 0
    partial_reasons: list[str] = field(default_factory=list)
    coverage_complete: bool = True

    def _partial(self, reason: str) -> None:
        self.coverage_complete = False
        if reason not in self.partial_reasons:
            self.partial_reasons.append(reason)


def _read_and_scan(
    client: MinioClient,
    obj: ObjectInfo,
    budget: Budget,
    result: DiscoverResult,
    seen: set[tuple[Any, ...]],
    on_finding: Callable[[dict[str, Any]], None] | None,
) -> bool:
    """Read one object in ranged chunks and scan each. Large objects are read in
    `chunk_size` ranged reads up to `max_object_size` (never skipped), with overlap so
    a secret on a chunk boundary is still matched. Returns False when the time budget
    is exhausted (the caller should then stop entirely)."""
    offset = 0
    object_read = 0
    carry = ""
    read_any = False
    while object_read < budget.max_object_size:
        if budget.expired():
            result._partial("timeout")
            return False
        length = min(budget.chunk_size, budget.max_object_size - object_read)
        resp = client.get_object_range(obj.bucket, obj.key, start=offset, length=length, signed=True)
        if resp.transport_error:
            result._partial("read_failure")
            return True  # skip this object, keep scanning others
        if resp.http_status in {401, 403} or (resp.error is not None and resp.error.code == "AccessDenied"):
            result._partial("permission_denied")
            return True
        if resp.http_status == 416 or (resp.error is not None and resp.error.code == "InvalidRange"):
            break  # requested range is past the object end -> done reading it
        if resp.http_status not in {200, 206}:
            result._partial("read_failure")
            return True
        body = resp.body or b""
        if not body:
            break  # end of object reached
        read_any = True
        result.bytes_read += len(body)
        object_read += len(body)
        offset += len(body)
        text = carry + body.decode("utf-8", errors="replace")
        try:
            matches = scan_value(text, object_path="$", enabled=None)
        except Exception:  # noqa: BLE001 - a bad chunk must not abort discovery
            result._partial("parse_failure")
        else:
            for match in matches:
                dedup_key = (match.detector, match.value, match.object_path, obj.bucket, obj.key)
                if dedup_key in seen:
                    continue  # overlap can surface a boundary secret twice
                seen.add(dedup_key)
                finding = {
                    "type": match.detector,
                    "bucket": obj.bucket,
                    "key": obj.key,
                    "value": match.value,
                    "masked_value": mask_secret(match.value),
                    "object_path": match.object_path,
                }
                result.findings.append(finding)
                if on_finding is not None:
                    on_finding(finding)  # real-time emission of each finding
        carry = text[-_CHUNK_OVERLAP:]
        if len(body) < length:
            break  # short read -> end of object
    else:
        # loop ended because we reached the per-object cap: the object is larger.
        result._partial("object_truncated")
    if read_any:
        result.objects_scanned += 1
    return True


def discover_secrets(
    client: MinioClient,
    objects: Iterable[ObjectInfo],
    *,
    budget: Budget | None = None,
    on_finding: Callable[[dict[str, Any]], None] | None = None,
) -> DiscoverResult:
    """Scan candidate objects for secrets, streaming and bounded; large objects are
    read in chunks rather than skipped. `on_finding`, if given, is called with each
    finding as it is discovered (used for real-time output)."""
    budget = budget or Budget()
    result = DiscoverResult()
    seen: set[tuple[Any, ...]] = set()
    obj_iter: Iterator[ObjectInfo] = iter(objects)
    enumerated = 0
    for obj in obj_iter:
        # `max_objects` bounds how many objects are *examined* (enumerated). Callers
        # stream `max_objects + 1` so hitting this cap means the listing was
        # truncated -> honest partial coverage.
        if enumerated >= budget.max_objects:
            result._partial("object_limit")
            break
        enumerated += 1
        reason = is_candidate_key(obj.key)
        if reason is None:
            continue
        result.candidates.append({"bucket": obj.bucket, "key": obj.key, "reason": reason})
        if budget.expired():
            result._partial("timeout")
            break
        if not _read_and_scan(client, obj, budget, result, seen, on_finding):
            break  # time budget exhausted
    return result


__all__ = ["Budget", "DiscoverResult", "discover_secrets", "is_candidate_key"]
