"""Two-stage MinIO secret discovery: object-name prioritisation + bounded
content inspection, feeding the shared secret_detection engine.

Bounded by inspected bytes and an optional time budget. Object listings are
streamed; partial coverage is reported when a budget is reached.
"""

from __future__ import annotations

import threading
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
DISCOVER_WORKERS = 8


@dataclass
class Budget:
    # Objects are read in bounded ranged chunks; the target-wide byte budget
    # controls the total amount of content inspected.
    max_object_size: int | None = None
    max_objects: int | None = None
    time_budget: float | None = None
    max_total_bytes: int | None = 50 * 1024 * 1024
    chunk_size: int = _DEFAULT_CHUNK
    _started: float = field(default_factory=time.monotonic)
    _claimed_bytes: int = 0
    _active_claims: int = 0
    _condition: threading.Condition = field(default_factory=threading.Condition, repr=False)

    def expired(self) -> bool:
        return self.time_budget is not None and (time.monotonic() - self._started) >= self.time_budget

    def claim(self, length: int) -> int:
        with self._condition:
            if self.max_total_bytes is None:
                return length
            while self._claimed_bytes >= self.max_total_bytes and self._active_claims:
                self._condition.wait()
            allowed = min(length, max(0, self.max_total_bytes - self._claimed_bytes))
            self._claimed_bytes += allowed
            if allowed:
                self._active_claims += 1
            return allowed

    def release(self, length: int) -> None:
        if self.max_total_bytes is not None:
            with self._condition:
                self._claimed_bytes -= length
                self._active_claims -= 1
                self._condition.notify_all()

    def byte_limit_reached(self) -> bool:
        if self.max_total_bytes is None:
            return False
        with self._condition:
            while self._claimed_bytes >= self.max_total_bytes and self._active_claims:
                self._condition.wait()
            return self._claimed_bytes >= self.max_total_bytes


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
    while budget.max_object_size is None or object_read < budget.max_object_size:
        if budget.expired():
            result._partial("timeout")
            return False
        length = budget.claim(
            min(budget.chunk_size, budget.max_object_size - object_read)
            if budget.max_object_size is not None
            else budget.chunk_size
        )
        if length <= 0:
            result._partial("max_bytes")
            return False
        try:
            resp = client.get_object_range(obj.bucket, obj.key, start=offset, length=length, signed=True)
        except Exception:  # noqa: BLE001 - one failed object must not retain the shared reservation
            budget.release(length)
            result._partial("read_failure")
            return True
        if resp.transport_error:
            budget.release(length)
            result._partial("read_failure")
            return True  # skip this object, keep scanning others
        if resp.http_status in {401, 403} or (resp.error is not None and resp.error.code == "AccessDenied"):
            budget.release(length)
            result._partial("permission_denied")
            return True
        if resp.http_status == 416 or (resp.error is not None and resp.error.code == "InvalidRange"):
            budget.release(length)
            break  # requested range is past the object end -> done reading it
        if resp.http_status not in {200, 206}:
            budget.release(length)
            result._partial("read_failure")
            return True
        body = (resp.body or b"")[:length]
        budget.release(length - len(body))
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
    nested_scheduler: Any | None = None,
    scheduler_key: Any | None = None,
) -> DiscoverResult:
    """Scan candidate objects for secrets, streaming and bounded; large objects are
    read in chunks rather than skipped. `on_finding`, if given, is called with each
    finding as it is discovered (used for real-time output)."""
    budget = budget or Budget()
    result = DiscoverResult()
    obj_iter: Iterator[ObjectInfo] = iter(objects)
    enumerated = 0

    def candidates() -> Iterator[tuple[int, ObjectInfo]]:
        nonlocal enumerated
        candidate_index = 0
        for obj in obj_iter:
            if budget.byte_limit_reached():
                result._partial("max_bytes")
                return
            # `max_objects` bounds how many objects are *examined* (enumerated).
            if budget.max_objects is not None and enumerated >= budget.max_objects:
                result._partial("object_limit")
                return
            enumerated += 1
            reason = is_candidate_key(obj.key)
            if reason is None:
                continue
            result.candidates.append({"bucket": obj.bucket, "key": obj.key, "reason": reason})
            if budget.expired():
                result._partial("timeout")
                return
            yield candidate_index, obj
            candidate_index += 1

    def scan_object(item: tuple[int, ObjectInfo]) -> DiscoverResult:
        _index, obj = item
        local = DiscoverResult()
        _read_and_scan(client, obj, budget, local, set(), None)
        return local

    def merge(local: DiscoverResult) -> None:
        result.objects_scanned += local.objects_scanned
        result.bytes_read += local.bytes_read
        for reason in local.partial_reasons:
            result._partial(reason)
        for finding in local.findings:
            result.findings.append(finding)
            if on_finding is not None:
                on_finding(finding)

    if nested_scheduler is None:
        for item in candidates():
            merge(scan_object(item))
            if budget.expired():
                result._partial("timeout")
                break
        return result

    pending: dict[int, DiscoverResult] = {}
    next_index = 0
    for item, local in nested_scheduler.iter_completed(
        candidates(),
        scan_object,
        key=scheduler_key,
        per_key_limit=DISCOVER_WORKERS,
    ):
        index, _obj = item
        pending[index] = local
        while next_index in pending:
            merge(pending.pop(next_index))
            next_index += 1
    return result


__all__ = ["Budget", "DISCOVER_WORKERS", "DiscoverResult", "discover_secrets", "is_candidate_key"]
