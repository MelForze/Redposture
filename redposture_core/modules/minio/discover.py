"""Two-stage MinIO secret discovery with ranged, bounded content reads."""

from __future__ import annotations

import codecs
import hashlib
import json
import tempfile
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any, Protocol

from ...clients.minio_api import MinioResponse
from ...data_discovery import _scan_portioned_value
from ...discovery_frontier import DiscoveryFrontier
from ...discovery_options import DEFAULT_DISCOVER_MAX_BYTES, DEFAULT_DISCOVER_TIME
from ...discovery_paths import Text, json_discovery_path
from ...discovery_spool import SpoolingRecords
from ...discovery_text import DiscoveryTextStream, _Value
from ...discovery_values import DiskBackedText
from ...json_stream import JSONPath, JSONScalarStream
from ...scheduler import NestedSchedulerCancelled
from ...secret_detection import fingerprint, scan_value
from .enumerate import ObjectInfo


class ObjectReader(Protocol):
    """Ranged object transport shared by S3 and Console discovery."""

    def get_object_range(self, bucket: str, key: str, *, start: int, length: int, signed: bool) -> MinioResponse: ...


# Stage 1: interesting-by-name substrings / suffixes. A match makes the key a
# *candidate*, not a finding.
_CANDIDATE_SUFFIXES = (
    ".txt",
    ".log",
    ".csv",
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


def _candidate_reason(obj: ObjectInfo) -> str | None:
    named = is_candidate_key(obj.key)
    if named is not None:
        return named
    content_type = str(obj.content_type or "").lower().split(";", 1)[0].strip()
    if content_type.startswith(("image/", "audio/", "video/")):
        return None
    if obj.key.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".webp", ".mp3", ".mp4")):
        return None
    # Unknown extensions and application/octet-stream can contain plain text.
    # Read them under the existing target-wide byte, object and time budgets.
    return "content:unclassified"


# Text carried from one chunk into the next so a secret straddling a chunk
# boundary is still matched (chunked reads would otherwise split it).
# Internal ranged-read size — kept memory-bounded and deliberately NOT a CLI flag.
_DEFAULT_CHUNK = 8 * 1024 * 1024
DISCOVER_WORKERS = 8


@dataclass
class Budget:
    # Object reads are ranged. max_total_bytes is retained as a public field
    # name, but bounds one active portion, not cumulative target content.
    max_object_size: int | None = None
    max_objects: int | None = None
    time_budget: float | None = DEFAULT_DISCOVER_TIME
    max_total_bytes: int | None = DEFAULT_DISCOVER_MAX_BYTES
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
            if self.max_total_bytes <= 0:
                return 0
            while self._claimed_bytes >= self.max_total_bytes:
                if self.expired():
                    return 0
                self._condition.wait(timeout=0.1)
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
        return False


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


def _path_identity(path: Text) -> tuple[int, str]:
    """Use one bounded content identity for equivalent text and disk paths."""
    if isinstance(path, DiskBackedText):
        return path.byte_length, path.digest
    digest = hashlib.sha256()
    length = 0
    for offset in range(0, len(path), 65536):
        encoded = path[offset : offset + 65536].encode("utf-8")
        length += len(encoded)
        digest.update(encoded)
    return length, digest.hexdigest()


def _canonical_dedup_key(key: tuple[Any, ...]) -> tuple[Any, ...]:
    detector, identity, path, bucket, object_key = key
    if isinstance(path, (str, DiskBackedText)):
        path = _path_identity(path)
    return detector, identity, path, bucket, object_key


class _JSONDocuments(JSONScalarStream):
    """Keep scalar streaming across consecutive JSON documents in an object."""

    def _character(self, char: str) -> None:
        if self.root_state == "done" and char not in " \t\r\n":
            self.root_state = "value"
            self.root_kind = None
        super()._character(char)


def _read_and_scan(
    client: ObjectReader,
    obj: ObjectInfo,
    budget: Budget,
    result: DiscoverResult,
    seen: set[tuple[Any, ...]],
    on_finding: Callable[[dict[str, Any]], None] | None,
    cancelled: Callable[[], bool] | None = None,
    *,
    retain_findings: bool = True,
) -> bool:
    """Read one object in ranged chunks and scan each. Large objects are read in
    `chunk_size` ranged reads up to `max_object_size` (never skipped). The text
    reader retains unfinished values across range boundaries. Returns False when the time budget
    is exhausted (the caller should then stop entirely)."""
    offset = object_read = 0
    read_any = False
    complete = False
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    seen_frontier: DiscoveryFrontier | None = None
    seen_bytes = 0
    seen_normalized = False
    content_kind: str | None = None
    probe_open: int | None = None
    json_value: _Value | None = None
    replay = None
    json_parser: _JSONDocuments | None = None
    semantic_portion = max(64, min(budget.chunk_size, 65536))

    def publish(value: Any, object_path: Text = "$") -> None:
        nonlocal seen_frontier, seen_bytes, seen_normalized
        deadline = budget._started + budget.time_budget if budget.time_budget is not None else None
        if (
            content_kind == "text"
            and isinstance(value, str)
            and isinstance(object_path, str)
            and len(value) <= semantic_portion
            and value.lstrip().startswith(("{", "["))
        ):
            # The prefix probe already established plain-text syntax. Do not
            # send a bounded log line back through the JSON prefix heuristic.
            matches, covered = scan_value(value, object_path=object_path), True
        else:
            matches, _, covered = _scan_portioned_value(value, object_path, semantic_portion, _deadline=deadline)
        if not covered:
            result._partial("timeout" if budget.expired() else "unscannable_continuous_field")
        for match in matches:
            identity = fingerprint(match.value)
            dedup_key = _canonical_dedup_key((match.detector, identity, match.object_path, obj.bucket, obj.key))
            if not seen_normalized:
                normalized = {_canonical_dedup_key(previous) for previous in seen}
                seen.clear()
                seen.update(normalized)
                seen_normalized = True
            key_bytes = sum(item.__sizeof__() for item in dedup_key)
            if seen_frontier is None and (len(seen) >= 2048 or seen_bytes + key_bytes > 4 * 1024 * 1024):
                seen_frontier = DiscoveryFrontier()
                for previous in seen:
                    seen_frontier.claim(json.dumps(previous, ensure_ascii=False))
                seen.clear()
            if seen_frontier is not None:
                if not seen_frontier.claim(json.dumps(dedup_key, ensure_ascii=False)):
                    continue
            else:
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                seen_bytes += key_bytes
            finding = {
                "type": match.detector,
                "bucket": obj.bucket,
                "key": obj.key,
                "value": match.value,
                "object_path": match.object_path,
            }
            if retain_findings:
                result.findings.append(finding)
            if on_finding is not None:
                on_finding(finding)

    scanner = DiscoveryTextStream(publish, result._partial, portion=budget.chunk_size)

    def replay_chunks() -> Iterator[bytes]:
        if replay is None:
            return
        replay.seek(0)
        while chunk := replay.read(65536):
            if budget.expired():
                raise TimeoutError("discover_time")
            if cancelled is not None and cancelled():
                raise NestedSchedulerCancelled("MinIO discovery cancelled")
            yield chunk

    def plain_fallback(*, invalid_json: bool = False) -> None:
        nonlocal content_kind, json_value
        # A structural prefix alone does not make a log a JSON document.
        # Replay only the undecided/JSON-looking source, using bounded disk
        # storage, if later syntax establishes that plain-text scanning is needed.
        if invalid_json and (obj.key.lower().endswith(".json") or "json" in str(obj.content_type or "").lower()):
            result._partial("parse_failure")
        content_kind = "text"
        if json_parser is not None:
            json_parser.close()
        if json_value is not None:
            json_value.close()
            json_value = None
        for chunk in replay_chunks():
            scanner.feed(decoder.decode(chunk))
        if replay is not None:
            replay.close()

    def feed_json(chunk: bytes) -> bool:
        nonlocal json_parser
        try:
            if json_parser is None:

                def publish_json(path: JSONPath, value: Any) -> None:
                    named = bool(path) and isinstance(path[-1], (str, DiskBackedText))
                    publish({path[-1]: value} if named else value, json_discovery_path(path[:-1] if named else path))

                def json_string(path: JSONPath, text: str, final: bool) -> None:
                    nonlocal json_value
                    if json_value is None:
                        json_value = _Value(semantic_portion)
                    json_value.append(text)
                    if final:
                        value = json_value.finish()
                        json_value = None
                        publish_json(path, value)

                json_parser = _JSONDocuments(
                    json_string,
                    on_primitive=lambda item: publish_json(*item),
                    deadline=budget._started + budget.time_budget if budget.time_budget is not None else None,
                )
            json_parser.feed(chunk)
            return True
        except (ValueError, UnicodeError):
            plain_fallback(invalid_json=True)
            return False

    def feed(chunk: bytes) -> None:
        nonlocal content_kind, probe_open, replay
        if content_kind == "text":
            scanner.feed(decoder.decode(chunk))
            return
        prefix = chunk.lstrip(b" \t\r\n")
        if replay is None and probe_open is None and prefix and prefix[0] not in b"{[":
            # No undecided prefix needs replay and no JSON parser was used.
            # Feed the exact bytes, including leading whitespace, as before.
            content_kind = "text"
            scanner.feed(decoder.decode(chunk))
            return
        if replay is None:
            replay = tempfile.SpooledTemporaryFile(max_size=65536)
        replay.seek(0, 2)
        replay.write(chunk)
        if content_kind == "json":
            feed_json(chunk)
            return
        if probe_open is None:
            if not prefix:
                return
            if prefix[0] not in b"{[":
                plain_fallback()
                return
            probe_open = prefix[0]
            prefix = prefix[1:].lstrip(b" \t\r\n")
        if not prefix:
            return
        starts = b'"}' if probe_open == ord("{") else b'"{[0123456789-tfn]'
        if prefix[0] not in starts:
            plain_fallback()
            return
        content_kind = "json"
        for pending in replay_chunks():
            if not feed_json(pending):
                break

    try:
        while budget.max_object_size is None or object_read < budget.max_object_size:
            if cancelled is not None and cancelled():
                raise NestedSchedulerCancelled("MinIO discovery cancelled")
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
                try:
                    response = client.get_object_range(obj.bucket, obj.key, start=offset, length=length, signed=True)
                except Exception:  # noqa: BLE001 - preserve completed findings after one failed object
                    result._partial("read_failure")
                    return True
                if response.transport_error:
                    result._partial("read_failure")
                    return True
                if response.http_status in {401, 403} or (
                    response.error is not None and response.error.code == "AccessDenied"
                ):
                    result._partial("permission_denied")
                    return True
                if response.http_status == 416 or (
                    response.error is not None and response.error.code == "InvalidRange"
                ):
                    complete = True
                    break
                if response.http_status not in {200, 206}:
                    result._partial("read_failure")
                    return True
                body = (response.body or b"")[:length]
                if not body:
                    complete = True
                    break
                read_any = True
                result.bytes_read += len(body)
                object_read += len(body)
                offset += len(body)
                # Keep Unicode allocations small even when an HTTP Range is
                # several MiB. Repeated large non-ASCII decode allocations can
                # grow the process RSS despite their short Python lifetime.
                for position in range(0, len(body), 65_536):
                    if budget.expired():
                        result._partial("timeout")
                        return False
                    if cancelled is not None and cancelled():
                        raise NestedSchedulerCancelled("MinIO discovery cancelled")
                    feed(body[position : position + 65_536])
                if len(body) < length:
                    complete = True
                    break
            finally:
                budget.release(length)
        if complete:
            if content_kind == "json":
                try:
                    assert json_parser is not None
                    json_parser.finish()
                except (ValueError, UnicodeError):
                    plain_fallback(invalid_json=True)
            elif content_kind is None:
                plain_fallback()
            if content_kind == "text":
                scanner.feed(decoder.decode(b"", final=True))
                scanner.finish()
        else:
            result._partial("object_truncated")
        if read_any:
            result.objects_scanned += 1
        return True
    except ValueError:
        result._partial("parse_failure")
        return True
    except TimeoutError:
        result._partial("timeout")
        return False
    except OSError:
        result._partial("storage_failure")
        return True
    finally:
        if replay is not None:
            replay.close()
        if json_parser is not None:
            json_parser.close()
        if json_value is not None:
            json_value.close()
        scanner.close()
        if seen_frontier is not None:
            seen_frontier.close()


def discover_secrets(
    client: ObjectReader,
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
    result = DiscoverResult(findings=SpoolingRecords(), candidates=SpoolingRecords())
    findings_lock = threading.Lock()
    obj_iter: Iterator[ObjectInfo] = iter(objects)
    enumerated = 0

    def candidates() -> Iterator[tuple[int, ObjectInfo]]:
        nonlocal enumerated
        candidate_index = 0
        while True:
            if budget.expired():
                result._partial("timeout")
                return
            try:
                obj = next(obj_iter)
            except StopIteration:
                return
            if budget.expired():
                result._partial("timeout")
                return
            if budget.byte_limit_reached():
                result._partial("max_bytes")
                return
            # `max_objects` bounds how many objects are *examined* (enumerated).
            if budget.max_objects is not None and enumerated >= budget.max_objects:
                result._partial("object_limit")
                return
            enumerated += 1
            reason = _candidate_reason(obj)
            if reason is None:
                continue
            try:
                result.candidates.append({"bucket": obj.bucket, "key": obj.key, "reason": reason})
            except OSError:
                result._partial("storage_failure")
                return
            if budget.expired():
                result._partial("timeout")
                return
            yield candidate_index, obj
            candidate_index += 1

    def scan_object(item: tuple[int, ObjectInfo]) -> DiscoverResult:
        index, obj = item
        local = DiscoverResult()

        def publish(finding: dict[str, Any]) -> None:
            # Store immediately; the SQL sort key preserves final input order
            # without retaining completed objects behind a slow earlier read.
            with findings_lock:
                assert isinstance(result.findings, SpoolingRecords)
                result.findings.append(finding, sort_key=f"{index:020d}")
                if on_finding is not None:
                    on_finding(finding)

        _read_and_scan(
            client,
            obj,
            budget,
            local,
            set(),
            publish,
            cancelled=(lambda: bool(getattr(nested_scheduler, "cancelled", False))) if nested_scheduler else None,
            retain_findings=False,
        )
        return local

    def merge(local: DiscoverResult) -> None:
        result.objects_scanned += local.objects_scanned
        result.bytes_read += local.bytes_read
        for reason in local.partial_reasons:
            result._partial(reason)

    if nested_scheduler is None:
        for item in candidates():
            merge(scan_object(item))
            if budget.expired():
                result._partial("timeout")
                break
        return result

    for _item, local in nested_scheduler.iter_completed(
        candidates(),
        scan_object,
        key=scheduler_key,
        per_key_limit=DISCOVER_WORKERS,
    ):
        merge(local)
    return result


__all__ = ["Budget", "DISCOVER_WORKERS", "DiscoverResult", "discover_secrets", "is_candidate_key"]
