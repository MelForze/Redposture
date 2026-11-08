"""Bounded, incremental secret inspection for read-only storage discovery."""

from __future__ import annotations

import base64
import codecs
import hashlib
import itertools
import json
import re
import tarfile
import tempfile
import time
import zipfile
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import ExitStack, closing, contextmanager
from contextvars import ContextVar
from io import BytesIO
from typing import Any
from urllib.parse import quote, urlencode, urlsplit

from .data_discovery import _scan_portioned_value
from .discovery_base64 import decoded_base64_file
from .discovery_containers import DiskContainer, DiskMapping, DiskSequence
from .discovery_encoded import compressed_text_prefix, decode_disk_structured_blob, encoded_text_prefix
from .discovery_engine import _json_container_prefix
from .discovery_frontier import DiscoveryFrontier
from .discovery_json import DiskJSONDocument
from .discovery_matches import prefer_specific_matches
from .discovery_occurrences import OccurrenceRegistry
from .discovery_options import DEFAULT_DISCOVER_TIME, UNLIMITED_DISCOVER_BYTES
from .discovery_paths import Text, concat_discovery_text, json_discovery_path
from .discovery_payloads import is_tar_header, iter_payload_members, needs_payload_reader, scan_payload_file
from .discovery_rendering import format_discovery_finding_line
from .discovery_sources import SourceManifest, SourceRead
from .discovery_spool import (
    SpoolingFindings,
    SpoolingFingerprints,
    SpoolingRecords,
    SpoolingValues,
)
from .discovery_text import DiscoveryTextStream
from .discovery_values import DiskBackedText, iter_json_chunks
from .json_stream import JSONPath, JSONScalarStream, SingleStringFieldStream
from .scheduler import NestedSchedulerCancelled
from .secret_detection import _scan_text, detector_names, fingerprint, is_secret_field_name

FINDING_SPOOL_THRESHOLD = 4096
_SOURCE_LOCATION: ContextVar[tuple[object, Mapping[str, Any]] | None] = ContextVar(
    "discovery_source_location", default=None
)


class DiscoveryCollector:
    """Keep a per-response portion bound and a target-wide time deadline."""

    def __init__(self, module: str, ctx: Any, record: Mapping[str, Any]) -> None:
        self.module = module
        self.ctx = ctx
        started_at = getattr(ctx, "discovery_started_at", None)
        if started_at is None:
            started_at = time.monotonic()
        self.deadline = float(started_at) + float(getattr(ctx.args, "discover_time", None) or DEFAULT_DISCOVER_TIME)
        private_limit = getattr(ctx.args, "discover_max_bytes", None)
        # The CLI has no byte budget. Keep the private limit for fault tests,
        # while real scans are bounded by fixed wire portions and the deadline.
        self.remaining = int(private_limit) if private_limit is not None else UNLIMITED_DISCOVER_BYTES
        self.bytes_read = 0
        self.bytes_inspected = 0
        self.findings: list[dict[str, Any]] = []
        self.partial_reasons: list[str] = []
        self._additional_partial_reports = 0
        self.partial_events = 0
        self._all_partial_access_denied = True
        self._spool: OccurrenceRegistry | None = None
        self._sources = 0
        self._live_emitted = False
        self.source_manifest: SourceManifest | None = None
        self.source = (
            "anonymous"
            if record.get("status") == "open_no_auth" or record.get("anonymous_access") is True
            else "authenticated"
            if record.get("provided_credentials_ok") is True
            or record.get("status") in {"valid_credentials", "weak_default_creds", "auth_valid", "open_auth"}
            else "access_unverified"
        )

    def _check_cancellation(self) -> None:
        cancelled = getattr(self.ctx, "cancelled", None)
        if callable(cancelled) and cancelled():
            self.partial("discovery", "cancelled")
            raise NestedSchedulerCancelled("discovery cancelled")

    def allowed(self) -> bool:
        self._check_cancellation()
        if time.monotonic() >= self.deadline:
            self.partial("budget", "discover_time")
            return False
        return True

    def cap(self, maximum: int = 10 * 1024 * 1024) -> int:
        return min(maximum, self.remaining) if self.allowed() else 0

    def charge(self, length: int) -> bool:
        if not self.allowed():
            return False
        if length > self.remaining:
            self.partial("budget", "discover_max_bytes")
            return False
        self.bytes_read += length
        return True

    def partial(self, source: Text, reason: str) -> None:
        self.partial_events += 1
        if isinstance(source, DiskBackedText):
            try:
                source = next(source.iter_text_chunks(max_chars=200), "")
            except (OSError, RuntimeError):
                source = "streamed_json_location"
        detail = f"{source}: {reason}" if source != "budget" else reason
        detail = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", detail)
        detail = "".join(char for char in detail if char >= " ")[:200]
        if "access_denied" not in detail:
            self._all_partial_access_denied = False
        if detail in self.partial_reasons:
            return
        if len(self.partial_reasons) < 64:
            self.partial_reasons.append(detail)
        else:
            self._additional_partial_reports += 1

    def mark_accessible_source(self) -> None:
        """An authorized empty source is complete even without scanned values."""
        self._sources += 1

    @contextmanager
    def source_guard(self, manifest: SourceManifest, source: str) -> Iterator[None]:
        """Keep cancellation observable even when transport raises it directly."""
        try:
            with manifest.guard(source):
                yield
        except (NestedSchedulerCancelled, KeyboardInterrupt):
            self.partial(source, "cancelled")
            raise

    @contextmanager
    def source_attempt(self, source: str, *, scope: str | None = None, content: bool = True) -> Iterator[SourceRead]:
        """Count validated reads independently of findings, including empty sources."""
        if self.source_manifest is None:
            self.source_manifest = SourceManifest()
        manifest = self.source_manifest
        manifest.request(source, scope=scope)
        evidence = SourceRead()
        before = self.partial_events
        finished = False
        try:
            with self.source_guard(manifest, source):
                yield evidence
                finished = True
                if content and evidence.complete and self.partial_events == before:
                    self.mark_accessible_source()
        finally:
            manifest.read(source, evidence.count)
            manifest.finish(
                source,
                complete=finished and evidence.complete and self.partial_events == before,
                denied=evidence.status in {401, 403},
                unsupported=evidence.unsupported,
            )

    def declare_sources(self, *classes: str) -> None:
        """Expose implemented but unrequested classes without inventing reads."""
        if self.source_manifest is None:
            self.source_manifest = SourceManifest()
        for name in classes:
            self.source_manifest.declare(self.module + "." + name)

    @contextmanager
    def source_location(self, location: Mapping[str, Any]) -> Iterator[None]:
        """Pass a row/object locator through nested readers without shared mutable state."""
        token = _SOURCE_LOCATION.set((self, dict(location)))
        try:
            yield
        finally:
            _SOURCE_LOCATION.reset(token)

    def add(
        self,
        path: Text,
        value: Any,
        *,
        charge: bool = True,
        prefer_specific: bool = False,
        location: Mapping[str, Any] | None = None,
        field_name: str | None = None,
    ) -> bool:
        self._check_cancellation()
        scoped = _SOURCE_LOCATION.get()
        if location is None and scoped is not None and scoped[0] is self:
            location = scoped[1]
        place: dict[str, Any] = dict(location) if location is not None else {"source_kind": "content", "object": path}
        if location is None and self.module == "mongodb" and isinstance(value, Mapping) and "_id" in value:
            identifier = value["_id"]
            place.update(
                source_kind="document",
                locator_kind="document_id",
                id=identifier
                if identifier is None or isinstance(identifier, (str, int, float, bool, list, Mapping, DiskBackedText))
                else str(identifier),
            )
        matches, inspected, covered = _scan_portioned_value(
            value, concat_discovery_text("$.", path), self.remaining, _deadline=self.deadline, _field_name=field_name
        )
        if prefer_specific:
            try:
                matches = prefer_specific_matches(matches)
            except OSError:
                self.partial(path, "storage_failure")
                return False
        if charge:
            self.bytes_read += inspected
        else:
            if time.monotonic() >= self.deadline:
                self.partial("budget", "discover_time")
                # The caller already downloaded and charged these bytes. Scan
                # the prefix before stopping any further source requests.
        if not covered:
            if time.monotonic() >= self.deadline:
                self.partial("budget", "discover_time")
            else:
                self.partial(path, getattr(matches, "incomplete_reason", None) or "discover_max_bytes")
        if not (isinstance(value, (Mapping, list, tuple, str, bytes)) and not value):
            self._sources += 1
        self.bytes_inspected += inspected
        try:
            for match in matches:
                self._check_cancellation()
                identity = ("value", fingerprint(match.value))
                finding = {
                    "type": match.detector,
                    "confidence": match.confidence,
                    "detectors": list(match.rule_ids),
                    "value": match.value,
                    "fingerprint": identity[1],
                    "object_path": match.object_path,
                    "source": self.source,
                }
                emit = getattr(self.ctx, "live_emit", None)
                if self._spool is None:
                    self._spool = OccurrenceRegistry()
                    self.findings = self._spool
                if not self._spool.add(
                    finding,
                    location={**place, "object_path": match.object_path, "source": self.source},
                    identity=identity,
                ):
                    continue
                if isinstance(match.value, DiskBackedText):
                    disk_emit = getattr(self.ctx, "live_discovery_value", None)
                    if callable(disk_emit):
                        disk_emit(
                            self.module.upper(),
                            self.ctx.host,
                            self.ctx.port,
                            finding_type=match.detector,
                            value=match.value,
                            place=match.object_path,
                        )
                        self._live_emitted = True
                        assert self._spool is not None
                        self._spool.mark_emitted(*identity)
                    continue
                if callable(emit):
                    emit(
                        [
                            format_discovery_finding_line(
                                self.module.upper(),
                                self.ctx.host,
                                self.ctx.port,
                                severity=match.confidence,
                                finding_type=match.detector,
                                value=finding["value"],
                                place=finding["object_path"],
                            )
                        ]
                    )
                    self._live_emitted = True
                    self._spool.mark_emitted(*identity)
        except OSError:
            self.partial(path, "storage_failure")
            return False
        return self.allowed()

    def read(self, getter: Any, endpoint: str, source: str, *, maximum: int = 10 * 1024 * 1024) -> bytes | None:
        """Fetch one capped response through the owning module's HTTP transport."""
        cap = self.cap(maximum)
        if not cap:
            return None
        try:
            status, body, headers, error = getter(endpoint, cap)
        except (OSError, ValueError) as exc:
            self.partial(source, str(exc))
            return None
        if error:
            self.partial(source, str(error))
            if status != 200 or not body or "timeout" not in str(error).lower():
                return None
        if status in {401, 403}:
            self.partial(source, "access_denied")
            return None
        if status != 200:
            self.partial(source, f"HTTP {status}")
            return None
        if len(body) > self.remaining:
            self.partial("budget", "discover_max_bytes")
            return None
        self.bytes_read += len(body)
        if time.monotonic() >= self.deadline:
            self.partial("budget", "discover_time")
        incomplete = str(headers.get("x-redposture-truncated") or "").lower() == "true" or bool(error)
        if incomplete:
            self.partial(source, "response_truncated")
            # A response cut in the middle of a token cannot verify that
            # token. Retain only the last complete text prefix for early
            # findings; binary and indivisible prefixes stay uninspected.
            if body.startswith((b"PK\x03\x04", b"\x1f\x8b")):
                return None
            try:
                body.decode("utf-8")
            except UnicodeDecodeError:
                return None
            boundary = max(body.rfind(bytes((char,))) for char in b" \t\r\n,;\"'")
            return body[: boundary + 1] if boundary >= 0 else None
        return body

    def scan_archive(self, source: str, body: bytes, kind: str) -> None:
        """Inspect archive members in memory without extracting paths to disk."""
        self.scan_archive_file(source, BytesIO(body), kind)

    def scan_disk_text(
        self,
        source: Text,
        value: DiskBackedText,
        *,
        key: Text | None = None,
        _depth: int = 0,
        prefer_specific: bool = False,
    ) -> bool:
        """Inspect a completed scalar while preserving nested JSON field context."""
        if value.obvious_placeholder:
            self.mark_accessible_source()
            return self.allowed()
        if _depth > 32:
            self.partial(source, "nested_json_depth")
            return False
        prefix = ""
        for chunk in value.iter_text_chunks(max_chars=4096):
            if not self.allowed():
                return False
            prefix = chunk.lstrip()
            if prefix:
                break
        if not prefix.startswith(("{", "[")):
            if key is not None and (isinstance(key, DiskBackedText) or is_secret_field_name(key)):
                return self.add(source, {key: value}, charge=False, prefer_specific=prefer_specific)
            path = concat_discovery_text(source, ".", key) if key is not None else source
            with value.path.open("rb") as reader:
                self._scan_member_stream(
                    path, "value", reader, object_path=path, charge=False, prefer_specific=prefer_specific
                )
            self.mark_accessible_source()
            return self.allowed()
        return self.scan_json_chunks(
            concat_discovery_text(source, ".", key) if key is not None else source,
            (part.encode("utf-8") for part in value.iter_text_chunks()),
            _depth=_depth,
            prefer_specific=prefer_specific,
        )

    def scan_json_chunks(
        self, source: Text, chunks: Iterable[bytes], *, _depth: int = 0, prefer_specific: bool = False
    ) -> bool:
        """Publish completed JSON fields while the enclosing source is still arriving."""
        from .discovery_context import JSONFieldContext

        if _depth > 32:
            self.partial(source, "nested_json_depth")
            return False
        pending: list[str] = []
        pending_size = 0
        scalar: DiskBackedText | None = None

        def publish(path: JSONPath, content: Any, field_name: str | None) -> None:
            if field_name is not None:
                self.add(location(path), content, charge=False, prefer_specific=prefer_specific, field_name=field_name)
            elif isinstance(content, DiskBackedText):
                name = path[-1] if path and isinstance(path[-1], (str, DiskBackedText)) else None
                self.scan_disk_text(
                    location(path[:-1] if name is not None else path),
                    content,
                    key=name,
                    _depth=_depth + 1,
                    prefer_specific=prefer_specific,
                )
            elif path and isinstance(path[-1], (str, DiskBackedText)):
                self.add(location(path[:-1]), {path[-1]: content}, charge=False, prefer_specific=prefer_specific)
            else:
                self.add(location(path), content, charge=False, prefer_specific=prefer_specific)

        contexts = JSONFieldContext(publish, lambda reason: self.partial(source, reason), deadline=self.deadline)

        def location(path: JSONPath) -> Text:
            return json_discovery_path(path, source)

        def on_string(path: JSONPath, text: str, final: bool) -> None:
            nonlocal pending, pending_size, scalar
            if scalar is None:
                pending.append(text)
                pending_size += len(text.encode("utf-8"))
                if pending_size > 65_536:
                    scalar = DiskBackedText()
                    for part in pending:
                        scalar.append_text(part)
                    pending = []
            else:
                scalar.append_text(text)
            if not final:
                return
            if scalar is not None:
                scalar.finish()
                contexts.value(path, scalar)
                scalar = None
            else:
                content = "".join(pending)
                contexts.value(path, content)
            pending = []
            pending_size = 0

        def on_primitive(item: tuple[JSONPath, Any]) -> None:
            path, content = item
            contexts.value(path, content)

        decoder = JSONScalarStream(
            on_string,
            on_primitive=on_primitive,
            deadline=self.deadline,
            on_container=contexts.container,
            on_container_end=contexts.end,
        )
        flush_context = True
        try:
            for chunk in chunks:
                if not self.allowed():
                    return False
                decoder.feed(chunk)
            decoder.finish()
            self.mark_accessible_source()
            return True
        except NestedSchedulerCancelled:
            flush_context = False
            raise
        except (ValueError, UnicodeError):
            self.partial(source, "invalid_json")
            return False
        except TimeoutError:
            flush_context = False
            self.partial("budget", "discover_time")
            return False
        except OSError:
            flush_context = False
            self.partial(source, "storage_failure")
            try:
                contexts.close()
            except OSError:
                # A failed result store must not mask the original failure;
                # a source read failure can still publish its closed prefix.
                pass
            return False
        finally:
            try:
                contexts.close(flush=flush_context)
            finally:
                decoder.close()
                if scalar is not None:
                    scalar.close()

    def stream_http_content(
        self,
        pool: Any,
        url: str,
        source: str,
        *,
        headers: Mapping[str, str],
        timeout: float,
        media_type: str = "",
        prefer_specific: bool = False,
        allow_cross_origin_redirects: bool = False,
        preserve_authorization_on_cross_origin: bool = False,
        on_status: Callable[[int], None] | None = None,
    ) -> bool:
        """Inspect one HTTP response in bounded chunks without retaining its body in RAM."""
        early_probe = bytearray()
        early_pending = bytearray()
        early_inspected = 0
        early_disabled = media_type == "zip" or "tar+" in media_type or media_type.endswith((".tar", ".tar.gz", ".tgz"))
        response_status: int | None = None
        with tempfile.SpooledTemporaryFile(max_size=min(self.remaining, 1024 * 1024)) as spool:

            def accept_response(status: int, _headers: Mapping[str, str]) -> None:
                nonlocal response_status
                response_status = status
                if on_status is not None:
                    on_status(status)

            def scan_early_lines(data: bytes) -> None:
                nonlocal early_disabled, early_inspected
                if early_disabled or response_status != 200:
                    return
                if b"\x00" in data:
                    early_disabled = True
                    early_pending.clear()
                    return
                early_pending.extend(data)
                while (end := early_pending.find(b"\n")) >= 0:
                    line = bytes(early_pending[: end + 1])
                    del early_pending[: end + 1]
                    if len(line) > self.remaining:
                        continue
                    try:
                        value = line.decode("utf-8")
                    except UnicodeDecodeError:
                        early_disabled = True
                        early_pending.clear()
                        return
                    if (
                        len(line.rstrip(b"\r\n")) in {64, 76}
                        and encoded_text_prefix(line)
                        and not _scan_text(value, source, set(detector_names()) - {"high_entropy"})
                    ):
                        # A MIME base64 line can end halfway through a UTF-8
                        # codepoint or decoded secret. Classify the complete
                        # encoded source before publishing fragment findings.
                        early_disabled = True
                        early_pending.clear()
                        return
                    before = self.bytes_inspected
                    self.add(source, value, charge=False, prefer_specific=prefer_specific)
                    early_inspected += self.bytes_inspected - before
                if len(early_pending) > min(self.remaining, 1024 * 1024):
                    early_disabled = True
                    early_pending.clear()

            def write_chunk(chunk: bytes) -> None:
                nonlocal early_disabled
                if not self.charge(len(chunk)):
                    raise TimeoutError("discover stream budget exceeded")
                spool.write(chunk)
                if early_disabled:
                    return
                if len(early_probe) < 4:
                    needed = 4 - len(early_probe)
                    early_probe.extend(chunk[:needed])
                    if len(early_probe) < 4:
                        return
                    if early_probe.startswith((b"PK\x03\x04", b"\x1f\x8b")):
                        early_disabled = True
                        return
                    scan_early_lines(bytes(early_probe) + chunk[needed:])
                else:
                    scan_early_lines(chunk)

            response = pool.request_stream(
                "GET",
                url,
                on_chunk=write_chunk,
                on_response=accept_response,
                chunk_size=max(1, min(self.remaining, 64 * 1024)),
                headers={"User-Agent": "RedPosture/1.0", **headers},
                timeout=timeout,
                deadline=self.deadline,
                allow_cross_origin_redirects=allow_cross_origin_redirects,
                preserve_authorization_on_cross_origin=preserve_authorization_on_cross_origin,
            )
            if response.error or response.status != 200 or response.truncated:
                self.partial(
                    source,
                    "access_denied" if response.status in {401, 403} else response.error or f"HTTP {response.status}",
                )
                return False
            before_full_scan = self.bytes_inspected
            _scan_spooled_blob(self, spool, source, media_type, prefer_specific=prefer_specific)
            self.bytes_inspected -= min(early_inspected, self.bytes_inspected - before_full_scan)
            return True

    def stream_json_text_field(
        self,
        pool: Any,
        url: str,
        source: str,
        field: str,
        *,
        headers: Mapping[str, str],
        timeout: float,
        prefer_specific: bool = False,
    ) -> bool:
        """Read a single JSON string field through bounded network/text portions."""
        stop_reason: str | None = None
        scanner = DiscoveryTextStream(
            lambda value: self.add(source, value, charge=False, prefer_specific=prefer_specific),
            lambda reason: self.partial(source, reason),
            portion=self.remaining,
        )

        class StopStream(Exception):
            pass

        def scan_text(value: str, *, final: bool = False) -> None:
            if value:
                scanner.feed(value)
            if final and not scanner.finished:
                scanner.finish()

        decoder = SingleStringFieldStream(field, scan_text, on_complete=lambda: scan_text("", final=True))

        def on_response(status: int, response_headers: Mapping[str, str]) -> None:
            nonlocal stop_reason
            if status != 200:
                stop_reason = "access_denied" if status in {401, 403} else f"HTTP {status}"
                raise StopStream
            media_type = next(
                (str(value).lower() for key, value in response_headers.items() if str(key).lower() == "content-type"),
                "",
            )
            if "json" not in media_type:
                stop_reason = "unexpected_content_type"
                raise StopStream

        def on_chunk(chunk: bytes) -> None:
            nonlocal stop_reason
            if not self.charge(len(chunk)):
                stop_reason = "discover_time" if time.monotonic() >= self.deadline else "internal_read_portion"
                raise StopStream
            try:
                decoder.feed(chunk)
            except (UnicodeDecodeError, ValueError):
                stop_reason = "invalid_json"
                raise StopStream from None

        try:
            response = pool.request_stream(
                "GET",
                url,
                on_chunk=on_chunk,
                on_response=on_response,
                chunk_size=max(1, min(self.remaining, 64 * 1024)),
                headers={"User-Agent": "RedPosture/1.0", **headers},
                timeout=timeout,
                deadline=self.deadline,
                allow_cross_origin_redirects=False,
            )
            if stop_reason:
                self.partial(source, stop_reason)
                return False
            if response.error or response.status != 200 or response.truncated:
                self.partial(
                    source,
                    "access_denied" if response.status in {401, 403} else response.error or f"HTTP {response.status}",
                )
                return False
            try:
                decoder.finish()
                scan_text("", final=True)
            except (UnicodeDecodeError, ValueError):
                self.partial(source, "invalid_json")
                return False
            self.mark_accessible_source()
            return True
        finally:
            scanner.close()

    def stream_json_scalars(
        self,
        pool: Any,
        url: str,
        source: str,
        *,
        headers: Mapping[str, str],
        timeout: float,
        root_kind: str,
        exclude: Callable[[JSONPath], bool] | None = None,
        required_prefix: JSONPath | None = None,
        expected_string: tuple[JSONPath, str] | None = None,
        required_containers: Mapping[JSONPath, str] | None = None,
        row_validators: Mapping[JSONPath, tuple[frozenset[str], Callable[[Mapping[str, Any]], bool]]] | None = None,
        row_streamed_strings: Mapping[JSONPath, frozenset[str]] | None = None,
        on_row: Callable[[JSONPath, Mapping[str, Any]], None] | None = None,
        on_status: Callable[[int], None] | None = None,
        on_primitive_value: Callable[[JSONPath, Any], None] | None = None,
        on_response_headers: Callable[[Mapping[str, str]], None] | None = None,
        prefer_specific: bool = False,
        path_style: str = "url",
    ) -> bool:
        """Inspect a large structured JSON response one decoded scalar at a time."""
        pending = ""
        pending_size = 0
        active_path: JSONPath | None = None
        disk_secret: DiskBackedText | None = None
        text_scanner: DiscoveryTextStream | None = None
        stop_reason: str | None = None
        required_seen = required_prefix is None
        expected_parts: list[str] = []
        expected_seen = 0
        expected_ok = False
        expected_overflow = False
        containers_seen: set[JSONPath] = set()
        invalid_container = False
        active_rows: dict[JSONPath, dict[str, Any]] = {}
        row_fragments: dict[JSONPath, list[str]] = {}
        row_streamed_state: dict[JSONPath, tuple[int, bool]] = {}
        invalid_row = False
        portion_limit = max(1, min(self.remaining - 128, 1024 * 1024))

        class StopStream(Exception):
            pass

        def source_path(path: JSONPath, *, wrapped: bool = False) -> Text:
            # When scanning {key: scalar}, the scanner appends the key to the
            # supplied parent. The dot style must not repeat that final key.
            if path_style == "dot" and wrapped and path and isinstance(path[-1], (str, DiskBackedText)):
                path = path[:-1]
            return json_discovery_path(path, source, style=path_style)

        def add_segment(path: JSONPath, segment: str, *, full_scalar: bool) -> None:
            if not segment:
                return
            key = path[-1] if path else None
            value = {key: segment} if full_scalar and isinstance(key, (str, DiskBackedText)) else segment
            self.add(source_path(path, wrapped=full_scalar), value, charge=False, prefer_specific=prefer_specific)

        def on_string(path: JSONPath, text: str, final: bool) -> None:
            nonlocal pending, pending_size, active_path, required_seen, text_scanner
            nonlocal expected_seen, expected_ok, expected_overflow, invalid_row, disk_secret
            if row_validators is not None:
                for prefix, (wanted, _validator) in row_validators.items():
                    if path[: len(prefix)] != prefix:
                        continue
                    if len(path) == len(prefix) + 1 and isinstance(path[-1], int):
                        invalid_row = True
                    elif (
                        len(path) == len(prefix) + 2
                        and isinstance(path[len(prefix)], int)
                        and isinstance(path[-1], str)
                        and path[-1] in wanted
                    ):
                        if path[-1] in (row_streamed_strings or {}).get(prefix, frozenset()):
                            length, valid = row_streamed_state.get(path, (0, True))
                            length += len(text)
                            valid = valid and all(ord(char) >= 32 for char in text)
                            if final:
                                active_rows.setdefault(path[:-1], {})[path[-1]] = (
                                    "__streamed_text__" if length and valid else ""
                                )
                                row_streamed_state.pop(path, None)
                        else:
                            fragments = row_fragments.setdefault(path, [])
                            if sum(map(len, fragments)) + len(text) > 4096:
                                invalid_row = True
                                fragments.clear()
                            else:
                                fragments.append(text)
                            if final:
                                active_rows.setdefault(path[:-1], {})[path[-1]] = "".join(fragments)
                                row_fragments.pop(path, None)
            if required_prefix is not None and path[: len(required_prefix)] == required_prefix:
                required_seen = True
            if expected_string is not None and path == expected_string[0]:
                if sum(map(len, expected_parts)) + len(text) <= max(4096, len(expected_string[1])):
                    expected_parts.append(text)
                else:
                    expected_overflow = True
                    expected_parts.clear()
                if final:
                    expected_seen += 1
                    expected_ok = (
                        expected_seen == 1 and not expected_overflow and "".join(expected_parts) == expected_string[1]
                    )
                    expected_parts.clear()
            if exclude is not None and exclude(path):
                return
            if active_path != path:
                if active_path is not None:
                    raise ValueError("JSON scalar path changed before completion")
                active_path = path
                pending = ""
                pending_size = 0
            if (
                path
                and isinstance(path[-1], (str, DiskBackedText))
                and (isinstance(path[-1], DiskBackedText) or is_secret_field_name(path[-1]))
            ):
                if disk_secret is not None:
                    disk_secret.append_text(text)
                else:
                    pending += text
                    pending_size += len(text.encode("utf-8"))
                    if pending_size > portion_limit:
                        disk_secret = DiskBackedText()
                        disk_secret.append_text(pending)
                        pending = ""
                        pending_size = 0
                if final:
                    if disk_secret is None:
                        add_segment(path, pending, full_scalar=True)
                    else:
                        disk_secret.finish()
                        # A JSON document encoded as a string needs recursive
                        # parsing; a key match alone cannot classify it.
                        value_prefix = next(disk_secret.iter_text_chunks(max_chars=64), "").lstrip()
                        if value_prefix.startswith(("{", "[")):
                            self.scan_disk_text(source_path(path), disk_secret, prefer_specific=prefer_specific)
                            disk_secret.close()
                        else:
                            before = len(self.findings)
                            self.add(
                                source_path(path, wrapped=True),
                                {path[-1]: disk_secret},
                                charge=False,
                                prefer_specific=prefer_specific,
                            )
                            if len(self.findings) == before:
                                disk_secret.close()
                        disk_secret = None
                    pending = ""
                    pending_size = 0
                    active_path = None
                return
            if text_scanner is None:
                text_scanner = DiscoveryTextStream(
                    lambda value: self.add(source_path(path), value, charge=False, prefer_specific=prefer_specific),
                    lambda reason: self.partial(source_path(path), reason),
                    portion=self.remaining,
                )
            text_scanner.feed(text)
            if final:
                text_scanner.finish()
                text_scanner.close()
                text_scanner = None
                active_path = None
                pending = ""
                pending_size = 0

        def on_primitive(item: tuple[JSONPath, Any]) -> None:
            nonlocal required_seen, invalid_row
            path, value = item
            if on_primitive_value is not None:
                on_primitive_value(path, value)
            if row_validators is not None:
                for prefix, (wanted, _validator) in row_validators.items():
                    if path[: len(prefix)] != prefix:
                        continue
                    if len(path) == len(prefix) + 1 and isinstance(path[-1], int):
                        invalid_row = True
                    elif (
                        len(path) == len(prefix) + 2
                        and isinstance(path[len(prefix)], int)
                        and isinstance(path[-1], str)
                        and path[-1] in wanted
                    ):
                        active_rows.setdefault(path[:-1], {})[path[-1]] = value
            if required_prefix is not None and path[: len(required_prefix)] == required_prefix:
                required_seen = True
            if exclude is not None and exclude(path):
                return
            if path and isinstance(path[-1], (str, DiskBackedText)):
                self.add(
                    source_path(path, wrapped=True), {path[-1]: value}, charge=False, prefer_specific=prefer_specific
                )

        def on_container(path: JSONPath, _kind: str) -> None:
            nonlocal required_seen, invalid_container, invalid_row
            if required_prefix is not None and path[: len(required_prefix)] == required_prefix:
                required_seen = True
            if required_containers is not None and path in required_containers:
                if path in containers_seen or _kind != required_containers[path]:
                    invalid_container = True
                containers_seen.add(path)
            if row_validators is not None:
                for prefix in row_validators:
                    if len(path) == len(prefix) + 1 and path[: len(prefix)] == prefix and isinstance(path[-1], int):
                        if _kind == "object":
                            active_rows[path] = {}
                        else:
                            invalid_row = True

        def on_container_end(path: JSONPath, kind: str) -> None:
            nonlocal invalid_row
            if row_validators is None or kind != "object":
                return
            for prefix, (_wanted, validator) in row_validators.items():
                if len(path) == len(prefix) + 1 and path[: len(prefix)] == prefix and isinstance(path[-1], int):
                    row = active_rows.pop(path, {})
                    if not validator(row):
                        invalid_row = True
                    elif on_row is not None:
                        on_row(path, row)

        parser = JSONScalarStream(
            on_string,
            on_primitive=on_primitive,
            on_container=on_container,
            on_container_end=on_container_end,
            deadline=self.deadline,
        )

        def on_response(status: int, response_headers: Mapping[str, str]) -> None:
            nonlocal stop_reason
            if on_status is not None:
                on_status(status)
            if status != 200:
                stop_reason = "access_denied" if status in {401, 403} else f"HTTP {status}"
                raise StopStream
            media_type = next(
                (str(value).lower() for key, value in response_headers.items() if str(key).lower() == "content-type"),
                "",
            )
            if status == 200 and "json" not in media_type:
                stop_reason = "unexpected_content_type"
                raise StopStream
            if on_response_headers is not None:
                on_response_headers(response_headers)

        def on_chunk(chunk: bytes) -> None:
            nonlocal stop_reason
            if not self.charge(len(chunk)):
                stop_reason = "discover_time" if time.monotonic() >= self.deadline else "internal_read_portion"
                raise StopStream
            try:
                parser.feed(chunk)
            except (UnicodeDecodeError, ValueError):
                stop_reason = "invalid_json"
                raise StopStream from None
            except TimeoutError:
                stop_reason = "discover_time"
                raise StopStream from None
            except OSError:
                stop_reason = "storage_failure"
                raise StopStream from None

        response = pool.request_stream(
            "GET",
            url,
            on_chunk=on_chunk,
            on_response=on_response,
            chunk_size=max(1, min(self.remaining, 64 * 1024)),
            headers={"User-Agent": "RedPosture/1.0", **headers},
            timeout=timeout,
            deadline=self.deadline,
            allow_cross_origin_redirects=False,
        )
        if disk_secret is not None:
            disk_secret.close()
        if text_scanner is not None:
            text_scanner.close()
        parser.close()
        if stop_reason:
            self.partial(source, stop_reason)
            return False
        if response.error or response.status != 200 or response.truncated:
            self.partial(
                source,
                "access_denied" if response.status in {401, 403} else response.error or f"HTTP {response.status}",
            )
            return False
        try:
            parser.finish()
        except (UnicodeDecodeError, ValueError):
            self.partial(source, "invalid_json")
            return False
        if parser.root_kind != root_kind:
            self.partial(source, "invalid_json_root")
            return False
        if not required_seen:
            self.partial(source, "required_json_field_missing")
            return False
        if expected_string is not None and not expected_ok:
            self.partial(source, "identity_mismatch")
            return False
        if required_containers is not None and (invalid_container or containers_seen != set(required_containers)):
            self.partial(source, "required_json_collection_missing")
            return False
        if invalid_row:
            self.partial(source, "invalid_json_collection_row")
            return False
        self.mark_accessible_source()
        return True

    def scan_archive_file(self, source: str, stream: Any, kind: str) -> None:
        """Inspect archive members from a seekable file or bounded spool."""

        def check_deadline() -> None:
            if not self.allowed():
                raise TimeoutError("discover_time")

        try:
            check_deadline()
            if kind not in {"zip", "tar"}:
                self.partial(source, f"unsupported_archive:{kind}")
                return
            for ordinal, (name, member) in enumerate(iter_payload_members(stream, kind, check_deadline)):
                self._scan_member_stream(
                    source, name, member, object_path=concat_discovery_text(source, f"/member/{ordinal}/file/", name)
                )
            self.mark_accessible_source()
        except NestedSchedulerCancelled:
            raise
        except (OSError, EOFError, tarfile.TarError, zipfile.BadZipFile, RuntimeError, ValueError) as exc:
            self.partial(source, f"archive_error:{type(exc).__name__}")

    def scan_base64_payload(self, source: Text, encoded: Any, *, field_name: str | None = None) -> None:
        """Scan a field whose API schema explicitly declares base64 bytes."""

        def check() -> None:
            if not self.allowed():
                raise TimeoutError("discover_time")

        if not isinstance(encoded, (str, DiskBackedText)):
            self.partial(source, "invalid_base64_value")
            return
        try:
            with decoded_base64_file(encoded, check) as (stream, _size):
                self._scan_retained_payload(source, stream, field_name=field_name)
        except (ValueError, UnicodeError):
            self.partial(source, "invalid_base64_value")
        except TimeoutError:
            self.partial(source, "discover_time")
        except OSError:
            self.partial(source, "storage_failure")

    def _scan_retained_payload(
        self,
        source: Text,
        stream: Any,
        *,
        key: Text = "",
        prefer_specific: bool = False,
        field_name: str | None = None,
        source_complete: bool = True,
    ) -> None:
        def check() -> None:
            if not self.allowed():
                raise TimeoutError("discover_time")

        def publish(item: Any, place: Text) -> None:
            self.add(place, item, charge=False, prefer_specific=prefer_specific, field_name=field_name)

        scan_payload_file(
            stream,
            source,
            publish=publish,
            partial=lambda reason: self.partial(source, reason),
            check=check,
            key=key,
            source_complete=source_complete,
        )
        self.mark_accessible_source()

    def _scan_member_stream(
        self,
        source: Text,
        name: Text,
        stream: Any,
        *,
        object_path: Text | None = None,
        charge: bool = True,
        prefer_specific: bool = False,
    ) -> None:
        """Read declared text incrementally; classify other members before scanning.

        Archive/binary/encoded and JSON prefixes retain their dedicated readers.
        A later text decoding error preserves only already completed findings.
        """
        portion = max(1, min(self.remaining, 64 * 1024))
        path = object_path or concat_discovery_text(source, "/file/", name)
        suffix = name[-32:].lower() if isinstance(name, str) else ""
        if isinstance(name, DiskBackedText):
            for part in name.iter_text_chunks():
                if not self.allowed():
                    return
                suffix = (suffix + part)[-32:].lower()
        declared_text = suffix.endswith(
            (".csv", ".env", ".txt", ".log", ".ini", ".conf", ".properties", ".toml", ".yaml", ".yml", ".xml")
        )
        early_scanner: DiscoveryTextStream | None = None
        early_decoder: Any = None
        early_probe = bytearray()
        early_decided = not declared_text

        with ExitStack() as cleanup, tempfile.SpooledTemporaryFile(max_size=min(self.remaining, 1024 * 1024)) as spool:
            decoder = codecs.getincrementaldecoder("utf-8")("strict")
            binary = False
            while self.allowed():
                chunk = stream.read(portion)
                if not chunk:
                    break
                if charge and not self.charge(len(chunk)):
                    return
                if b"\x00" in chunk:
                    binary = True
                if not binary:
                    try:
                        decoder.decode(chunk)
                    except UnicodeDecodeError:
                        binary = True
                spool.write(chunk)
                early_data = chunk
                if not early_decided:
                    needed = min(512 - len(early_probe), len(chunk))
                    early_probe.extend(chunk[:needed])
                    if len(early_probe) < 512:
                        continue
                    early_decided = True
                    probe = bytes(early_probe)
                    early_data = probe + chunk[needed:]
                    encoding = "utf-16" if probe.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
                    if not probe.startswith(
                        (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08", b"\x1f\x8b")
                    ) and not is_tar_header(probe):
                        try:
                            sample = codecs.getincrementaldecoder(encoding)("strict").decode(probe)
                        except UnicodeError:
                            sample = ""
                        explicit_text = sample and "\0" not in sample and not _json_container_prefix(sample)
                        if explicit_text and (
                            not encoded_text_prefix(sample)
                            or _scan_text(sample, "$", set(detector_names()) - {"high_entropy"})
                        ):
                            early_decoder = codecs.getincrementaldecoder(encoding)("strict")
                            early_scanner = DiscoveryTextStream(
                                lambda value: self.add(path, value, charge=False, prefer_specific=prefer_specific),
                                lambda reason: self.partial(path, reason),
                                portion=portion,
                            )
                            cleanup.callback(early_scanner.close)
                if early_scanner is not None:
                    try:
                        text = early_decoder.decode(early_data)
                        broken = re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]", text)
                        if broken is not None:
                            early_scanner.feed(text[: broken.start()])
                            self.partial(path, "binary_or_unsupported_encoding")
                            early_scanner.close()
                            early_scanner = None
                            binary = True
                        else:
                            early_scanner.feed(text)
                    except UnicodeError:
                        self.partial(path, "invalid_text_encoding")
                        if early_scanner is not None:
                            early_scanner.close()
                        early_scanner = None
            else:
                return
            if early_scanner is not None:
                try:
                    early_scanner.feed(early_decoder.decode(b"", final=True))
                    early_scanner.finish()
                    return
                except UnicodeError:
                    self.partial(path, "invalid_text_encoding")
                    early_scanner.close()
            if not binary:
                try:
                    decoder.decode(b"", final=True)
                except UnicodeDecodeError:
                    binary = True
            spool.seek(0)
            probe = spool.read(512)
            spool.seek(0)
            if binary or needs_payload_reader(probe, name):
                self._scan_retained_payload(path, spool, key=name, prefer_specific=prefer_specific)
                return
            prefix = spool.read(4096).lstrip()
            spool.seek(0)
            if encoded_text_prefix(prefix):
                encoded = DiskBackedText()
                decoded = None
                try:
                    while self.allowed() and (chunk := spool.read(portion)):
                        encoded.append_text(chunk.decode("ascii"))
                    if not self.allowed():
                        return
                    encoded.finish()
                    decoded = decode_disk_structured_blob(encoded, deadline=self.deadline)
                    if decoded is not None:
                        self.scan_disk_text(path, decoded.text, prefer_specific=prefer_specific)
                        return
                    if compressed_text_prefix(prefix):
                        self.partial(path, "invalid_encoded_blob")
                        return
                except TimeoutError:
                    self.partial("budget", "discover_time")
                    return
                except UnicodeError:
                    # A plausible first portion does not prove that the rest
                    # of an ordinary text file is encoded.
                    pass
                finally:
                    encoded.close()
                    if decoded is not None:
                        decoded.text.close()
                spool.seek(0)
            if prefix.startswith((b"{", b"[")):
                value = DiskBackedText()
                decoder = codecs.getincrementaldecoder("utf-8")("strict")
                try:
                    while self.allowed() and (chunk := spool.read(portion)):
                        value.append_text(decoder.decode(chunk))
                    if not self.allowed():
                        return
                    value.append_text(decoder.decode(b"", final=True))
                    value.finish()
                    self.scan_disk_text(path, value, prefer_specific=prefer_specific)
                finally:
                    value.close()
                return
            decoder = codecs.getincrementaldecoder("utf-8")("strict")
            scanner = DiscoveryTextStream(
                lambda value: self.add(path, value, charge=False, prefer_specific=prefer_specific),
                lambda reason: self.partial(path, reason),
                portion=self.remaining,
            )
            try:
                while self.allowed():
                    chunk = spool.read(portion)
                    if not chunk:
                        break
                    scanner.feed(decoder.decode(chunk))
                else:
                    return
                scanner.feed(decoder.decode(b"", final=True))
                scanner.finish()
            finally:
                scanner.close()

    def result(self) -> dict[str, Any]:
        if self._spool is not None:
            self._spool.finish()
            self.findings = self._spool.bounded_inline_view(max_findings=FINDING_SPOOL_THRESHOLD)
        reasons = self.partial_reasons.copy()
        if self._additional_partial_reports:
            reasons.append(f"additional_partial_reports:{self._additional_partial_reports}")
        return {
            **({"sources": self.source_manifest.result()} if self.source_manifest is not None else {}),
            "status": (
                "unavailable"
                if not self._sources and reasons and self._all_partial_access_denied
                else "partial"
                if reasons
                else "complete"
                if self._sources
                else "unavailable"
            ),
            "bytes_read": self.bytes_read,
            "bytes_inspected": self.bytes_inspected,
            "source": self.source,
            "findings": self.findings,
            "partial_reasons": reasons,
            "live_emitted": self._live_emitted,
            "emitted_fingerprints": (
                self._spool.emitted_fingerprints()
                if self.findings is self._spool and self._spool is not None
                else list(self._spool.emitted_fingerprints())
                if self._spool is not None
                else []
            ),
        }


def merge_discovery_results(*results: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """Merge value identities without discarding source locations or live provenance."""
    present = [item for item in results if isinstance(item, Mapping)]
    if not present:
        return None
    registry: OccurrenceRegistry | None = None
    reasons: list[str] = []
    source_manifest = SourceManifest()
    has_manifest = False
    for item in present:
        if isinstance(item.get("sources"), list):
            has_manifest = True
            source_manifest.merge(item["sources"])
        rows = item.get("findings")
        if not isinstance(rows, list):
            rows = []
        fingerprints = item.get("emitted_fingerprints")
        emitted_this = (
            set(fingerprints)
            if isinstance(fingerprints, list) and not isinstance(fingerprints, SpoolingFingerprints)
            else set()
        )
        finding_rows = (
            rows.iter_with_emission()
            if isinstance(rows, SpoolingFindings)
            else (
                (
                    row,
                    str(row.get("fingerprint")) in emitted_this
                    or bool(item.get("live_emitted"))
                    and not isinstance(fingerprints, list),
                )
                for row in rows
                if isinstance(row, Mapping)
            )
        )
        for finding, was_emitted in finding_rows:
            if registry is None:
                registry = OccurrenceRegistry()
            locations = finding.get("locations")
            if not isinstance(locations, list) or not locations:
                if finding.get("object_path") is not None:
                    locations = [
                        {
                            "source_kind": "content",
                            "object_path": finding["object_path"],
                            "source": finding.get("source"),
                        }
                    ]
                else:
                    locations = [{"locator_kind": "unavailable", "source_kind": "content"}]
                    if "source_locator_unavailable" not in reasons:
                        reasons.append("source_locator_unavailable")
            if (
                int(finding.get("occurrence_count") or 0) > len(locations)
                and "source_locations_incomplete" not in reasons
            ):
                reasons.append("source_locations_incomplete")
            for location in locations:
                registry.add(
                    finding,
                    location=location,
                    emitted=was_emitted,
                    merge_emission=True,
                    identity=("value", fingerprint(finding["value"])) if "value" in finding else None,
                )
        for reason in item.get("partial_reasons") or ():
            if isinstance(reason, str) and reason not in reasons:
                reasons.append(reason)
    findings: list[dict[str, Any]] = []
    emitted: list[str] = []
    if registry is not None:
        registry.finish()
        findings = registry.bounded_inline_view(max_findings=FINDING_SPOOL_THRESHOLD)
        emitted = registry.emitted_fingerprints() if findings is registry else list(registry.emitted_fingerprints())
    statuses = {str(item.get("status")) for item in present}
    sources = {str(item.get("source")) for item in present}
    status = (
        "unavailable"
        if statuses == {"unavailable"}
        else "partial"
        if reasons
        else "complete"
        if statuses == {"complete"}
        else "partial"
    )
    return {
        **({"sources": source_manifest.result()} if has_manifest else {}),
        "status": status,
        "source": next(iter(sources)) if len(sources) == 1 else "mixed",
        "bytes_read": sum(int(item.get("bytes_read") or 0) for item in present),
        "bytes_inspected": sum(int(item.get("bytes_inspected") or 0) for item in present),
        "findings": findings,
        "partial_reasons": reasons,
        "live_emitted": bool(emitted) or any(bool(item.get("live_emitted")) for item in present),
        "emitted_fingerprints": emitted,
    }


def _json_page(collector: DiscoveryCollector, getter: Any, path: str, source: str) -> list[dict[str, Any]] | None:
    category = "repository_catalog_pages" if "/repositories" in path else "project_catalog_pages"
    with collector.source_attempt(
        collector.module + "." + category, scope="selected_target_validated_JSON_responses"
    ) as evidence:

        def tracked(*args: Any) -> Any:
            result = getter(*args)
            evidence.status = result[0]
            return result

        body = collector.read(tracked, path, source)
        if body is None:
            return None
        try:
            data = json.loads(body)
        except (ValueError, UnicodeError):
            collector.partial(source, "invalid_json")
            return None
        if not isinstance(data, list) or any(not isinstance(item, Mapping) for item in data):
            collector.partial(source, "invalid_list")
            return None
        if all(isinstance(item.get("name"), str) and item["name"] for item in data):
            collector.mark_accessible_source()
            evidence.accept()
        return data


def _page_fingerprint(value: Any, collector: DiscoveryCollector) -> bytes:
    """Hash JSON content without materializing or sorting a disk-backed object.

    Object member hashes are combined commutatively, while arrays retain order.
    Type markers and member counts distinguish empty objects, arrays and scalars.
    """
    if not collector.allowed():
        raise TimeoutError("discover_time")
    digest = hashlib.blake2b(digest_size=32)
    if isinstance(value, Mapping):
        combined = 0
        count = 0
        for key, child in value.items():
            member = hashlib.blake2b(digest_size=32)
            member.update(_page_fingerprint(key, collector))
            member.update(_page_fingerprint(child, collector))
            combined = (combined + int.from_bytes(member.digest(), "big")) % (1 << 256)
            count += 1
        digest.update(b"object")
        digest.update(str(count).encode())
        digest.update(combined.to_bytes(32, "big"))
    elif isinstance(value, (list, tuple, DiskSequence)):
        digest.update(b"array")
        for child in value:
            digest.update(_page_fingerprint(child, collector))
    else:
        digest.update(b"scalar")
        for chunk in iter_json_chunks(value):
            if not collector.allowed():
                raise TimeoutError("discover_time")
            digest.update(chunk.encode("utf-8"))
    return digest.digest()


def _pages(
    collector: DiscoveryCollector,
    getter: Any,
    base: str,
    source: str,
    *,
    size: int = 100,
    stream_page: Callable[[str, str], tuple[list[dict[str, Any]] | None, dict[str, str]]] | None = None,
) -> Any:
    """Yield API list items until EOF or target deadline, detecting repeats."""
    page = 1
    processed = 0
    with DiscoveryFrontier() as seen:
        while collector.allowed():
            suffix = "&" if "?" in base else "?"
            path = f"{base}{suffix}per_page={size}&page={page}"
            cap = collector.cap(10 * 1024 * 1024)
            if not cap:
                return
            try:
                status, body, headers, error = getter(path, cap)
            except (OSError, ValueError) as exc:
                collector.partial(source, str(exc))
                return
            collector.bytes_read += len(body)
            if status in {401, 403}:
                collector.partial(source, "access_denied")
                return
            if error or status != 200:
                collector.partial(source, str(error or f"HTTP {status}"))
                return
            streamed_items: list[dict[str, Any]] | None = None
            if str(headers.get("x-redposture-truncated") or "").lower() == "true":
                if size > 1:
                    smaller = size // 2
                    while smaller > 1 and processed % smaller:
                        smaller -= 1
                    size = max(1, smaller)
                    page = processed // size + 1
                    continue
                if stream_page is None:
                    collector.partial(source, "single_item_response_truncated")
                    return
                streamed_items, headers = stream_page(path, source)
                if streamed_items is None:
                    return
            if streamed_items is not None:
                items = streamed_items
            else:
                try:
                    items = json.loads(body)
                except (ValueError, UnicodeError):
                    collector.partial(source, "invalid_json")
                    return
                if not isinstance(items, list) or any(not isinstance(item, Mapping) for item in items):
                    collector.partial(source, "invalid_list")
                    return
            try:
                identity = _page_fingerprint(items, collector).hex()
            except (OSError, ValueError) as exc:
                collector.partial(source, str(exc))
                return
            if not seen.claim(identity):
                collector.partial(source, "repeated_page")
                return
            yield from items
            processed += len(items)
            next_page = str(headers.get("x-next-page") or "").strip()
            if next_page.isdigit() and int(next_page) > page:
                page = int(next_page)
                continue
            if "x-next-page" in headers and not next_page:
                return
            if len(items) < size:
                return
            page += 1


def discover_gitlab_sources(ctx: Any, record: Mapping[str, Any], collector: DiscoveryCollector) -> None:
    """Read accessible GitLab source, CI variables, logs and artifacts."""
    from .modules.gitlab import actions

    if collector.source_manifest is None:
        collector.source_manifest = SourceManifest()
    manifest = collector.source_manifest
    for name in (
        "project_catalog",
        "branch_catalog",
        "repository_tree",
        "repository_files",
        "commit_catalog",
        "commit_diffs",
        "historical_files",
        "project_variable_catalog",
        "project_variable_values",
        "job_catalog",
        "job_traces",
        "job_artifacts",
        "group_variable_catalog",
        "group_variable_values",
        "instance_variable_catalog",
        "instance_variable_values",
        "wiki_contents",
        "snippet_contents",
        "package_files",
    ):
        manifest.declare("gitlab." + name)
    manifest.request("gitlab.project_catalog", scope="selected_or_accessible_project_metadata")
    project_catalog_events = collector.partial_events

    timeout = float(getattr(ctx.args, "timeout", 5.0) or 5.0)
    token = str(getattr(ctx.credential, "token", "") or "") or None
    headers = actions._gitlab_api_headers(token)
    use_https = bool(record.get("https"))

    def get(path: str, cap: int) -> tuple[int, bytes, dict[str, str], str | None]:
        return actions._http_request(
            str(ctx.host),
            int(ctx.port),
            "GET",
            path,
            timeout,
            use_https=use_https,
            headers=headers,
            response_size_cap=cap,
        )

    def project_get(path: str, cap: int) -> tuple[int, bytes, dict[str, str], str | None]:
        response = get(path, cap)
        if response[0] in {401, 403}:
            manifest.finish("gitlab.project_catalog", complete=False, denied=True)
        return response

    def get_range(path: str, cap: int, offset: int) -> tuple[int, bytes, dict[str, str], str | None]:
        # The synchronous GitLab HTTP adapter retains several copies of a
        # large ranged response before the collector can spool it. A 1 MiB
        # wire portion keeps peak RSS stable across larger files.
        cap = min(cap, 1024 * 1024)
        range_headers = dict(headers)
        range_headers["Range"] = f"bytes={offset}-{offset + cap - 1}"
        return actions._http_request(
            str(ctx.host),
            int(ctx.port),
            "GET",
            path,
            timeout,
            use_https=use_https,
            headers=range_headers,
            response_size_cap=cap,
        )

    def scan_ranged_content(
        path: str, source: str, *, immutable: bool = False, media_type: str = ""
    ) -> tuple[bool, int | None]:
        response_status: int | None = None

        def tracked_range(endpoint: str, cap: int, offset: int) -> tuple[int, bytes, dict[str, str], str | None]:
            nonlocal response_status
            response = get_range(endpoint, cap, offset)
            response_status = response[0]
            return response

        def on_status(status: int) -> None:
            nonlocal response_status
            response_status = status

        with tempfile.SpooledTemporaryFile(max_size=min(collector.remaining, 1024 * 1024)) as spool:
            previous_reasons = len(collector.partial_reasons)
            if _download_http_ranges(collector, tracked_range, path, source, spool, require_validator=not immutable):
                before = collector.partial_events
                _scan_spooled_blob(collector, spool, source, media_type, prefer_specific=True)
                return collector.partial_events == before, response_status
            new_reasons = collector.partial_reasons[previous_reasons:]
            range_error = new_reasons[0].removeprefix(f"{source}: ").lower() if len(new_reasons) == 1 else ""
            if range_error not in {"response_truncated", "range_unsupported"} and not any(
                marker in range_error for marker in ("timed out", "timeout", "wrong version number")
            ):
                return False, response_status
            state = getattr(ctx, "lifecycle_state", None)
            pool = getattr(state, "http", None)
            if pool is None or not callable(getattr(pool, "request_stream", None)):
                return False, response_status
            from .clients.http_api import build_http_target_url

            url = build_http_target_url(
                str(ctx.host),
                int(ctx.port),
                path,
                default_scheme="https" if use_https else "http",
                override_bound_scheme=True,
            )
            if collector.stream_http_content(
                pool,
                url,
                source,
                headers=headers,
                timeout=timeout,
                media_type=media_type,
                prefer_specific=True,
                allow_cross_origin_redirects=True,
                preserve_authorization_on_cross_origin=True,
                on_status=on_status,
            ):
                del collector.partial_reasons[previous_reasons : previous_reasons + 1]
                return True, response_status
            return False, response_status

    def stream_json_value(
        path: str, source: str, status_callback: Callable[[int], None] | None = None
    ) -> tuple[Any, dict[str, str]]:
        state = getattr(ctx, "lifecycle_state", None)
        pool = getattr(state, "http", None)
        if not callable(getattr(pool, "request_stream", None)):
            collector.partial(source, "single_item_response_truncated")
            return None, {}
        assert pool is not None
        from .clients.http_api import build_http_target_url

        document = DiskJSONDocument(deadline=collector.deadline)
        response_headers: dict[str, str] = {}
        response_status = 0

        def on_response(status: int, received: Mapping[str, str]) -> None:
            nonlocal response_status
            response_status = status
            response_headers.update(received)
            if status_callback is not None:
                status_callback(status)

        def on_chunk(chunk: bytes) -> None:
            collector.bytes_read += len(chunk)
            document.feed(chunk)

        url = build_http_target_url(str(ctx.host), int(ctx.port), path, default_scheme="https" if use_https else "http")
        try:
            response = pool.request_stream(
                "GET",
                url,
                headers=headers,
                on_response=on_response,
                on_chunk=on_chunk,
                chunk_size=65_536,
                timeout=min(timeout, max(0.001, collector.deadline - time.monotonic())),
                deadline=collector.deadline,
                allow_cross_origin_redirects=True,
                preserve_authorization_on_cross_origin=True,
            )
            if response.error or response.truncated or response_status != 200:
                collector.partial(
                    source,
                    "access_denied"
                    if response_status in {401, 403}
                    else str(response.error or f"HTTP {response_status}"),
                )
                if response_status == 200:
                    return document.partial_value(completed_arrays_only=True), response_headers
                return None, response_headers
            payload = document.finish()
        except (OSError, ValueError, UnicodeError) as exc:
            collector.partial(source, f"invalid_stream:{exc}")
            if response_status == 200:
                return document.partial_value(completed_arrays_only=True), response_headers
            return None, response_headers
        finally:
            document.close()
        return payload, response_headers

    def stream_json_page(path: str, source: str) -> tuple[list[dict[str, Any]] | None, dict[str, str]]:
        payload, response_headers = stream_json_value(path, source)
        if payload is None:
            return None, response_headers
        if not isinstance(payload, (list, SpoolingValues)):
            collector.partial(source, "invalid_list")
            return None, response_headers
        rows = SpoolingRecords()
        for item in payload:
            if not isinstance(item, Mapping):
                collector.partial(source, "invalid_item")
                return None, response_headers
            rows.append(item)
        return rows, response_headers

    def read_document(path: str, source: str) -> tuple[Mapping[str, Any] | None, int | None]:
        status: int | None = None

        def on_status(value: int) -> None:
            nonlocal status
            status = value

        cap = collector.cap()
        if not cap:
            return None, status
        try:
            status, body, received, error = get(path, cap)
            collector.bytes_read += len(body)
            if error or status != 200:
                collector.partial(source, "access_denied" if status in {401, 403} else str(error or f"HTTP {status}"))
                return None, status
            if str(received.get("x-redposture-truncated") or "").lower() == "true":
                value, _headers = stream_json_value(path, source, on_status)
            else:
                value = json.loads(body)
        except (OSError, ValueError, UnicodeError) as exc:
            collector.partial(source, f"invalid_document:{exc}")
            return None, status
        if not isinstance(value, Mapping):
            collector.partial(source, "invalid_document_object")
            return None, status
        return value, status

    def source_pages(base: str, source: str, kind: str, *, count_catalog: bool = False) -> Iterator[Mapping[str, Any]]:
        manifest.request(kind, scope="selected_projects")
        denied = False

        def tracked_get(path: str, cap: int) -> tuple[int, bytes, dict[str, str], str | None]:
            nonlocal denied
            response = get(path, cap)
            denied |= response[0] in {401, 403}
            return response

        iterator = iter(_pages(collector, tracked_get, base, source, stream_page=stream_json_page))
        complete, finished = True, False
        try:
            while True:
                before = collector.partial_events
                try:
                    item = next(iterator)
                except StopIteration:
                    complete &= collector.partial_events == before
                    finished = True
                    if complete:
                        collector.mark_accessible_source()
                    break
                complete &= collector.partial_events == before
                if count_catalog:
                    manifest.read(kind)
                yield item
        finally:
            manifest.finish(kind, complete=complete and finished, denied=denied)

    def list_projects() -> SpoolingRecords | None:

        projects = SpoolingRecords()
        seen_pages = DiscoveryFrontier()
        page_size = 100
        page = 1
        try:
            while collector.allowed():
                query = {"per_page": page_size, "page": page, "simple": "true", "order_by": "id", "sort": "asc"}
                if not token_scope:
                    query["visibility"] = "public"
                path = "/api/v4/projects?" + urlencode(query)
                cap = collector.cap(10 * 1024 * 1024)
                if not cap:
                    return projects if projects else None
                try:
                    status, body, page_headers, error = project_get(path, cap)
                except (OSError, ValueError) as exc:
                    collector.partial("projects/list", str(exc))
                    return projects if projects else None
                collector.bytes_read += len(body)
                if status in {401, 403}:
                    collector.partial("projects/list", "access_denied")
                    return projects if projects else None
                if error or status != 200:
                    collector.partial("projects/list", str(error or f"HTTP {status}"))
                    return projects if projects else None
                streamed_items: list[dict[str, Any]] | None = None
                if str(page_headers.get("x-redposture-truncated") or "").lower() == "true":
                    if page_size == 1:
                        streamed_items, page_headers = stream_json_page(path, "projects/list")
                        if streamed_items is None:
                            return projects if projects else None
                    else:
                        smaller = page_size // 2
                        while smaller > 1 and len(projects) % smaller:
                            smaller -= 1
                        page_size = max(1, smaller)
                        page = len(projects) // page_size + 1
                        continue
                if streamed_items is not None:
                    items = streamed_items
                else:
                    try:
                        items = json.loads(body)
                    except (ValueError, UnicodeError):
                        collector.partial("projects/list", "invalid_json")
                        return projects
                if not isinstance(items, list):
                    collector.partial("projects/list", "invalid_list")
                    return projects
                signature = tuple(str(item.get("id")) for item in items if isinstance(item, Mapping))
                signature_key = hashlib.sha256("\x00".join(signature).encode()).hexdigest()
                if signature and not seen_pages.claim(signature_key):
                    collector.partial("projects/list", "repeated_page")
                    return projects
                for item in items:
                    if isinstance(item, Mapping):
                        projects.append(
                            {
                                key: item[key]
                                for key in ("id", "path", "path_with_namespace", "namespace")
                                if key in item
                            }
                        )
                next_page = str(page_headers.get("x-next-page") or "").strip()
                if next_page.isdigit() and int(next_page) > page:
                    page = int(next_page)
                elif len(items) >= page_size:
                    page += 1
                else:
                    collector.add("projects/list", {"count": len(projects)}, charge=False)
                    return projects
            return projects
        finally:
            seen_pages.close()
            projects.finish()

    def pages(base: str, source: str, kind: str | None = None) -> Any:
        if kind is not None:
            return source_pages(base, source, kind, count_catalog=True)
        return _pages(
            collector,
            get,
            base,
            source,
            stream_page=stream_json_page,
        )

    def source_content(kind: str, path: str, source: str, *, immutable: bool = False, media_type: str = "") -> None:
        manifest.request(kind, scope="selected_projects")
        with collector.source_guard(manifest, kind):
            ok, status = scan_ranged_content(path, source, immutable=immutable, media_type=media_type)
            if ok:
                manifest.read(kind)
            manifest.finish(kind, complete=ok, denied=status in {401, 403})

    def source_value(kind: str, source: str, value: Any) -> None:
        manifest.request(kind, scope="selected_projects_or_parent_groups")
        if not isinstance(value, Mapping) or any(
            not isinstance(item, (str, DiskBackedText)) for item in value.values()
        ):
            collector.partial(source, "variable_value_unavailable")
            manifest.finish(kind, complete=False)
            return
        with collector.source_guard(manifest, kind):
            before = collector.partial_events
            if collector.add(source, value, charge=False, prefer_specific=True):
                manifest.read(kind)
            manifest.finish(kind, complete=collector.partial_events == before)

    token_scope = bool(token and record.get("token_valid") is True)

    projects = record.get("token_projects" if token_scope else "public_projects")
    selected = record.get("project_filters")
    filters = [str(value) for value in selected if str(value).strip()] if isinstance(selected, list) else []
    list_error = record.get("token_projects_error" if token_scope else "public_projects_error")
    fresh_projects = list_projects() if not filters else None
    if fresh_projects is not None:
        projects = fresh_projects
    elif list_error:
        collector.partial("projects", str(list_error))
    if not isinstance(projects, list):
        if not filters:
            if not any(reason.startswith("projects/list:") for reason in collector.partial_reasons):
                collector.partial("projects", "project_list_unavailable")
            manifest.finish("gitlab.project_catalog", complete=False)
            return
        projects = []
    extra_projects: list[Mapping[str, Any]] = []
    for ref in filters:
        if any(
            isinstance(project, Mapping)
            and ref in {str(project.get("id")), str(project.get("path_with_namespace")), str(project.get("path"))}
            for project in projects
        ):
            continue
        source = f"project/{ref}/details"
        body = collector.read(project_get, "/api/v4/projects/" + quote(ref, safe=""), source)
        if body is None:
            continue
        try:
            selected_project = json.loads(body)
        except (ValueError, UnicodeError):
            collector.partial(source, "invalid_json")
            continue
        if not isinstance(selected_project, Mapping) or type(selected_project.get("id")) is not int:
            collector.partial(source, "project_identity_unavailable")
            continue
        extra_projects.append(selected_project)
    manifest.read("gitlab.project_catalog", len(projects) + len(extra_projects))
    manifest.finish("gitlab.project_catalog", complete=collector.partial_events == project_catalog_events)
    group_ids: set[int] = set()
    for project in itertools.chain(projects, extra_projects):
        if not isinstance(project, Mapping) or not collector.allowed():
            continue
        project_id = project.get("id")
        if type(project_id) is not int:
            collector.partial("projects", "project_id_unavailable")
            continue
        name = str(project.get("path_with_namespace") or project_id)
        key = f"/api/v4/projects/{project_id}"
        source = f"project/{name}"
        namespace = project.get("namespace")
        if (
            isinstance(namespace, Mapping)
            and type(namespace.get("id")) is int
            and namespace.get("kind", "group") == "group"
        ):
            group_ids.add(namespace["id"])

        for branch in pages(key + "/repository/branches", source + "/branches", "gitlab.branch_catalog"):
            branch_name = str(branch.get("name") or "")
            if not branch_name:
                collector.partial(source + "/branches", "branch_name_unavailable")
                continue
            ref = quote(branch_name, safe="")
            for item in pages(
                key + f"/repository/tree?recursive=true&ref={ref}",
                source + f"/branch/{branch_name}/tree",
                "gitlab.repository_tree",
            ):
                if item.get("type") != "blob" or not isinstance(item.get("path"), str):
                    continue
                path = str(item["path"])
                file_path = key + f"/repository/files/{quote(path, safe='')}/raw?ref={ref}&lfs=true"
                source_content("gitlab.repository_files", file_path, source + f"/branch/{branch_name}/file/{path}")

        commits = pages(key + "/repository/commits?all=true", source + "/history", "gitlab.commit_catalog")
        for commit in commits:
            sha = str(commit.get("id") or "")
            if not sha:
                collector.partial(source + "/history", "commit_sha_unavailable")
                continue
            parents = commit.get("parent_ids")
            parent = str(parents[0]) if isinstance(parents, list) and parents else None
            for diff in pages(
                key + f"/repository/commits/{quote(sha, safe='')}/diff",
                source + f"/commit/{sha}/diff",
                "gitlab.commit_diffs",
            ):
                if diff.get("collapsed") or diff.get("too_large"):
                    collector.partial(source + f"/commit/{sha}", "diff_truncated")
                deleted = diff.get("deleted_file") is True
                path = str(diff.get("old_path" if deleted else "new_path") or "")
                historical_ref = parent if deleted else sha
                if not path or not historical_ref:
                    collector.partial(source + f"/commit/{sha}", "historical_path_unavailable")
                    continue
                file_path = (
                    key + f"/repository/files/{quote(path, safe='')}/raw?ref={quote(historical_ref, safe='')}&lfs=true"
                )
                source_content(
                    "gitlab.historical_files", file_path, source + f"/commit/{sha}/file/{path}", immutable=True
                )

        if token:
            for variable in pages(key + "/variables", source + "/variables", "gitlab.project_variable_catalog"):
                variable_key = str(variable.get("key") or "")
                if not variable_key or "value" not in variable:
                    collector.partial(source + "/variables", "variable_value_unavailable")
                    continue
                source_value(
                    "gitlab.project_variable_values",
                    source + f"/variable/{variable_key}",
                    {variable_key: variable["value"]},
                )

        for job in pages(key + "/jobs", source + "/jobs", "gitlab.job_catalog"):
            job_id = job.get("id")
            if type(job_id) is not int:
                collector.partial(source + "/jobs", "job_id_unavailable")
                continue
            source_content("gitlab.job_traces", key + f"/jobs/{job_id}/trace", source + f"/job/{job_id}/trace")
            artifact = job.get("artifacts_file")
            if isinstance(artifact, Mapping) and artifact.get("filename"):
                source_content(
                    "gitlab.job_artifacts",
                    key + f"/jobs/{job_id}/artifacts",
                    source + f"/job/{job_id}/artifacts",
                    media_type="zip",
                )

        from .modules.gitlab.discover import discover_project_extras

        discover_project_extras(
            collector,
            project,
            source,
            pages=source_pages,
            document=read_document,
            content=scan_ranged_content,
            manifest=manifest,
        )

    if token:
        pending = sorted(group_ids)
        visited_groups: set[int] = set()
        while pending and collector.allowed():
            group_id = pending.pop(0)
            if group_id in visited_groups:
                continue
            visited_groups.add(group_id)
            source = f"group/{group_id}/variables"
            for variable in pages(f"/api/v4/groups/{group_id}/variables", source, "gitlab.group_variable_catalog"):
                variable_key = str(variable.get("key") or "")
                if not variable_key or "value" not in variable:
                    collector.partial(source, "variable_value_unavailable")
                    continue
                source_value(
                    "gitlab.group_variable_values",
                    f"group/{group_id}/variable/{variable_key}",
                    {variable_key: variable["value"]},
                )
            group_body = collector.read(get, f"/api/v4/groups/{group_id}", f"group/{group_id}/details")
            if group_body is not None:
                try:
                    group_data = json.loads(group_body)
                except (ValueError, UnicodeError):
                    collector.partial(f"group/{group_id}/details", "invalid_json")
                    continue
                parent_id = group_data.get("parent_id") if isinstance(group_data, Mapping) else None
                if type(parent_id) is int and parent_id > 0 and parent_id not in visited_groups:
                    pending.append(parent_id)
        token_user = record.get("token_user")
        if isinstance(token_user, Mapping) and token_user.get("is_admin") is True:
            for variable in pages(
                "/api/v4/admin/ci/variables", "admin/ci/variables", "gitlab.instance_variable_catalog"
            ):
                variable_key = str(variable.get("key") or "")
                if variable_key and "value" in variable:
                    source_value(
                        "gitlab.instance_variable_values",
                        f"admin/ci/variable/{variable_key}",
                        {variable_key: variable["value"]},
                    )


def _registry_json(collector: DiscoveryCollector, getter: Any, path: str, source: str) -> Mapping[str, Any] | None:
    category = (
        "repository_catalog_pages"
        if "/_catalog" in path
        else "tag_catalog_pages"
        if "/tags/list" in path
        else "oci_manifests"
        if "/manifests/" in path
        else "component_catalog_pages"
    )
    with collector.source_attempt(
        collector.module + "." + category, scope="selected_target_validated_JSON_responses"
    ) as evidence:

        def tracked(*args: Any) -> Any:
            result = getter(*args)
            evidence.status = result[0]
            return result

        body = collector.read(tracked, path, source)
        if body is None:
            return None
        try:
            data = json.loads(body)
        except (ValueError, UnicodeError):
            collector.partial(source, "invalid_json")
            return None
        if not isinstance(data, Mapping):
            collector.partial(source, "invalid_object")
            return None
        if category == "repository_catalog_pages":
            value = data.get("repositories")
            valid = isinstance(value, list) and all(isinstance(item, str) for item in value)
        elif category == "tag_catalog_pages":
            value = data.get("tags")
            valid = value is None or isinstance(value, list) and all(isinstance(item, str) for item in value)
        elif category == "component_catalog_pages":
            valid = isinstance(data.get("items"), list)
        else:
            valid = True  # Descriptor validation is performed by the manifest traversal.
        if valid:
            collector.mark_accessible_source()
            evidence.accept()
        return data


def _catalog_incomplete(collector: DiscoveryCollector, category: str) -> None:
    if collector.source_manifest is None:
        collector.source_manifest = SourceManifest()
    kind = collector.module + "." + category
    collector.source_manifest.declare(kind)
    collector.source_manifest.finish(kind, complete=False)


@contextmanager
def _catalog_completion(collector: DiscoveryCollector, category: str) -> Iterator[None]:
    if collector.source_manifest is None:
        collector.source_manifest = SourceManifest()
    kind = collector.module + "." + category
    collector.source_manifest.declare(kind)
    before = collector.partial_events
    try:
        with collector.source_guard(collector.source_manifest, kind):
            yield
    finally:
        if collector.partial_events != before:
            _catalog_incomplete(collector, category)


def _registry_catalog(collector: DiscoveryCollector, getter: Any) -> list[str]:
    with _catalog_completion(collector, "repository_catalog_pages"):
        return _read_registry_catalog(collector, getter)


def _read_registry_catalog(collector: DiscoveryCollector, getter: Any) -> list[str]:
    repositories: list[str] = []
    seen: set[str] = set()
    last: str | None = None
    while collector.allowed():
        query = "?n=100" + ("&last=" + quote(last, safe="") if last else "")
        data = _registry_json(collector, getter, "/v2/_catalog" + query, "registry/catalog")
        if data is None:
            return repositories
        page = data.get("repositories")
        if not isinstance(page, list) or any(not isinstance(item, str) for item in page):
            collector.partial("registry/catalog", "invalid_repositories")
            return repositories
        new = [name for name in page if name not in seen]
        if page and not new:
            collector.partial("registry/catalog", "repeated_page")
            return repositories
        repositories.extend(new)
        seen.update(new)
        if len(page) < 100:
            return repositories
        last = page[-1]
    return repositories


def _registry_tags(collector: DiscoveryCollector, getter: Any, repository: str) -> list[str]:
    with _catalog_completion(collector, "tag_catalog_pages"):
        return _read_registry_tags(collector, getter, repository)


def _read_registry_tags(collector: DiscoveryCollector, getter: Any, repository: str) -> list[str]:
    tags: list[str] = []
    seen: set[str] = set()
    last: str | None = None
    encoded = quote(repository, safe="/")
    while collector.allowed():
        query = "?n=100" + ("&last=" + quote(last, safe="") if last else "")
        data = _registry_json(collector, getter, f"/v2/{encoded}/tags/list{query}", f"repository/{repository}/tags")
        if data is None:
            return tags
        page = data.get("tags") or []
        if not isinstance(page, list) or any(not isinstance(item, str) for item in page):
            collector.partial(f"repository/{repository}/tags", "invalid_tags")
            return tags
        new = [tag for tag in page if tag not in seen]
        if page and not new:
            collector.partial(f"repository/{repository}/tags", "repeated_page")
            return tags
        tags.extend(new)
        seen.update(new)
        if len(page) < 100:
            return tags
        last = page[-1]
    return tags


def _harbor_repositories(collector: DiscoveryCollector, getter: Any) -> list[str]:
    repositories: list[str] = []
    seen_repositories: set[str] = set()
    seen_project_pages: set[tuple[str, ...]] = set()
    page = 1
    while collector.allowed():
        path = f"/api/v2.0/projects?page_size=100&page={page}"
        projects = _json_page(collector, getter, path, "harbor/projects")
        if projects is None:
            return repositories
        project_signature = tuple(str(project.get("name") or "") for project in projects)
        if project_signature and project_signature in seen_project_pages:
            _catalog_incomplete(collector, "project_catalog_pages")
            collector.partial("harbor/projects", "repeated_page")
            return repositories
        seen_project_pages.add(project_signature)
        for project in projects:
            name = str(project.get("name") or "")
            if not name:
                _catalog_incomplete(collector, "project_catalog_pages")
                collector.partial("harbor/projects", "project_name_unavailable")
                continue
            seen_repo_pages: set[tuple[str, ...]] = set()
            repo_page = 1
            repo_complete = False
            while collector.allowed():
                repo_path = f"/api/v2.0/projects/{quote(name, safe='')}/repositories?page_size=100&page={repo_page}"
                items = _json_page(collector, getter, repo_path, f"harbor/project/{name}/repositories")
                if items is None:
                    break
                repo_signature = tuple(str(item.get("name") or "") for item in items)
                if repo_signature and repo_signature in seen_repo_pages:
                    collector.partial(f"harbor/project/{name}/repositories", "repeated_page")
                    break
                seen_repo_pages.add(repo_signature)
                for item in items:
                    repository = str(item.get("name") or "")
                    if repository and repository not in seen_repositories:
                        repositories.append(repository)
                        seen_repositories.add(repository)
                if len(items) < 100:
                    repo_complete = True
                    break
                repo_page += 1
            if not repo_complete:
                _catalog_incomplete(collector, "repository_catalog_pages")
        if len(projects) < 100:
            return repositories
        page += 1
    _catalog_incomplete(collector, "project_catalog_pages")
    return repositories


def _download_http_ranges(
    collector: DiscoveryCollector,
    getter: Any,
    path: str,
    source: str,
    spool: Any,
    *,
    expected_digest: str | None = None,
    require_validator: bool = False,
) -> bool:
    """Download one source in verified HTTP ranges without materializing it."""
    cap = max(1, min(collector.remaining, 8 * 1024 * 1024))
    offset = 0
    total: int | None = None
    range_calls = 0
    initial_etag: str | None = None
    digest = None
    if expected_digest:
        algorithm, separator, value = expected_digest.partition(":")
        if separator and algorithm in {"sha1", "sha256"} and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value):
            digest = hashlib.new(algorithm)
    while collector.allowed():
        try:
            status, body, headers, error = getter(path, cap, offset)
            range_calls += 1
        except (OSError, ValueError) as exc:
            collector.partial(source, str(exc))
            return False
        if error:
            collector.partial(source, str(error))
            return False
        if status in {401, 403}:
            collector.partial(source, "access_denied")
            return False
        headers = {str(key).lower(): str(value) for key, value in headers.items()}
        etag = headers.get("etag")
        if offset == 0:
            initial_etag = etag if etag and not etag.startswith("W/") else None
        elif initial_etag is not None and etag != initial_etag:
            collector.partial(source, "source_changed_during_ranges")
            return False
        if headers.get("x-redposture-truncated") == "true" or len(body) > cap:
            collector.partial(source, "response_truncated")
            return False
        if status == 200 and offset == 0:
            # A small registry may ignore Range. The HTTP transport proves
            # whether it received the whole response; never retry a 200 from
            # an offset and accidentally duplicate the first portion.
            length = headers.get("content-length")
            if length is not None and (not length.isdecimal() or int(length) != len(body)):
                collector.partial(source, "range_unsupported")
                return False
            if not collector.charge(len(body)):
                return False
            spool.write(body)
            if digest is not None:
                digest.update(body)
                if expected_digest is None or digest.hexdigest() != expected_digest.partition(":")[2]:
                    collector.partial(source, "digest_mismatch")
                    return False
            return True
        if status != 206:
            collector.partial(source, "range_unsupported" if status == 200 else f"HTTP {status}")
            return False
        match = re.fullmatch(r"bytes (\d+)-(\d+)/(\d+)", headers.get("content-range", ""))
        if match is None:
            collector.partial(source, "invalid_content_range")
            return False
        start, end, response_total = (int(part) for part in match.groups())
        if (
            start != offset
            or end < start
            or end - start + 1 != len(body)
            or len(body) > cap
            or end >= response_total
            or (total is not None and response_total != total)
        ):
            collector.partial(source, "invalid_content_range")
            return False
        if not collector.charge(len(body)):
            return False
        spool.write(body)
        if digest is not None:
            digest.update(body)
        total = response_total
        offset = end + 1
        if offset == total:
            if digest is not None and (
                expected_digest is None or digest.hexdigest() != expected_digest.partition(":")[2]
            ):
                collector.partial(source, "digest_mismatch")
                return False
            if require_validator and digest is None and initial_etag is None and range_calls > 1:
                collector.partial(source, "range_identity_unverified")
                return False
            return True
    return False


def _download_http_blob_stream(
    collector: DiscoveryCollector,
    pool: Any,
    url: str,
    source: str,
    spool: Any,
    *,
    headers: Mapping[str, str],
    timeout: float,
    expected_digest: str | None = None,
    on_status: Callable[[int], None] | None = None,
) -> bool:
    """Copy one HTTP asset directly to disk and verify its advertised digest."""
    digest = None
    if expected_digest:
        algorithm, separator, value = expected_digest.partition(":")
        if separator and algorithm in {"sha1", "sha256"} and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value):
            digest = hashlib.new(algorithm)
    status = 0

    def on_response(received_status: int, _received_headers: Mapping[str, str]) -> None:
        nonlocal status
        status = received_status
        if on_status is not None:
            on_status(received_status)

    def on_chunk(chunk: bytes) -> None:
        if status != 200:
            return
        if not collector.charge(len(chunk)):
            raise TimeoutError("discover_time")
        spool.write(chunk)
        if digest is not None:
            digest.update(chunk)

    try:
        response = pool.request_stream(
            "GET",
            url,
            headers=headers,
            on_response=on_response,
            on_chunk=on_chunk,
            chunk_size=65_536,
            timeout=min(timeout, max(0.001, collector.deadline - time.monotonic())),
            deadline=collector.deadline,
            allow_cross_origin_redirects=True,
            preserve_authorization_on_cross_origin=True,
        )
    except (OSError, ValueError) as exc:
        collector.partial(source, str(exc))
        return False
    if status in {401, 403}:
        collector.partial(source, "access_denied")
        return False
    if response.error or response.truncated or status != 200:
        collector.partial(source, str(response.error or f"HTTP {status}"))
        return False
    if digest is not None and (expected_digest is None or digest.hexdigest() != expected_digest.partition(":")[2]):
        collector.partial(source, "digest_mismatch")
        return False
    return True


def _scan_spooled_blob(
    collector: DiscoveryCollector, spool: Any, source: str, media_type: str, *, prefer_specific: bool = False
) -> None:
    size = spool.seek(0, 2)
    if not size:
        collector.mark_accessible_source()
        return
    spool.seek(0)
    prefix = spool.read(512)
    spool.seek(0)
    if "tar+" in media_type or media_type.endswith((".tar", ".tar.gz", ".tar.gzip", ".tgz")):
        # A declared layer may be an empty TAR with no nonzero header. Keep
        # that type hint while the shared reader validates the gzip trailer.
        collector._scan_retained_payload(source, spool, key="content.tar", prefer_specific=prefer_specific)
    elif needs_payload_reader(prefix, source):
        collector._scan_retained_payload(source, spool, prefer_specific=prefer_specific)
    elif "zip" in media_type:
        collector.scan_archive_file(source, spool, "zip")
    elif size <= min(collector.remaining, 1024 * 1024):
        body = spool.read()
        try:
            value = json.loads(body)
        except (ValueError, UnicodeError):
            try:
                value = body.decode("utf-8")
            except UnicodeDecodeError:
                collector.partial(source, "binary_or_non_utf8")
                return
        collector.add(source, value, charge=False, prefer_specific=prefer_specific)
    else:
        collector._scan_member_stream(
            source, "content", spool, object_path=source, charge=False, prefer_specific=prefer_specific
        )


def _scan_registry_blob(
    collector: DiscoveryCollector,
    getter: Any,
    repository: str,
    digest: str,
    source: str,
    media_type: str,
    *,
    range_getter: Any | None = None,
) -> None:
    category = next((name for name in ("config", "layer", "artifact") if "/" + name + "/" in source), "blob")
    with collector.source_attempt(
        collector.module + ".oci_" + category, scope="selected_images_decoded_payloads"
    ) as evidence:

        def tracked(*args: Any) -> Any:
            result = getter(*args)
            evidence.status = result[0]
            return result

        def tracked_range(*args: Any) -> Any:
            assert range_getter is not None
            result = range_getter(*args)
            evidence.status = result[0]
            return result

        _read_registry_blob(
            collector,
            tracked,
            repository,
            digest,
            source,
            media_type,
            range_getter=tracked_range if range_getter is not None else None,
            evidence=evidence,
        )


def _read_registry_blob(
    collector: DiscoveryCollector,
    getter: Any,
    repository: str,
    digest: str,
    source: str,
    media_type: str,
    *,
    range_getter: Any | None,
    evidence: SourceRead,
) -> None:
    path = f"/v2/{quote(repository, safe='/')}/blobs/{quote(digest, safe=':')}"
    if range_getter is not None:
        with tempfile.SpooledTemporaryFile(max_size=min(collector.remaining, 1024 * 1024)) as spool:
            if _download_http_ranges(collector, range_getter, path, source, spool, expected_digest=digest):
                _scan_spooled_blob(collector, spool, source, media_type)
                evidence.accept()
        return
    # This legacy no-Range path is used only when the streaming adapter is
    # absent. Never turn the removed CLI byte budget into an unbounded HTTP
    # response allocation; the normal registry path uses verified ranges.
    body = collector.read(getter, path, source)
    if body is None:
        return
    if "tar" in media_type or (len(body) > 2 and body[:2] == b"\x1f\x8b"):
        collector.scan_archive(source, body, "tar")
    elif "zip" in media_type or body.startswith(b"PK\x03\x04"):
        collector.scan_archive(source, body, "zip")
    else:
        try:
            value = json.loads(body)
        except (ValueError, UnicodeError):
            try:
                value = body.decode("utf-8")
            except UnicodeDecodeError:
                collector.partial(source, "binary_or_non_utf8")
                return
        collector.add(source, value, charge=False)
    evidence.accept()


def _scan_registry_manifest(
    collector: DiscoveryCollector,
    getter: Any,
    repository: str,
    reference: str,
    seen_blobs: set[tuple[str, str]],
    *,
    depth: int = 0,
    range_getter: Any | None = None,
) -> None:
    source = f"image/{repository}/{reference}"

    def invalid(reason: str) -> None:
        collector.partial(source, reason)
        if collector.source_manifest is not None:
            collector.source_manifest.declare(collector.module + ".oci_manifests")
            collector.source_manifest.finish(collector.module + ".oci_manifests", complete=False)

    if depth > 4:
        invalid("manifest_depth_limit")
        return
    path = f"/v2/{quote(repository, safe='/')}/manifests/{quote(reference, safe=':')}"
    manifest = _registry_json(collector, getter, path, source + "/manifest")
    if manifest is None:
        return
    collector.add(source + "/manifest", manifest, charge=False)
    children = manifest.get("manifests")
    if isinstance(children, list):
        for child in children:
            digest = str(child.get("digest") or "") if isinstance(child, Mapping) else ""
            if digest:
                _scan_registry_manifest(
                    collector, getter, repository, digest, seen_blobs, depth=depth + 1, range_getter=range_getter
                )
            else:
                invalid("invalid_child_manifest")
        return
    for category, descriptors in (
        ("config", [manifest.get("config")]),
        ("layer", manifest.get("layers") or []),
        ("artifact", manifest.get("blobs") or []),
    ):
        if not isinstance(descriptors, list):
            invalid(f"invalid_{category}_descriptors")
            continue
        for descriptor in descriptors:
            if not isinstance(descriptor, Mapping) or not descriptor.get("digest"):
                invalid(f"invalid_{category}_descriptor")
                continue
            digest = str(descriptor["digest"])
            if (repository, digest) in seen_blobs:
                continue
            seen_blobs.add((repository, digest))
            _scan_registry_blob(
                collector,
                getter,
                repository,
                digest,
                source + f"/{category}/{digest}",
                str(descriptor.get("mediaType") or ""),
                range_getter=range_getter,
            )


def _discover_nexus_assets(
    collector: DiscoveryCollector,
    getter: Any,
    ctx: Any,
    *,
    range_getter: Any | None = None,
    stream_headers: Mapping[str, str] | None = None,
) -> None:
    with collector.source_attempt("nexus.repository_catalog_pages", scope="validated_JSON_responses") as evidence:

        def tracked(*args: Any) -> Any:
            result = getter(*args)
            evidence.status = result[0]
            return result

        repositories = collector.read(tracked, "/service/rest/v1/repositories", "nexus/repositories")
        if repositories is None:
            return
        try:
            items = json.loads(repositories)
        except (ValueError, UnicodeError):
            collector.partial("nexus/repositories", "invalid_json")
            return
        if not isinstance(items, list):
            collector.partial("nexus/repositories", "invalid_list")
            return
        if all(isinstance(item, Mapping) and item.get("name") for item in items):
            collector.mark_accessible_source()
            evidence.accept()
    selected_repo = str(getattr(ctx.args, "repository", "") or "")
    selected_asset = str(getattr(ctx.args, "asset", "") or "")

    def asset_selected(asset: Mapping[str, Any]) -> bool:
        path = str(asset.get("path") or "")
        url = str(asset.get("downloadUrl") or "")
        return not selected_asset or selected_asset == url or selected_asset.lstrip("/") == path.lstrip("/")

    matched_asset = False
    for item in items:
        if not isinstance(item, Mapping) or not item.get("name"):
            collector.partial("nexus/repositories", "invalid_repository")
            continue
        name = str(item["name"])
        if selected_repo and selected_repo != name:
            continue
        if not selected_asset:
            collector.add(f"nexus/repository/{name}/metadata", item, charge=False)
        continuation: str | None = None
        seen_tokens: set[str] = set()
        catalog_complete = False
        while collector.allowed():
            query = {"repository": name}
            if continuation:
                query["continuationToken"] = continuation
            path = "/service/rest/v1/components?" + urlencode(query)
            page = _registry_json(collector, getter, path, f"nexus/repository/{name}/components")
            if page is None:
                break
            components = page.get("items")
            if not isinstance(components, list):
                _catalog_incomplete(collector, "component_catalog_pages")
                collector.partial(f"nexus/repository/{name}/components", "invalid_items")
                break
            for component in components:
                if not isinstance(component, Mapping):
                    _catalog_incomplete(collector, "component_catalog_pages")
                    collector.partial(f"nexus/repository/{name}/components", "invalid_component")
                    continue
                assets = component.get("assets") or []
                if not isinstance(assets, list):
                    _catalog_incomplete(collector, "component_catalog_pages")
                    collector.partial(f"nexus/repository/{name}/assets", "invalid_assets")
                    continue
                if selected_asset:
                    assets = [asset for asset in assets if isinstance(asset, Mapping) and asset_selected(asset)]
                    if not assets:
                        continue
                collector.add(
                    f"nexus/repository/{name}/component/metadata",
                    {key: value for key, value in component.items() if key != "assets"},
                    charge=False,
                )
                for asset in assets:
                    if not isinstance(asset, Mapping):
                        _catalog_incomplete(collector, "component_catalog_pages")
                        collector.partial(f"nexus/repository/{name}/assets", "invalid_asset")
                        continue
                    asset_path = str(asset.get("path") or "")
                    url = str(asset.get("downloadUrl") or "")
                    if not asset_selected(asset):
                        continue
                    matched_asset = True
                    parsed = urlsplit(url)
                    if parsed.scheme not in {"", "http", "https"} or not parsed.path.startswith("/"):
                        collector.partial(f"nexus/repository/{name}/asset/{asset_path}", "download_url_unavailable")
                        continue
                    # Nexus may advertise its internal hostname behind a proxy.
                    # Route only the path through the already confirmed target;
                    # never follow the advertised host or send credentials there.
                    source = f"nexus/repository/{name}/asset/{asset_path.lstrip('/')}"
                    asset_endpoint = parsed.path + ("?" + parsed.query if parsed.query else "")
                    with collector.source_attempt(
                        "nexus.asset_contents", scope="selected_assets_decoded_payloads"
                    ) as evidence:

                        def tracked_getter(*args: Any) -> Any:
                            result = getter(*args)
                            evidence.status = result[0]
                            return result

                        def tracked_range(*args: Any) -> Any:
                            assert range_getter is not None
                            result = range_getter(*args)
                            evidence.status = result[0]
                            return result

                        if range_getter is None:
                            body = collector.read(tracked_getter, asset_endpoint, source)
                            if body is None:
                                continue
                            with tempfile.SpooledTemporaryFile(max_size=min(collector.remaining, 1024 * 1024)) as spool:
                                spool.write(body)
                                _scan_spooled_blob(collector, spool, source, asset_path, prefer_specific=True)
                                evidence.accept()
                        else:
                            checksums = asset.get("checksum")
                            digest = None
                            if isinstance(checksums, Mapping):
                                for algorithm in ("sha256", "sha1"):
                                    value = checksums.get(algorithm)
                                    if isinstance(value, str) and value:
                                        digest = f"{algorithm}:{value.lower()}"
                                        break
                            with tempfile.SpooledTemporaryFile(max_size=min(collector.remaining, 1024 * 1024)) as spool:
                                state = getattr(ctx, "lifecycle_state", None)
                                pool = getattr(state, "http", None)
                                if callable(getattr(pool, "request_stream", None)):
                                    from .clients.http_api import build_http_target_url

                                    endpoint_path = str(getattr(state, "base_path", "") or "") + asset_endpoint
                                    asset_url = build_http_target_url(
                                        str(getattr(state, "host", None) or ctx.host),
                                        int(getattr(state, "port", None) or ctx.port),
                                        endpoint_path,
                                        default_scheme=str(
                                            getattr(state, "scheme", None)
                                            or ("https" if int(ctx.port) in {443, 5001} else "http")
                                        ),
                                    )
                                    downloaded = _download_http_blob_stream(
                                        collector,
                                        pool,
                                        asset_url,
                                        source,
                                        spool,
                                        headers=stream_headers or {},
                                        timeout=float(getattr(ctx.args, "timeout", 5.0) or 5.0),
                                        expected_digest=digest,
                                        on_status=lambda status: setattr(evidence, "status", status),
                                    )
                                else:
                                    downloaded = _download_http_ranges(
                                        collector,
                                        tracked_range,
                                        asset_endpoint,
                                        source,
                                        spool,
                                        expected_digest=digest,
                                        require_validator=True,
                                    )
                                if downloaded:
                                    _scan_spooled_blob(collector, spool, source, asset_path, prefer_specific=True)
                                    evidence.accept()
            next_token = str(page.get("continuationToken") or "")
            if not next_token:
                catalog_complete = True
                break
            if next_token in seen_tokens:
                collector.partial(f"nexus/repository/{name}/components", "repeated_page")
                break
            seen_tokens.add(next_token)
            continuation = next_token
        if not catalog_complete:
            _catalog_incomplete(collector, "component_catalog_pages")
    if selected_asset and not matched_asset:
        collector.partial("nexus/asset", "selector_not_found")


def discover_registry_sources(ctx: Any, record: Mapping[str, Any], collector: DiscoveryCollector, product: str) -> None:
    """Read accessible Nexus assets and OCI manifests/configs/layers."""
    from .modules.registry import actions

    if collector.source_manifest is None:
        collector.source_manifest = SourceManifest()
    for name in (
        "oci_endpoint",
        "repository_catalog_pages",
        "tag_catalog_pages",
        "oci_manifests",
        "oci_config",
        "oci_layer",
        "oci_artifact",
    ):
        collector.source_manifest.declare(product + "." + name)
    if product == "harbor":
        collector.source_manifest.declare(product + ".project_catalog_pages")
    if product == "nexus":
        collector.source_manifest.declare(product + ".component_catalog_pages")
        collector.source_manifest.declare(product + ".asset_contents")

    timeout = float(getattr(ctx.args, "timeout", 5.0) or 5.0)
    anonymous = record.get("status") in {"open_no_auth", "invalid_credentials_anonymous"}
    credential = ctx.credential
    headers = actions._auth_headers(
        None if anonymous else credential.username,
        None if anonymous else credential.password,
        None if anonymous else credential.token,
    )

    def get(path: str, cap: int) -> tuple[int, bytes, dict[str, str], str | None]:
        request_headers = dict(headers)
        if "/manifests/" in path:
            request_headers["Accept"] = actions._REGISTRY_MANIFEST_ACCEPT
        return actions._http_request(
            str(ctx.host),
            int(ctx.port),
            "GET",
            path,
            timeout,
            headers=request_headers,
            response_size_cap=cap,
        )

    def get_range(path: str, cap: int, start: int) -> tuple[int, bytes, dict[str, str], str | None]:
        request_headers = dict(headers)
        request_headers["Range"] = f"bytes={start}-{start + cap - 1}"
        return actions._http_request(
            str(ctx.host),
            int(ctx.port),
            "GET",
            path,
            timeout,
            headers=request_headers,
            response_size_cap=cap,
        )

    if product == "nexus" and record.get("is_nexus") is True:
        _discover_nexus_assets(collector, get, ctx, range_getter=get_range, stream_headers=headers)
        # Nexus' REST endpoint identifies itself as a registry product even when
        # its OCI connector is hosted on another port. A 404 /v2 probe proves
        # this address cannot serve OCI manifests or blobs.
        if record.get("probe_status") == 404:
            collector.source_manifest.request(product + ".oci_endpoint", scope="this_address_detect_probe")
            collector.source_manifest.finish(product + ".oci_endpoint", complete=False, unsupported=True)
            if getattr(ctx.args, "image", None) or getattr(ctx.args, "tag", None):
                collector.partial("nexus/oci", "OCI endpoint unavailable on this address")
            return
    if record.get("is_registry") is not True:
        collector.source_manifest.request(product + ".oci_endpoint", scope="this_address_detect_probe")
        collector.source_manifest.finish(product + ".oci_endpoint", complete=False, unsupported=True)
        return
    collector.source_manifest.request(product + ".oci_endpoint", scope="this_address_detect_probe")
    collector.source_manifest.finish(product + ".oci_endpoint", complete=True)
    image = str(getattr(ctx.args, "image", "") or "")
    repository = str(getattr(ctx.args, "repository", "") or "")
    tag = str(getattr(ctx.args, "tag", "") or "")
    if image:
        parsed_repo, parsed_ref = actions._split_image_reference(image)
        targets = {parsed_repo: [parsed_ref]} if parsed_repo and parsed_ref else {}
        if not targets:
            collector.partial("registry/image", "invalid_image_selector")
    else:
        if repository:
            repositories = [repository]
        elif product == "harbor":
            repositories = _harbor_repositories(collector, get)
            if not repositories:
                repositories = _registry_catalog(collector, get)
        else:
            repositories = _registry_catalog(collector, get)
        targets = {repo: [tag] if tag else _registry_tags(collector, get, repo) for repo in repositories}
    seen_blobs: set[tuple[str, str]] = set()
    for repo, references in targets.items():
        for reference in references:
            if not collector.allowed():
                return
            _scan_registry_manifest(collector, get, repo, reference, seen_blobs, range_getter=get_range)


_PORTAINER_DISCOVERY_EXCLUDED = frozenset(
    {
        "GraphDriver",
        "HostnamePath",
        "HostsPath",
        "LogPath",
        "ResolvConfPath",
        "ShmPath",
    }
)


class _PortainerProjection:
    """A read-only scanner view; preserve the source owner without copying it."""

    def __init__(self, source: Any, parent: str) -> None:
        self.source = source
        self.parent = parent

    @property
    def byte_length(self) -> int:
        # This is an upper bound; exact inspected bytes are counted by scanning.
        return self.source.byte_length

    @property
    def reference_owner(self) -> Any:
        return self

    @property
    def reference_locator(self) -> None:
        return None

    @property
    def reference_id(self) -> str:
        return f"portainer-projection:{id(self)}"

    def view(self, locator: Any) -> Any:
        if locator is not None:
            raise KeyError(locator)
        return self


class _PortainerMappingView(_PortainerProjection, DiskMapping):
    def _included(self, key: Any) -> bool:
        return key not in _PORTAINER_DISCOVERY_EXCLUDED and not (self.parent == "TLSInfo" and key == "TrustRoot")

    def __iter__(self):
        return (key for key in self.source if self._included(key))

    def __len__(self) -> int:
        excluded = sum(key in self.source for key in _PORTAINER_DISCOVERY_EXCLUDED)
        if self.parent == "TLSInfo" and "TrustRoot" in self.source:
            excluded += 1
        return len(self.source) - excluded

    def __getitem__(self, key: Any) -> Any:
        if not self._included(key):
            raise KeyError(key)
        return _portainer_discovery_view(self.source[key], parent="TLSInfo" if key == "TLSInfo" else "")


class _PortainerSequenceView(_PortainerProjection, DiskSequence):
    def __len__(self) -> int:
        return len(self.source)

    def __iter__(self):
        return (_portainer_discovery_view(item, parent=self.parent) for item in self.source)

    def __getitem__(self, index):
        if isinstance(index, slice):
            return [_portainer_discovery_view(item, parent=self.parent) for item in self.source[index]]
        return _portainer_discovery_view(self.source[index], parent=self.parent)


class _PortainerConfigMetadataView(_PortainerProjection, DiskMapping):
    """Exclude encoded Data while retaining every metadata field lazily."""

    def __iter__(self):
        return (key for key in self.source if self.parent != "Spec" or key != "Data")

    def __len__(self) -> int:
        return len(self.source) - int(self.parent == "Spec" and "Data" in self.source)

    def __getitem__(self, key: Any) -> Any:
        if self.parent == "Spec" and key == "Data":
            raise KeyError(key)
        value = self.source[key]
        if not self.parent and key == "Spec" and isinstance(value, Mapping):
            if isinstance(value, DiskContainer):
                return _PortainerConfigMetadataView(value, "Spec")
            return {name: item for name, item in value.items() if name != "Data"}
        return value


def _portainer_discovery_view(value: Any, *, parent: str = "") -> Any:
    """Keep exposed configuration while omitting local paths and public CA data."""
    if isinstance(value, DiskContainer):
        if isinstance(value, Mapping):
            return _PortainerMappingView(value, parent)
        if isinstance(value, list):
            return _PortainerSequenceView(value, parent)
    if isinstance(value, Mapping):
        return {
            key: _portainer_discovery_view(item, parent="TLSInfo" if key == "TLSInfo" else "")
            for key, item in value.items()
            if key not in _PORTAINER_DISCOVERY_EXCLUDED and not (parent == "TLSInfo" and key == "TrustRoot")
        }
    if isinstance(value, list):
        return [_portainer_discovery_view(item, parent=parent) for item in value]
    return value


def discover_portainer_sources(
    ctx: Any, record: Mapping[str, Any], inventory: Mapping[str, Any], collector: DiscoveryCollector
) -> None:
    """Read visible stack files and selected Docker environment data via Portainer."""
    from . import web_panels
    from .clients.http_session import HttpSessionPool
    from .modules.portainer.discover import scan_container_logs

    if collector.source_manifest is None:
        collector.source_manifest = SourceManifest()
    manifest = collector.source_manifest
    for name in (
        "container_logs",
        "environment_metadata",
        "container_catalog",
        "stack_catalog",
        "stack_files",
        "container_inspect",
        "swarm_config_catalog",
        "swarm_config_contents",
        "swarm_secret_metadata",
    ):
        manifest.declare("portainer." + name)
    manifest.declare("portainer.swarm_secret_values", implemented=False)

    ui_value = record.get("ui")
    ui = ui_value if isinstance(ui_value, Mapping) else {}
    base = str(ui.get("endpoint") or "")
    if not base:
        collector.partial("portainer", "panel_endpoint_unavailable")
        return
    headers: dict[str, str] = {}
    if ui.get("session_token"):
        headers["Authorization"] = "Bearer " + str(ui["session_token"])
    if ui.get("session_api_key"):
        headers["X-API-Key"] = str(ui["session_api_key"])
    if ui.get("session_cookie"):
        headers["Cookie"] = str(ui["session_cookie"])
    timeout = float(getattr(ctx.args, "timeout", 5.0) or 5.0)
    with closing(
        HttpSessionPool(
            timeout=timeout,
            insecure=not bool(getattr(ctx.args, "secure", False)),
            proxy=getattr(ctx.args, "_proxy_config", None),
            retries=0,
        )
    ) as pool:
        last_status = 0

        @contextmanager
        def source_attempt(kind: str, scope: str = "selected_environments") -> Iterator[Callable[[int], None]]:
            nonlocal last_status
            manifest.request(kind, scope=scope)
            before = collector.partial_events
            last_status = 0
            read_count: int | None = None
            finished = False

            def acknowledge(count: int = 1) -> None:
                nonlocal read_count
                read_count = count

            try:
                yield acknowledge
                finished = True
            except (NestedSchedulerCancelled, KeyboardInterrupt):
                collector.partial(kind, "cancelled")
                raise
            finally:
                complete = finished and read_count is not None and collector.partial_events == before
                if complete:
                    manifest.read(kind, read_count or 0)
                manifest.finish(kind, complete=complete, denied=last_status in {401, 403})

        def remember_status(status: int) -> None:
            nonlocal last_status
            last_status = status

        def get(path: str, cap: int) -> tuple[int, bytes, dict[str, str], str | None]:
            response = web_panels._get(
                pool,
                base,
                path,
                headers=headers,
                response_size_cap=cap,
                timeout=min(timeout, max(0.001, collector.deadline - time.monotonic())),
            )
            remember_status(response.status)
            response_headers = {str(key).lower(): str(value) for key, value in response.headers.items()}
            if response.truncated:
                response_headers["x-redposture-truncated"] = "true"
            return response.status, response.body, response_headers, response.error

        streamed = object()
        streamed_secrets = object()
        swarm_unavailable = object()

        def raw_json(
            path: str,
            source: str,
            *,
            stream_large: bool = False,
            stream_document: bool = False,
            stream_array: bool = False,
            swarm_only: bool = False,
            stream_catalog: str | None = None,
        ) -> Any:
            if stream_document:
                cap = collector.cap(10 * 1024 * 1024)
                if not cap:
                    return None
                response = web_panels._get(
                    pool,
                    base,
                    path,
                    headers=headers,
                    response_size_cap=cap,
                    timeout=min(timeout, max(0.001, collector.deadline - time.monotonic())),
                )
                remember_status(response.status)
                if response.truncated and response.status == 200 and not response.error:
                    document = DiskJSONDocument()
                    stream_status = 0

                    def retained_array() -> Any:
                        if not stream_array:
                            return None
                        completed = document.completed_array()
                        return completed if completed else None

                    def on_response(status: int, _received: Mapping[str, str]) -> None:
                        nonlocal stream_status
                        stream_status = status
                        remember_status(status)

                    def on_chunk(chunk: bytes) -> None:
                        if stream_status != 200:
                            return
                        if not collector.allowed():
                            raise TimeoutError("discover_time")
                        collector.bytes_read += len(chunk)
                        document.feed(chunk)

                    try:
                        streamed_response = pool.request_stream(
                            "GET",
                            base.rstrip("/") + path,
                            headers=headers,
                            on_response=on_response,
                            on_chunk=on_chunk,
                            chunk_size=65_536,
                            timeout=min(timeout, max(0.001, collector.deadline - time.monotonic())),
                            deadline=collector.deadline,
                        )
                        if stream_status in {401, 403}:
                            collector.partial(source, "access_denied")
                            return None
                        if streamed_response.error or streamed_response.truncated or stream_status != 200:
                            collector.partial(source, str(streamed_response.error or f"HTTP {stream_status}"))
                            return retained_array()
                        result = document.finish()
                    except (OSError, ValueError, UnicodeError) as exc:
                        collector.partial(source, f"invalid_stream:{exc}")
                        return retained_array()
                    if not isinstance(result, list if stream_array else Mapping):
                        collector.partial(source, "invalid_json")
                        return None
                    return result
                if response.error or response.status != 200:
                    collector.partial(
                        source,
                        "access_denied"
                        if response.status in {401, 403}
                        else response.error or f"HTTP {response.status}",
                    )
                    return None
                if not collector.charge(len(response.body)):
                    return None
                try:
                    result = json.loads(response.body)
                except (ValueError, UnicodeError):
                    collector.partial(source, "invalid_json")
                    return None
                if not isinstance(result, list if stream_array else Mapping):
                    collector.partial(source, "invalid_json")
                    return None
                return result
            if stream_large:
                cap = collector.cap(10 * 1024 * 1024)
                if not cap:
                    return None
                response = web_panels._get(
                    pool,
                    base,
                    path,
                    headers=headers,
                    response_size_cap=cap,
                    timeout=min(timeout, max(0.001, collector.deadline - time.monotonic())),
                )
                remember_status(response.status)
                if response.truncated:
                    excluded = {"GraphDriver", "HostnamePath", "HostsPath", "LogPath", "ResolvConfPath", "ShmPath"}
                    inspected_tty: bool | None = None

                    def inspect_primitive(parts: JSONPath, value: Any) -> None:
                        nonlocal inspected_tty
                        if parts == ("Config", "Tty") and type(value) is bool:
                            inspected_tty = value

                    def skip(path_parts: JSONPath) -> bool:
                        return any(part in excluded for part in path_parts if isinstance(part, str)) or any(
                            first == "TLSInfo" and second == "TrustRoot"
                            for first, second in zip(path_parts, path_parts[1:], strict=False)
                        )

                    collector.stream_json_scalars(
                        pool,
                        base.rstrip("/") + path,
                        source,
                        headers=headers,
                        timeout=timeout,
                        root_kind="object",
                        exclude=skip,
                        prefer_specific=True,
                        on_status=remember_status,
                        on_primitive_value=inspect_primitive,
                    )
                    if inspected_tty is not None:
                        return {"Config": {"Tty": inspected_tty}}
                    return streamed
                if response.error or response.status != 200:
                    collector.partial(
                        source,
                        "access_denied"
                        if response.status in {401, 403}
                        else response.error or f"HTTP {response.status}",
                    )
                    return None
                if not collector.charge(len(response.body)):
                    return None
                try:
                    return json.loads(response.body)
                except (ValueError, UnicodeError):
                    collector.partial(source, "invalid_json")
                    return None
            if swarm_only:
                cap = collector.cap(10 * 1024 * 1024)
                if not cap:
                    return None
                swarm_response = get(path, cap)
                if swarm_response[0] == 503 and swarm_response[3] is None:
                    # Docker returns 503 for Swarm APIs on a standalone
                    # engine. Confirm the engine state before classifying it.
                    return swarm_unavailable
                if stream_catalog and swarm_response[2].get("x-redposture-truncated") == "true":
                    if stream_catalog == "configs":
                        rows = SpoolingRecords()

                        def record_config(row: Mapping[str, Any]) -> bool:
                            config_id = row.get("ID") or row.get("Id")
                            if not isinstance(config_id, str) or not config_id:
                                return False
                            rows.append({"ID": config_id})
                            return True

                        complete = collector.stream_json_scalars(
                            pool,
                            base.rstrip("/") + path,
                            source,
                            headers=headers,
                            timeout=timeout,
                            root_kind="array",
                            exclude=lambda _path: True,
                            required_containers={(): "array"},
                            row_validators={(): (frozenset({"ID", "Id"}), record_config)},
                            on_status=remember_status,
                        )
                        if not complete and not rows:
                            return None
                        return rows
                    if stream_catalog == "secrets":
                        secret_count = 0

                        def record_secret(_row: Mapping[str, Any]) -> bool:
                            nonlocal secret_count
                            secret_count += 1
                            return True

                        complete = collector.stream_json_scalars(
                            pool,
                            base.rstrip("/") + path,
                            source,
                            headers=headers,
                            timeout=timeout,
                            root_kind="array",
                            required_containers={(): "array"},
                            row_validators={(): (frozenset(), record_secret)},
                            on_status=remember_status,
                            prefer_specific=True,
                        )
                        if not complete and not secret_count:
                            return None
                        return streamed_secrets if secret_count else []
                body = collector.read(lambda _path, _cap: swarm_response, path, source)
            else:
                body = collector.read(get, path, source)
            if body is None:
                return None
            try:
                return json.loads(body)
            except (ValueError, UnicodeError):
                collector.partial(source, "invalid_json")
                return None

        def get_json(path: str, source: str, **kwargs: Any) -> Any:
            if path == "/api/stacks":
                kind, array = "portainer.stack_catalog", True
            elif path.endswith("/json"):
                kind, array = "portainer.container_inspect", False
            elif path.endswith("/configs"):
                kind, array = "portainer.swarm_config_catalog", True
            elif path.endswith("/secrets"):
                kind, array = "portainer.swarm_secret_metadata", True
            else:
                return raw_json(path, source, **kwargs)
            with source_attempt(kind) as acknowledge:
                result = raw_json(path, source, **kwargs)
                if result is streamed or result is streamed_secrets:
                    acknowledge(1)  # One fully parsed wire source, catalog row count may be disk-backed.
                elif isinstance(result, list if array else Mapping):
                    acknowledge(len(result) if isinstance(result, list) else 1)
                elif result is not None and result is not swarm_unavailable:
                    collector.partial(source, "invalid_list" if array else "invalid_inspect")
                return result

        environments = inventory.get("environments")
        env_records = environments.get("records") if isinstance(environments, Mapping) else None
        manifest.request("portainer.environment_metadata", scope="selected_inventory")
        if not isinstance(env_records, list):
            manifest.finish("portainer.environment_metadata", complete=False)
            collector.partial("portainer/environments", "inventory_unavailable")
            return
        if not env_records:
            collector.partial("portainer/environments", "no_accessible_environments (access_denied_or_none)")
        env_complete = (
            isinstance(environments, Mapping) and not environments.get("partial") and not environments.get("status")
        )
        manifest.read("portainer.environment_metadata", len(env_records))
        manifest.finish("portainer.environment_metadata", complete=bool(env_complete))
        for environment in env_records:
            if isinstance(environment, Mapping):
                collector.add(
                    f"portainer/environment/{environment.get('Id')}/metadata", environment, prefer_specific=True
                )

        stacks = get_json("/api/stacks", "portainer/stacks", stream_document=True, stream_array=True)
        if isinstance(stacks, list):
            for stack in stacks:
                if not isinstance(stack, Mapping) or type(stack.get("Id")) is not int:
                    collector.partial("portainer/stacks", "invalid_stack")
                    continue
                stack_id = stack["Id"]
                collector.add(f"portainer/stack/{stack_id}/metadata", stack, charge=False, prefer_specific=True)
                stack_path = f"/api/stacks/{stack_id}/file"
                stack_source = f"portainer/stack/{stack_id}/file"
                with source_attempt("portainer.stack_files") as acknowledge:
                    stack_cap = collector.cap(10 * 1024 * 1024)
                    if stack_cap:
                        stack_response = web_panels._get(
                            pool,
                            base,
                            stack_path,
                            headers=headers,
                            response_size_cap=stack_cap,
                            timeout=min(timeout, max(0.001, collector.deadline - time.monotonic())),
                        )
                        remember_status(stack_response.status)
                        if stack_response.truncated:
                            collector.stream_json_text_field(
                                pool,
                                base.rstrip("/") + stack_path,
                                stack_source,
                                "StackFileContent",
                                headers=headers,
                                timeout=timeout,
                                prefer_specific=True,
                            )
                        elif stack_response.error or stack_response.status != 200:
                            collector.partial(
                                stack_source,
                                "access_denied"
                                if stack_response.status in {401, 403}
                                else stack_response.error or f"HTTP {stack_response.status}",
                            )
                        elif collector.charge(len(stack_response.body)):
                            try:
                                stack_file = json.loads(stack_response.body)
                            except (ValueError, UnicodeError):
                                collector.partial(stack_source, "invalid_json")
                            else:
                                if isinstance(stack_file, Mapping) and isinstance(
                                    stack_file.get("StackFileContent"), str
                                ):
                                    collector.add(
                                        stack_source, stack_file["StackFileContent"], charge=False, prefer_specific=True
                                    )
                                else:
                                    collector.partial(stack_source, "file_content_unavailable")
                    if stack_cap:
                        acknowledge(1)
        elif stacks is not None:
            collector.partial("portainer/stacks", "invalid_list")

        containers = inventory.get("containers")
        container_records = containers.get("records") if isinstance(containers, Mapping) else None
        manifest.request("portainer.container_catalog", scope="selected_inventory")
        catalog_complete = (
            isinstance(container_records, list)
            and isinstance(containers, Mapping)
            and not containers.get("partial")
            and not containers.get("status")
        )
        manifest.finish("portainer.container_catalog", complete=bool(catalog_complete))
        if catalog_complete and isinstance(container_records, list):
            manifest.read("portainer.container_catalog", len(container_records))
        if not isinstance(container_records, list) and env_records:
            collector.partial("portainer/containers", "inventory_unavailable")
            container_records = []
        elif not isinstance(container_records, list):
            container_records = []
        selected_ids = {
            int(item["Id"]) for item in env_records if isinstance(item, Mapping) and type(item.get("Id")) is int
        }
        if (
            not container_records
            and isinstance(containers, Mapping)
            and not containers.get("partial")
            and not containers.get("status")
        ):
            manifest.request("portainer.container_logs", scope="selected_environments_empty_container_catalog")
        for container in container_records:
            if not isinstance(container, Mapping):
                continue
            endpoint_id = container.get("environment")
            container_id = str(container.get("Id") or container.get("ID") or "")
            if type(endpoint_id) is not int or endpoint_id not in selected_ids or not container_id:
                collector.partial("portainer/containers", "container_identity_unavailable")
                continue
            source = f"portainer/environment/{endpoint_id}/container/{container_id}"
            data = get_json(
                f"/api/endpoints/{endpoint_id}/docker/containers/{quote(container_id, safe='')}/json",
                source,
                stream_large=True,
            )
            if isinstance(data, Mapping):
                collector.add(source, _portainer_discovery_view(data), charge=False, prefer_specific=True)
            elif data is not None and data is not streamed:
                collector.partial(source, "invalid_inspect")
            if collector.allowed():
                manifest.request("portainer.container_logs", scope="selected_environments")
                config = data.get("Config") if isinstance(data, Mapping) else None
                tty = config.get("Tty") if isinstance(config, Mapping) else None
                tty = tty if type(tty) is bool else None
                logs_path = f"/api/endpoints/{endpoint_id}/docker/containers/{quote(container_id, safe='')}/logs"
                logs_path += "?stdout=1&stderr=1&timestamps=0&follow=0&tail=all"
                with collector.source_guard(manifest, "portainer.container_logs"):
                    before_logs = collector.bytes_read
                    ok, status = scan_container_logs(
                        collector,
                        pool,
                        base.rstrip("/") + logs_path,
                        source + "/logs",
                        tty=tty,
                        headers=headers,
                        timeout=timeout,
                    )
                    if status == 200 and collector.bytes_read >= before_logs:
                        manifest.read("portainer.container_logs")
                    manifest.finish(
                        "portainer.container_logs",
                        complete=ok,
                        denied=status in {401, 403},
                        unsupported=status in {404, 405, 501},
                    )

        for endpoint_id in sorted(selected_ids):
            source = f"portainer/environment/{endpoint_id}"
            configs = get_json(
                f"/api/endpoints/{endpoint_id}/docker/configs",
                source + "/configs",
                swarm_only=True,
                stream_catalog="configs",
            )
            if configs is swarm_unavailable:
                info = get_json(f"/api/endpoints/{endpoint_id}/docker/info", source + "/swarm")
                swarm = info.get("Swarm") if isinstance(info, Mapping) else None
                if isinstance(swarm, Mapping) and str(swarm.get("LocalNodeState") or "").lower() == "inactive":
                    # Neither configs nor secrets exist on Docker Standalone.
                    manifest.finish("portainer.swarm_config_catalog", complete=False, unsupported=True)
                    continue
                collector.partial(source + "/configs", "HTTP 503")
            if isinstance(configs, list):
                with DiscoveryFrontier() as seen_configs:
                    for config in configs:
                        if not isinstance(config, Mapping):
                            collector.partial(source + "/configs", "invalid_config")
                            continue
                        config_id = str(config.get("ID") or config.get("Id") or "")
                        if not config_id:
                            collector.partial(source + "/configs", "config_id_unavailable")
                            continue
                        if not seen_configs.claim(config_id):
                            continue
                        with source_attempt("portainer.swarm_config_contents") as acknowledge:
                            detail = get_json(
                                f"/api/endpoints/{endpoint_id}/docker/configs/{quote(config_id, safe='')}",
                                source + f"/config/{config_id}",
                                stream_document=True,
                            )
                            if isinstance(detail, Mapping):
                                spec = detail.get("Spec")
                                encoded = spec.get("Data") if isinstance(spec, Mapping) else None
                                if isinstance(detail, DiskContainer):
                                    metadata: Mapping[str, Any] = _PortainerConfigMetadataView(detail, "")
                                else:
                                    ordinary_metadata = dict(detail)
                                    if isinstance(spec, Mapping):
                                        ordinary_metadata["Spec"] = {
                                            key: value for key, value in spec.items() if key != "Data"
                                        }
                                    metadata = ordinary_metadata
                                collector.add(
                                    source + f"/config/{config_id}/metadata",
                                    metadata,
                                    charge=False,
                                    prefer_specific=True,
                                )
                                if isinstance(encoded, DiskBackedText):
                                    # Data is arbitrary config bytes, not necessarily
                                    # UTF-8. Decode base64 before the shared format
                                    # dispatcher, without replacement characters.
                                    with tempfile.SpooledTemporaryFile(max_size=65536) as decoded_file:
                                        pending = ""
                                        try:
                                            for part in encoded.iter_text_chunks():
                                                if not collector.allowed():
                                                    break
                                                pending += part
                                                whole = len(pending) - len(pending) % 4
                                                if whole:
                                                    decoded = base64.b64decode(pending[:whole], validate=True)
                                                    decoded_file.write(decoded)
                                                    collector.bytes_read += len(decoded)
                                                    pending = pending[whole:]
                                            else:
                                                if pending:
                                                    raise ValueError("incomplete base64")
                                                decoded_file.seek(0)
                                                collector._scan_retained_payload(
                                                    source + f"/config/{config_id}/value",
                                                    decoded_file,
                                                    prefer_specific=True,
                                                )
                                        except ValueError:
                                            collector.partial(source + f"/config/{config_id}", "invalid_base64")
                                elif isinstance(encoded, str):
                                    try:
                                        decoded = base64.b64decode(encoded, validate=True)
                                    except ValueError:
                                        collector.partial(source + f"/config/{config_id}", "invalid_base64")
                                    else:
                                        if collector.charge(len(decoded)):
                                            collector.add(
                                                source + f"/config/{config_id}/value",
                                                decoded,
                                                charge=False,
                                                prefer_specific=True,
                                            )
                                else:
                                    collector.partial(source + f"/config/{config_id}", "config_data_unavailable")
                                acknowledge(1)
                            elif detail is not None:
                                collector.partial(source + f"/config/{config_id}", "invalid_inspect")
            elif configs is not None:
                collector.partial(source + "/configs", "invalid_list")
            secrets = get_json(
                f"/api/endpoints/{endpoint_id}/docker/secrets",
                source + "/secrets",
                swarm_only=True,
                stream_catalog="secrets",
            )
            if secrets is swarm_unavailable:
                collector.partial(source + "/secrets", "HTTP 503")
            if secrets is streamed_secrets or isinstance(secrets, list) and secrets:
                manifest.request("portainer.swarm_secret_values", implemented=False, scope="API_exposes_metadata_only")
                manifest.finish("portainer.swarm_secret_values", complete=False, unsupported=True)
            if secrets is streamed_secrets:
                collector.partial(source + "/secrets", "secret_values_not_exposed_by_api")
            if isinstance(secrets, list) and secrets:
                collector.partial(source + "/secrets", "secret_values_not_exposed_by_api")
                for secret in secrets:
                    if isinstance(secret, Mapping):
                        collector.add(source + "/secret/metadata", secret, charge=False, prefer_specific=True)
