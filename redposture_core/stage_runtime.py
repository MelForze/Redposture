"""Shared runtime helpers for staged audit modules."""

from __future__ import annotations

import copy
import functools
import inspect
import itertools
import json
import os
import re
import sys
import threading
import time
import weakref
from collections import Counter
from collections.abc import Awaitable, Callable, Generator, Iterable, Iterator, Mapping
from contextlib import AbstractContextManager, contextmanager, nullcontext
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
from typing import Any, Literal

from . import audit_models as _audit_models
from . import data_discovery, web_panels
from .audit_config import AuditConfig
from .audit_models import StageTrace
from .clients.tls_cache import tls_context_cache_stats
from .cve import CveCatalog, ProductResolver, enumerate_record, load_catalog, render_finding_lines
from .detection_diagnostics import FallbackDiagnostics, capture_fallbacks, measure_sync_detect, sync_fallback
from .discovery_options import DEFAULT_DISCOVER_TIME, UNLIMITED_DISCOVER_BYTES
from .discovery_rendering import (
    discovery_color_spans,
    format_discovery_finding_line,
    iter_discovery_location_lines,
    iter_discovery_source_lines,
    iter_disk_discovery_finding_line_chunks,
)
from .discovery_spool import SpoolingFindings, SpoolingStrings, contains_spooled
from .discovery_values import DiskBackedText, contains_disk_backed, iter_json_chunks
from .progress import CommandProgressOwner, NoOpProgress, ProgressHandle, suspend_active_progress_for_output
from .rendering import (
    format_report_line_for_console,
    normalize_report_line_for_storage,
    order_detection_fields,
    render_colored_marker_line,
    sanitize_report_line,
    sanitize_report_payload,
    suppress_redundant_auth_requirement,
)
from .runtime_diagnostics import RuntimeDiagnostics, observe_async_phase, observe_phase
from .scheduler import BoundedScheduler, SharedNestedScheduler, WorkPause, run_paused_sync
from .show_limits import dump_flag_enabled, dump_flag_limit, show_flag_enabled, show_flag_limit
from .targeting import (
    DEFAULT_STREAM_TARGET_WINDOW_SIZE,
    ScanTargetSpec,
    StreamingTargetPlan,
    TargetParsePolicy,
    build_scan_execution_groups,
    collect_scan_target_specs,
    stream_scan_target_specs,
)
from .utils import (
    collect_scan_ports,
    collect_scan_targets,
    filter_open_tcp_hosts_for_credential_file,
    parse_username_password_credential_file,
    utc_now_iso,
)

AuditRecord = _audit_models.AuditRecord
CapabilitySet = _audit_models.CapabilitySet
CredentialAttempt = _audit_models.CredentialAttempt
_RUNTIME_COMPAT_EXPORTS = (
    collect_scan_targets,
    collect_scan_target_specs,
    build_scan_execution_groups,
    filter_open_tcp_hosts_for_credential_file,
)
DEFAULT_RECORD_RETENTION_LIMIT = 100_000
_LARGE_AUDIT_PLAN_ENDPOINTS = 1_000
_DEFAULT_AUDIT_WORKERS = 64
_LARGE_AUDIT_WORKERS = 128
_DEFAULT_NESTED_WORKERS = 32
_LARGE_NESTED_WORKERS = 64
_TARGET_LIVE_EMIT: ContextVar[Callable[[Iterable[str]], None] | None] = ContextVar(
    "audit_target_live_emit", default=None
)
_TARGET_DISK_EMIT: ContextVar[Callable[..., None] | None] = ContextVar("audit_target_disk_emit", default=None)
_TARGET_STREAM_EMIT: ContextVar[Callable[[str], int] | None] = ContextVar("audit_target_stream_emit", default=None)
_TARGET_DISCOVERY_STARTED_AT: ContextVar[float | None] = ContextVar("audit_target_discovery_started_at", default=None)
_CREDENTIAL_PHASE_EMIT_ACTIVE: ContextVar[bool] = ContextVar("audit_credential_phase_emit_active", default=False)
_CREDENTIAL_JOB_ID: ContextVar[int | None] = ContextVar("audit_credential_job_id", default=None)
_CREDENTIAL_JOB_IDS = itertools.count(1)


def _credential_job_key() -> int:
    # Legacy workers keep their thread key. Only opt-in resumable jobs need a
    # stable, disjoint key while their Context moves between pool threads.
    key = _CREDENTIAL_JOB_ID.get()
    return key if key is not None else threading.get_ident()


def _merge_debug_events(*records: dict[str, Any]) -> list[str]:
    events: list[str] = []
    for record in records:
        source = record.get("debug_events")
        if not isinstance(source, list):
            continue
        for item in source:
            if isinstance(item, str) and item.strip():
                events.append(item)
    return events


def _merge_stages(*records: dict[str, Any]) -> list[dict[str, Any]]:
    stages: list[dict[str, Any]] = []
    for record in records:
        source = record.get("stages")
        if not isinstance(source, list):
            continue
        for entry in source:
            if isinstance(entry, dict):
                stages.append(dict(entry))
    return stages


def _merge_int_mapping(field: str, *records: dict[str, Any]) -> dict[str, int]:
    merged: dict[str, int] = {}
    for record in records:
        source = record.get(field)
        if not isinstance(source, dict):
            continue
        for key, value in source.items():
            merged[str(key)] = int(value or 0)
    return merged


def merge_stage_records(
    detect_record: dict[str, Any],
    deep_record: dict[str, Any],
    *,
    deep_fields: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Merge pass-1 detect/auth and pass-2 deep records consistently.

    Most staged modules previously carried local copies of this logic. The
    helper keeps additive JSON/debug telemetry stable while allowing modules
    with selective deep updates to pass an explicit field allow-list.
    """

    merged = dict(detect_record)
    if deep_fields is None:
        merged.update(deep_record)
    else:
        for field in deep_fields:
            if field in deep_record:
                merged[field] = deep_record[field]

    merged["debug_events"] = _merge_debug_events(detect_record, deep_record)
    merged["debug_events_streamed"] = bool(detect_record.get("debug_events_streamed")) or bool(
        deep_record.get("debug_events_streamed")
    )
    merged["stages"] = _merge_stages(detect_record, deep_record)
    merged["stage_durations_ms"] = _merge_int_mapping("stage_durations_ms", detect_record, deep_record)
    merged["stage_attempts"] = _merge_int_mapping("stage_attempts", detect_record, deep_record)
    merged["stage_failed_at"] = deep_record.get("stage_failed_at") or detect_record.get("stage_failed_at")
    return merged


def format_retry_decision(stage: str, attempt: int, max_attempts: int, backoff: float, reason: str) -> str:
    return (
        f"retry_decision stage={stage} attempt={int(attempt)}/{int(max_attempts)} "
        f"backoff={float(backoff):.2f}s reason={reason or '-'}"
    )


def format_stage_trace(stage: str, attempt: int, duration_ms: int, result: str, error: str | None = None) -> str:
    return (
        f"stage_trace stage_name={stage} attempt={int(attempt)} duration_ms={int(max(0, duration_ms))} "
        f"result={result or '-'} error={error or '-'}"
    )


def format_stage2_gate(host: str, port: int, decision: str, reason: str) -> str:
    return f"{host}:{int(port)} stage2_gate={decision} reason={reason or '-'}"


def format_pass_marker(pass_no: int, phase: str, event: str, **fields: Any) -> str:
    suffix = " ".join(f"{key}={value}" for key, value in fields.items())
    base = f"pass={int(pass_no)} {phase} {event}"
    return f"{base} {suffix}".rstrip()


# These adapters preserve the complete sync detection decision tree on retry.
# Compatibility fallbacks (framing, redirects, drivers, proxies) remain sync.
_NATIVE_TIMEOUT_RECOVERY_MODULES = frozenset(
    {
        "postgres",
        "grafana",
        "qdrant",
        "rabbitmq",
        "etcd",
        "proxmox",
        "docker-registry",
        "consul",
        "kubeapi",
        "minio",
        "elastic",
        "gitlab",
        "redis",
        "zookeeper",
        "grpc",
        "clickhouse",
        "kafka",
        "keeper",
        "mongodb",
    }
)


_PHASE_STAGE_NAMES: dict[AuditPhase, str] = {
    "detect": "detect_protocol",
    "auth": "auth_inference_credentials",
    "capabilities": "access_capabilities",
    "data": "data",
}


def _attach_runtime_phase_trace(
    current: AuditRecord,
    *,
    phase: AuditPhase,
    duration_ms: int,
    result: str,
    error: str | None = None,
    prior: AuditRecord | None = None,
    debug_emit: Callable[[str], None] | None = None,
) -> tuple[AuditRecord, bool]:
    """Carry phase telemetry across hooks and fill a missing canonical trace.

    Explicit lifecycle hooks may either own their complete telemetry contract or
    return ordinary records and let the shared runtime instrument the calls.
    Module-owned entries always win: retry traces and their ordering are kept
    verbatim, and a canonical phase is synthesized only when the hook omitted
    that phase entirely.
    """

    current_stages = list(current.stages)
    current_names = {stage.stage_name for stage in current_stages}

    carried: list[StageTrace] = []
    if prior is not None:
        for stage in prior.stages:
            if stage.stage_name not in current_names:
                carried.append(stage)

    stages = carried + current_stages
    stage_name = _PHASE_STAGE_NAMES[phase]
    added = stage_name not in {stage.stage_name for stage in stages}
    duration = max(0, int(duration_ms))
    if added:
        trace = StageTrace(
            stage_name=stage_name,
            attempt=1,
            duration_ms=duration,
            result=str(result or "ok"),
            error=str(error).strip() if error else None,
        )
        stages.append(trace)
        if debug_emit is not None:
            debug_emit(
                format_stage_trace(
                    trace.stage_name,
                    trace.attempt,
                    trace.duration_ms,
                    trace.result,
                    trace.error,
                )
            )

    stage_durations: dict[str, int] = {}
    stage_attempts: dict[str, int] = {}
    if prior is not None:
        prior_durations = prior.extra.get("stage_durations_ms")
        prior_attempts = prior.extra.get("stage_attempts")
        if isinstance(prior_durations, Mapping):
            stage_durations.update({str(key): int(value or 0) for key, value in prior_durations.items()})
        if isinstance(prior_attempts, Mapping):
            stage_attempts.update({str(key): int(value or 0) for key, value in prior_attempts.items()})
    current_durations = current.extra.get("stage_durations_ms")
    current_attempts = current.extra.get("stage_attempts")
    if isinstance(current_durations, Mapping):
        stage_durations.update({str(key): int(value or 0) for key, value in current_durations.items()})
    if isinstance(current_attempts, Mapping):
        stage_attempts.update({str(key): int(value or 0) for key, value in current_attempts.items()})
    if added:
        stage_durations.setdefault(stage_name, duration)
        stage_attempts.setdefault(stage_name, 1)

    extra = dict(current.extra)
    extra["stage_durations_ms"] = stage_durations
    extra["stage_attempts"] = stage_attempts
    extra.setdefault("timestamp", utc_now_iso())
    if not extra.get("stage_failed_at") and added and str(result).lower() in {"error", "fail", "timeout"}:
        extra["stage_failed_at"] = stage_name
    return replace(current, stages=tuple(stages), extra=extra), added


def _runtime_phase_outcome(
    phase: AuditPhase,
    current: AuditRecord,
    prior: AuditRecord | None = None,
) -> tuple[str, str | None]:
    status = str(current.status or "").strip().lower()
    current_error = str(current.extra.get("error") or "").strip() or None
    prior_error = str(prior.extra.get("error") or "").strip() or None if prior is not None else None
    if status == "fail":
        return "error", current_error or "phase failed"
    if phase == "data" and current_error is not None and current_error != prior_error:
        return "error", current_error
    return "ok", None


def should_use_global_progress(output_format: str, *dimensions: int) -> bool:
    """Return whether a command-level progress bar should own this run.

    The decision intentionally does not depend on stdout vs `-o`: text output
    written to a file still needs command-level progress ownership. Returning
    true for a single text target is deliberate: audit functions should not own
    progress, because they do not see the full command matrix (ports, URL groups,
    credential files). The outer command-level loop owns the single progress bar
    and inner per-group/per-credential progress stays disabled.
    """

    if str(output_format or "txt") != "txt":
        return False
    return any(int(value) > 0 for value in dimensions)


def progress_total_from_groups(group_hosts: Iterable[Iterable[Any]], credential_runs: int = 1) -> int:
    total_hosts = 0
    for hosts in group_hosts:
        try:
            total_hosts += len(hosts)  # type: ignore[arg-type]
        except TypeError:
            total_hosts += sum(1 for _ in hosts)
    return int(total_hosts) * max(1, int(credential_runs))


@contextmanager
def install_record_callback(args: Any, callback: Callable[[dict[str, Any]], None]) -> Iterator[None]:
    """Install a per-record callback on `args._record_callback` for the duration of the
    `with` block, then restore the previous value (or remove the attribute entirely if
    none was set). Previously consul/grpc each reimplemented this save-and-restore plumbing
    inline; centralizing it avoids the next module copying the same boilerplate."""
    previous = getattr(args, "_record_callback", None)
    args._record_callback = callback
    try:
        yield
    finally:
        if previous is None:
            try:
                delattr(args, "_record_callback")
            except AttributeError:
                pass
        else:
            args._record_callback = previous


def _record_callbacks_for_args(args: Any) -> tuple[Callable[[dict[str, Any]], None], ...]:
    callbacks: list[Callable[[dict[str, Any]], None]] = []
    seen: set[int] = set()
    for candidate in (getattr(args, "_record_callback", None), getattr(args, "record_callback", None)):
        if not callable(candidate):
            continue
        marker = id(candidate)
        if marker in seen:
            continue
        seen.add(marker)
        callbacks.append(candidate)
    return tuple(callbacks)


class LineOutputSink:
    """Buffered line sink for stages that must choose one emitted result from many attempts.

    Audit finalization is coordinator-owned, while other streaming stages may
    still have multiple producers. The mutex keeps lazy file preparation,
    file+console teeing, and each multi-line record atomic in both cases.
    """

    def __init__(
        self,
        output_path: str | None,
        emit_line: Callable[[str], None],
        *,
        append: bool = False,
        console: Any = None,
        observer: RuntimeDiagnostics | None = None,
    ) -> None:
        self._runtime_stats = observer
        self.output_path = output_path
        self.emit_line = emit_line
        self.console = console
        self.output_written = bool(append)
        self._append = bool(append)
        self._handle: Any = None
        self._lock = threading.Lock()
        self._closed = False

    def _prepare_unlocked(self) -> None:
        if not self.output_path or self._handle is not None:
            return
        os.makedirs(os.path.dirname(self.output_path) or ".", exist_ok=True)
        self._handle = open(self.output_path, "a" if self._append else "w", encoding="utf-8")

    def prepare(self) -> None:
        """Open the output before audit work starts.

        Non-append output is truncated eagerly so a zero-record run cannot
        preserve stale results from an earlier invocation.
        """

        with self._lock:
            if self._closed:
                return
            self._prepare_unlocked()

    @observe_phase("write")
    def emit_many(self, lines: Iterable[str]) -> None:
        # Single choke point for every TXT line reaching the file or the console
        # (streamed sections tee through here too): scrub control characters from
        # the record payload so a target-supplied name cannot forge a report line,
        # add a TSV field, or drive the operator's terminal. A no-op for JSON and
        # run-level lines, which carry no target data (see sanitize_report_line).
        console_lines = [order_detection_fields(sanitize_report_line(line)) for line in lines if line]
        if not console_lines:
            return
        with self._lock:
            if self._closed:
                return
            if self.output_path:
                self._prepare_unlocked()
                for line in console_lines:
                    line = normalize_report_line_for_storage(line)
                    self._handle.write(line + "\n")
                self._handle.flush()
            # Emit to console inside the lock too: without it a second thread's
            # `print()` can splice its output into the first thread's partial
            # write on POSIX (write(2) is atomic per-syscall but Python's
            # `print(...)` performs two writes).
            for line in console_lines:
                self.emit_line(line)
            self.output_written = True

    @observe_phase("write")
    def emit_json_chunks(self, chunks: Iterable[str]) -> None:
        """Tee one JSONL record without joining its contents in memory."""
        with self._lock:
            if self._closed:
                return
            if self.output_path:
                self._prepare_unlocked()
            for chunk in chunks:
                if not chunk:
                    continue
                if self._handle is not None:
                    self._handle.write(chunk)
                sys.stdout.write(chunk)
            if self._handle is not None:
                self._handle.write("\n")
                self._handle.flush()
            sys.stdout.write("\n")
            sys.stdout.flush()
            self.output_written = True

    @observe_phase("write")
    def emit_discovery_value(
        self,
        module: str,
        host: Any,
        port: Any,
        *,
        finding_type: Any,
        value: DiskBackedText,
        place: Any,
    ) -> None:
        """Tee one long TXT finding atomically without materializing its value."""
        chunks = iter_disk_discovery_finding_line_chunks(
            module, host, port, finding_type=finding_type, value=value, place=place
        )
        with self._lock:
            if self._closed:
                return
            if self.output_path:
                self._prepare_unlocked()
            with suspend_active_progress_for_output(sys.stdout):
                for index, chunk in enumerate(chunks):
                    if not chunk:
                        continue
                    if self._handle is not None:
                        self._handle.write(chunk)
                    if index == 0:
                        display = format_report_line_for_console(chunk)
                        parts = display.split("\t", 3)
                        if len(parts) == 4 and self.console is not None and hasattr(self.console, "_paint"):
                            tag, host_text, port_text, detail = parts
                            marker, _, payload = detail.partition("[!]")
                            sys.stdout.write(self.console._paint(tag.rstrip(), "blue", sys.stdout))
                            sys.stdout.write(
                                self.console._paint(
                                    f"{tag[len(tag.rstrip()) :]}\t{host_text}\t{port_text}\t{marker}",
                                    "white",
                                    sys.stdout,
                                )
                            )
                            sys.stdout.write(self.console._paint("[!]", "true_red", sys.stdout))
                            sys.stdout.write(self.console._paint(payload, "orange", sys.stdout))
                        else:
                            sys.stdout.write(display)
                    elif self.console is not None and hasattr(self.console, "_paint"):
                        sys.stdout.write(self.console._paint(chunk, "orange", sys.stdout))
                    else:
                        sys.stdout.write(chunk)
                if self._handle is not None:
                    self._handle.write("\n")
                    self._handle.flush()
                sys.stdout.write("\n")
                sys.stdout.flush()
            self.output_written = True

    @observe_phase("write")
    def emit_text_chunks(self, chunks: Iterable[str]) -> None:
        """Tee one long plain TXT row while retaining only a bounded fragment."""
        with self._lock:
            if self._closed:
                return
            if self.output_path:
                self._prepare_unlocked()
            with suspend_active_progress_for_output(sys.stdout):
                continuation_color = "white"
                for index, raw in enumerate(chunks):
                    chunk = sanitize_report_line(raw) if index == 0 else sanitize_report_payload(raw)
                    if self._handle is not None:
                        self._handle.write(normalize_report_line_for_storage(chunk) if index == 0 else chunk)
                    display = format_report_line_for_console(chunk) if index == 0 else chunk
                    if self.console is not None and hasattr(self.console, "_paint"):
                        columns = display.split("\t", 3) if index == 0 else []
                        if len(columns) == 4 and columns[3].lstrip().startswith("[!] "):
                            tag, host_text, port_text, detail = columns
                            before, _, payload = detail.partition("[!]")
                            sys.stdout.write(self.console._paint(tag, "blue", sys.stdout))
                            sys.stdout.write(
                                self.console._paint(f"\t{host_text}\t{port_text}\t{before}", "white", sys.stdout)
                            )
                            sys.stdout.write(self.console._paint("[!]", "true_red", sys.stdout))
                            sys.stdout.write(self.console._paint(payload, "orange", sys.stdout))
                            continuation_color = "orange"
                            continue
                        parts = display.split("\t", 1) if index == 0 else [display]
                        if len(parts) == 2:
                            sys.stdout.write(self.console._paint(parts[0], "blue", sys.stdout))
                            sys.stdout.write(self.console._paint("\t" + parts[1], "white", sys.stdout))
                        else:
                            sys.stdout.write(self.console._paint(display, continuation_color, sys.stdout))
                    else:
                        sys.stdout.write(display)
                if self._handle is not None:
                    self._handle.write("\n")
                    self._handle.flush()
                sys.stdout.write("\n")
                sys.stdout.flush()
            self.output_written = True

    def emit_stream_file(self, path: str, *, batch: int = 1000) -> int:
        """Stream a file of pre-formatted lines to the sink without materialising it.

        Used for very large streamed sections (e.g. a minio object listing buffered
        during the data phase): the file is read and teed to file+console in bounded
        batches, so memory stays bounded regardless of the listing size. Returns the
        number of lines emitted.
        """
        emitted = 0
        try:
            handle = open(path, encoding="utf-8")
        except OSError:
            return 0
        try:
            buffer: list[str] = []
            buffer_chars = 0
            while raw := handle.readline(65_536):
                if len(raw) == 65_536 and not raw.endswith("\n"):
                    if buffer:
                        self.emit_many(buffer)
                        emitted += len(buffer)
                        buffer = []
                        buffer_chars = 0

                    def fragments(first: str) -> Iterator[str]:
                        yield first
                        while following := handle.readline(65_536):
                            yield following.removesuffix("\n")
                            if following.endswith("\n"):
                                break

                    self.emit_text_chunks(fragments(raw))
                    emitted += 1
                    continue
                line = raw.rstrip("\n")
                if not line:
                    continue
                buffer.append(line)
                buffer_chars += len(line)
                if len(buffer) >= max(1, batch) or buffer_chars >= 1024 * 1024:
                    self.emit_many(buffer)
                    emitted += len(buffer)
                    buffer = []
                    buffer_chars = 0
            if buffer:
                self.emit_many(buffer)
                emitted += len(buffer)
        finally:
            handle.close()
        return emitted

    def close(self) -> None:
        with self._lock:
            self._closed = True
            if self._handle is not None:
                self._handle.close()
                self._handle = None


def _build_colored_emit(console: Any, colorize: Callable[[Any, str], bool] | None) -> Callable[[str], None]:
    """Build a stdout emitter that colorizes marker lines via the spec's explicit
    `colorize` hook, falling back to plain output. The colorizer no-ops (returns
    `False`) on lines that don't start with its tag, so JSON output stays clean;
    file output never reaches here (the sink writes files directly)."""

    def emit(line: str) -> None:
        line = format_report_line_for_console(line)
        if "Discover Secrets" in line or (" Value=" in line and " Place=" in line):
            tag = line.split(None, 1)[0]
            if render_colored_marker_line(
                console,
                line,
                tag=tag,
                extra_spans=discovery_color_spans,
            ):
                return
        if colorize is not None and colorize(console, line):
            return
        console.plain(line)

    return emit


AuditPhase = Literal["detect", "auth", "capabilities", "data"]

_DISCOVERY_SUMMARY_LINE = re.compile(r"^\S+\s+\S+\s+\S+\s+\[\*\] Discover (?:Complete|Secrets) \(status:")


def _is_discovery_summary_line(line: str) -> bool:
    return _DISCOVERY_SUMMARY_LINE.match(line) is not None


@dataclass(frozen=True)
class AuditHookContext:
    args: Any
    logger: Any
    host: str
    port: int
    credential: AuditCredentialRun
    target: ScanTargetSpec | None = None
    run_deep_checks: bool = True
    debug_emit: Callable[[str], None] | None = None
    phase: AuditPhase = "data"
    credential_runs: tuple[AuditCredentialRun, ...] = ()
    lifecycle_state: Any = None
    nested_scheduler: SharedNestedScheduler | None = None
    # Live TXT sink (tees console + `-o` file). The runtime uses it for staged
    # detect/auth/capability output; data hooks may use the same sink for findings.
    # JSON remains one complete record per target. None disables live output.
    live_emit: Callable[[Iterable[str]], None] | None = None
    live_discovery_value: Callable[..., None] | None = None
    discovery_started_at: float | None = None
    cancelled: Callable[[], bool] | None = None
    reuse_http: bool = False
    session_budget: Any = None
    # Publish a completed inventory through phase deduplication before content
    # scanning. A transferred _stream_lines_file is emitted boundedly and removed.
    emit_ready_inventory: Callable[[dict[str, Any]], None] | None = None


@dataclass(frozen=True)
class ModuleAuditSpec:
    """Declarative command contract consumed by `AuditCommandRunner`.

    Existing modules can wrap their current host audit functions with these
    hooks, while new modules should use this spec directly instead of owning
    command-level target/output/progress loops.
    """

    module: str
    label: str
    default_port: int
    # Legacy production host_stage callables remain supported. The runner keeps
    # anonymous protocol detection separate, then invokes a monolithic stage
    # once per credential candidate with deep checks enabled so authentication
    # and data work are not repeated. Phase-aware host_stage callables and the
    # explicit hooks below retain the full staged lifecycle.
    host_stage: Callable[..., AuditRecord | dict[str, Any]] | None = None
    # Exact action/schema values for strict CLI-to-host-stage binding. When
    # supplied, every non-runtime host-stage parameter must be present by its
    # exact name; aliases and silent type-based defaults are disabled.
    host_stage_options: Mapping[str, Any] | None = None
    detect: Callable[[AuditHookContext], AuditRecord] | None = None
    # Native async detection is opt-in and tied to the matching sync hook.
    # dataclasses.replace(detect=...) must not accidentally keep a stale adapter.
    detect_async: Callable[[AuditHookContext, Any], Awaitable[AuditRecord]] | None = None
    async_detect_sync_hook: Callable[[AuditHookContext], AuditRecord] | None = None
    auth: Callable[[AuditHookContext, AuditRecord], AuditRecord] | None = None
    capabilities: Callable[[AuditHookContext, AuditRecord], AuditRecord] | None = None
    data: Callable[[AuditHookContext, AuditRecord], AuditRecord] | None = None
    lifecycle_state_factory: Callable[[AuditHookContext], Any] | None = None
    lifecycle_state_close: Callable[[Any], None] | None = None
    # Output: either an explicit `render` callable, or a `render_module` whose
    # `_format_*` functions the runner introspects (via `render_record_with_module`).
    # `colorize` is the module's explicit `_render_colored_*_line` hook; the runner
    # applies it to stdout (no `__all__` name-magic in the call site).
    render: Callable[[AuditRecord], Iterable[str]] | None = None
    render_module: Any = None
    colorize: Callable[[Any, str], bool] | None = None
    is_detected: Callable[[AuditRecord], bool] | None = None
    deep_gate: Callable[[AuditRecord], tuple[bool, str]] | None = None
    # Some product roots require auth while individual public objects remain
    # readable. Only an explicit discovery request may probe those objects.
    discover_public_on_auth_required: bool = False
    # Opt in when a data hook needs the confirmed service line visible before
    # it blocks for operator input. The shared phase emitter deduplicates the
    # final record and keeps the text file in the same order as the terminal.
    live_phase_output: bool = False
    # E3 opt-in: when True + `--defcreds` + detect status==open_no_auth, the
    # runner returns the detect record instead of re-running the host_stage
    # against every default credential. Kafka hardcodes this behavior in
    # `_should_keep_anonymous_detect_record`; other modules opt in via this
    # flag as their credential loop is proven safe to skip on anon-open.
    keep_anonymous_open_no_auth: bool = False
    # Skip a credential catalog when protocol detection proved there is no
    # read-only verifier capable of distinguishing accepted from arbitrary
    # credentials. The detect record must expose
    # credential_verification_status="unavailable".
    skip_credentials_without_verifier: bool = False
    # Normal audit text is a findings report: records that did not confirm the
    # requested service stay available to callbacks, --debug, and JSON, but do
    # not produce one failure line per target. Specialised callers may opt out.
    suppress_undetected_records_in_text: bool = True
    # A module may distinguish successful identity verification from a record
    # that merely remains usable through anonymous access.
    credential_gate: Callable[[AuditCredentialRun, AuditRecord], tuple[bool, str]] | None = None
    # Optional active, bounded harmless command proof. Modules that opt in
    # defer their initial text line until this hook has a truthful result.
    rce_probe: Callable[[AuditHookContext, AuditRecord], AuditRecord] | None = None
    # Preserve every credential that was actually tried, including a
    # successful final candidate. Default-off keeps other module payloads
    # unchanged.
    record_all_credential_attempts: bool = False
    # Opt-in completeness ledger, including candidates left unverified by a
    # safety stop or cancellation. Existing module payloads remain unchanged.
    record_skipped_credential_attempts: bool = False
    logical_target_key: Callable[[AuditRecord], object | None] | None = None
    phase_output_key: Callable[[AuditRecord, str], str] | None = None
    # If every supplied credential is rejected or unverified, continue data
    # collection with a previously confirmed anonymous-open detect record.
    fallback_to_anonymous_detect_record: bool = False
    # Continue to the next credential candidate when one auth hook raises an
    # operational exception. Default-off preserves existing module behavior.
    continue_after_credential_error: bool = False
    # Continue probing credentials after the first accepted candidate. The
    # first accepted identity still owns capabilities/data, while every
    # credential result is retained for the final attempt history.
    continue_after_credential_success: bool = False
    # Remove module-specific secrets from JSON lines without changing retained
    # records or callbacks.
    structured_output_redact_fields: tuple[str, ...] = ()
    # Additive structured fields copied from each auth record into the
    # ``attempted_credentials`` history. Default-empty preserves other modules.
    credential_attempt_detail_fields: tuple[str, ...] = ()
    # Large scans can opt out of retaining every completed record while still
    # streaming output and callbacks. ``None`` preserves the shared default.
    record_retention_limit: int | None = None
    # Minimum time between TTY progress renders. ``None`` preserves immediate
    # refresh behavior for existing modules.
    progress_refresh_interval_s: float | None = None
    # A module whose authenticated probe enriches the primary service line may
    # defer that line until the first auth result. This avoids printing an
    # interim ``version:-`` line followed by a second, corrected service line
    # while discovery/CVE output is streamed.
    defer_detect_output_until_auth: bool = False
    # Some modules enrich their service/credential lines in later phases.
    # An append-only live stream cannot replace those provisional lines, so
    # emit the stable detection after capabilities and the remaining complete
    # record after the target lifecycle finishes.
    defer_phase_output_until_final: bool = False
    # Some scanners inspect content while the same data phase is still
    # collecting capability fields. Render those findings with the final
    # record so the complete credential line precedes them.
    defer_discovery_findings_until_final: bool = False
    # A module may have a stable service/auth verdict after capabilities while
    # its data phase streams findings. Emit that verdict before entering data,
    # then append only newly rendered inventory/summary lines at completion.
    emit_capabilities_before_data: bool = False
    # Optional module-specific product/version resolver for offline CVE
    # enumeration. The shared resolver covers standard record fields.
    cve_product_resolver: ProductResolver | None = None
    # Appended for positional spec compatibility. Only socket-free admission
    # yields; auth/data themselves remain synchronous in the same worker cap.
    auth_wait: Callable[[AuditHookContext, AuditRecord], AbstractContextManager[Iterable[WorkPause]]] | None = None


@dataclass(frozen=True)
class AuditCredentialRun:
    """One credential candidate considered by command-level audit runtime."""

    username: str | None = None
    password: str | None = None
    token: str | None = None
    source: str = "anonymous"

    @property
    def label(self) -> str:
        if self.token:
            return f"token:{self.source}"
        if self.username is not None:
            return f"{self.username}:{self.password or ''}"
        return "anonymous"

    def to_attempt(self, *, ok: bool | None = None, error: str | None = None) -> CredentialAttempt:
        return CredentialAttempt(
            username=self.username,
            password=self.password,
            token=self.token,
            ok=ok,
            error=error,
        )


@dataclass(frozen=True)
class AuditCommandPlan:
    """Normalized work plan for audit command execution.

    `targets_by_port` is the command-level shape shared by multi-port modules:
    detect work is performed once per host:port, while credential candidates are
    tracked separately for modules that support credential-file mode.
    """

    targets_by_port: dict[int, tuple[str, ...]] = field(default_factory=dict)
    target_specs_by_port: dict[int, tuple[ScanTargetSpec, ...]] = field(default_factory=dict)
    target_plan: StreamingTargetPlan | None = None
    ports: tuple[int, ...] = ()
    credential_runs: tuple[AuditCredentialRun, ...] = (AuditCredentialRun(),)
    output_path: str | None = None
    output_format: str = "txt"
    workers: int = 1
    append: bool = False
    target_window_size: int = DEFAULT_STREAM_TARGET_WINDOW_SIZE
    requested_target_count: int | None = None

    @property
    def target_count(self) -> int:
        if self.target_plan is not None:
            return self.target_plan.count_for_ports(self.ports)
        if self.target_specs_by_port:
            return sum(len(specs) for specs in self.target_specs_by_port.values())
        return sum(len(hosts) for hosts in self.targets_by_port.values())

    @property
    def unique_host_count(self) -> int:
        if self.target_plan is not None:
            return self.target_plan.unique_host_count()
        if self.target_specs_by_port:
            return len({spec.host for specs in self.target_specs_by_port.values() for spec in specs})
        return len({host for hosts in self.targets_by_port.values() for host in hosts})

    def target_counts_by_port(self) -> dict[int, int]:
        """Exact endpoint counts per port without expanding a large CIDR."""

        if self.target_plan is None:
            source = self.target_specs_by_port or self.targets_by_port
            return {int(port): len(items) for port, items in source.items() if items}
        target_plan = self.target_plan
        matrix_ports = tuple(dict.fromkeys(int(port) for port in self.ports))
        explicit_total = sum(target_plan.explicit_port_counts.values())
        result: dict[int, int] = {}
        for port in target_plan.execution_ports(matrix_ports):
            explicit_count = target_plan.explicit_port_counts.get(port, 0)
            count = explicit_count
            if port in matrix_ports:
                count += target_plan.count_for_ports((port,)) - explicit_total
            if count:
                result[port] = count
        return result

    @property
    def fallback_target_count(self) -> int:
        return int(self.requested_target_count or self.target_count)

    @property
    def credential_run_count(self) -> int:
        return max(1, len(self.credential_runs))

    @property
    def total_work_units(self) -> int:
        return self.target_count * self.credential_run_count

    def iter_targets(self) -> Iterable[tuple[int, str, int]]:
        return ((idx, host, port) for idx, host, port, _target in self.iter_target_specs())

    def iter_target_specs(self) -> Iterable[tuple[int, str, int, ScanTargetSpec | None]]:
        if self.target_plan is not None:
            return self._iter_streaming_target_specs()
        if self.target_specs_by_port:
            items: list[tuple[int, str, int, ScanTargetSpec | None]] = []
            idx = 0
            for port, specs in self.target_specs_by_port.items():
                for spec in specs:
                    items.append((idx, str(spec.host), int(port), spec))
                    idx += 1
            return items
        items = []
        idx = 0
        for port, hosts in self.targets_by_port.items():
            for host in hosts:
                items.append((idx, str(host), int(port), None))
                idx += 1
        return items

    def _iter_streaming_target_specs(self):
        if self.target_plan is None:
            return
        idx = 0
        matrix_ports = tuple(int(port) for port in self.ports)
        for port in self.target_plan.execution_ports(matrix_ports):
            for spec in self.target_plan.iter_specs_for_port(int(port), matrix_ports):
                yield idx, str(spec.host), int(port), spec
                idx += 1

    def iter_target_windows(
        self,
        window_size: int | None = None,
    ):
        size = max(1, int(window_size or self.target_window_size or DEFAULT_STREAM_TARGET_WINDOW_SIZE))
        current: list[tuple[int, str, int, ScanTargetSpec | None]] = []
        for item in self.iter_target_specs():
            current.append(item)
            if len(current) >= size:
                yield current
                current = []
        if current:
            yield current

    def first_target_spec(self) -> tuple[int, str, int, ScanTargetSpec | None] | None:
        for item in self.iter_target_specs():
            return item
        return None

    def single_target_spec(self) -> tuple[int, str, int, ScanTargetSpec | None] | None:
        if self.target_count != 1:
            return None
        return self.first_target_spec()

    def require_single_target_spec(self) -> tuple[int, str, int, ScanTargetSpec | None]:
        """Like `single_target_spec()` but raises `ValueError` instead of returning None.
        Centralizes the "requires exactly one target host" validation that postgres /
        clickhouse / etc. shell modes share. Callers catch the ValueError to produce
        their own per-mode error prefix (e.g. `--sql-shell <msg>`)."""
        spec = self.single_target_spec()
        if spec is None:
            raise ValueError("requires exactly one target host")
        return spec

    def iter_work_items(self) -> Iterable[tuple[int, str, int, AuditCredentialRun, ScanTargetSpec | None]]:
        if self.target_plan is not None:
            return self._iter_streaming_work_items()
        items: list[tuple[int, str, int, AuditCredentialRun, ScanTargetSpec | None]] = []
        idx = 0
        credential_runs = self.credential_runs or (AuditCredentialRun(),)
        for _target_idx, host, port, target in self.iter_target_specs():
            for credential in credential_runs:
                items.append((idx, str(host), int(port), credential, target))
                idx += 1
        return items

    def _iter_streaming_work_items(self):
        idx = 0
        credential_runs = self.credential_runs or (AuditCredentialRun(),)
        for _target_idx, host, port, target in self.iter_target_specs():
            for credential in credential_runs:
                yield idx, str(host), int(port), credential, target
                idx += 1


@dataclass(frozen=True)
class AuditCommandResult:
    records: list[dict[str, Any]]
    detected_count: int
    emitted_lines: int
    typed_records: list[AuditRecord]
    suppressed_records: int = 0
    record_count: int = 0
    status_counts: dict[str, int] = field(default_factory=dict)
    record_retention_truncated: bool = False
    operational_failure_count: int = 0
    # True when run_plan already emitted a run-level outcome summary (an
    # no-service fallback line (with an incomplete-scan suffix when needed), or its JSON
    # summary). Callers use it to suppress a coarser, redundant fallback message.
    summary_emitted: bool = False

    @property
    def inconclusive(self) -> bool:
        """Whether no service was confirmed and detection had operational failures."""

        return self.detected_count == 0 and self.operational_failure_count > 0


def command_result_exit_code(result: AuditCommandResult) -> int:
    """Return a shell status that preserves incomplete audit outcomes.

    A negative service result is still a successful audit. A run where no
    service was confirmed and at least one target failed before detection is
    operationally inconclusive. A mixed run with confirmed services and a
    pre-detection operational failure is partial. Both outcomes return nonzero.
    """

    operational_failure_count = int(getattr(result, "operational_failure_count", 0) or 0)
    return 1 if operational_failure_count > 0 else 0


@dataclass(frozen=True)
class _AuditDetectOutcome:
    record: AuditRecord
    lifecycle_state: Any = None
    runtime_stage_telemetry: bool = False
    started_at: float | None = None
    additional_surface_scheduled: bool = False


@dataclass(frozen=True)
class _AuditPipelineOutcome:
    """One target's completed detect-to-deep lifecycle.

    Workers return the final record plus the counters the coordinator needs.
    Keeping finalization out of workers preserves exact completion-order
    callbacks/output without allowing records from different targets to
    interleave.
    """

    record: AuditRecord
    detected: bool
    deep_candidate: bool
    deep_processed: bool
    additional_records: tuple[AuditRecord, ...] = ()
    duplicate_target: bool = False


@dataclass(frozen=True)
class ModuleRunSummary:
    module: str
    attempted_targets: int
    credential_runs: int
    detected_count: int
    emitted_lines: int
    output_path: str | None = None

    @classmethod
    def from_result(
        cls,
        *,
        module: str,
        plan: AuditCommandPlan,
        result: AuditCommandResult,
    ) -> ModuleRunSummary:
        return cls(
            module=module,
            attempted_targets=plan.target_count,
            credential_runs=plan.credential_run_count,
            detected_count=result.detected_count,
            emitted_lines=result.emitted_lines,
            output_path=plan.output_path,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "attempted_targets": int(self.attempted_targets),
            "credential_runs": int(self.credential_runs),
            "detected_count": int(self.detected_count),
            "emitted_lines": int(self.emitted_lines),
            "output_path": self.output_path,
        }


def _record_to_model(record: AuditRecord) -> AuditRecord:
    if isinstance(record, AuditRecord):
        return record
    raise TypeError("AuditCommandRunner hooks must return AuditRecord")


def _record_to_dict(record: AuditRecord) -> dict[str, Any]:
    return _record_to_model(record).to_dict()


def build_basic_audit_plan(
    args: Any,
    *,
    default_port: int,
    default_ports: Iterable[int] | None = None,
) -> AuditCommandPlan:
    cfg = AuditConfig.from_namespace(args)
    # `--port` now accepts the same list/range/file syntax that `--ports`
    # used to require (see `_port_spec` in cli_args.py). Merge the two into
    # a single string for the shared parser: if `--port` came in as a spec
    # (not a bare int) we treat it as if the user had typed `--ports`.
    port_value = getattr(args, "port", None)
    ports_raw = getattr(args, "ports", None)
    port_is_spec = isinstance(port_value, str)
    combined_ports_spec: str | None
    if port_is_spec and ports_raw:
        combined_ports_spec = f"{port_value},{ports_raw}"
    elif port_is_spec:
        combined_ports_spec = port_value
    else:
        combined_ports_spec = ports_raw
    try:
        ports = collect_scan_ports(combined_ports_spec)
    except ValueError as exc:
        raise ValueError(f"failed to parse --port: {exc}") from exc
    if not ports:
        # Only the single-int form of --port flows into this branch — spec
        # values were already merged into combined_ports_spec above.
        int_port = port_value if isinstance(port_value, int) else None
        if int_port is None and default_ports is not None:
            ports = [int(port) for port in default_ports]
        else:
            ports = [int(int_port if int_port is not None else default_port)]

    targets = getattr(args, "targets", None) or getattr(args, "hosts", None)
    hosts_file = getattr(args, "hosts_file", None)
    if hosts_file:
        targets = f"{targets},{hosts_file}" if targets else hosts_file
    target_plan = getattr(args, "_preparsed_target_plan", None)
    if target_plan is None:
        try:
            target_plan = stream_scan_target_specs(
                targets,
                policy=TargetParsePolicy(url_mode="preserve", path_policy="preserve"),
                exclude_targets=getattr(args, "out_targets", None),
            )
        except (OSError, ValueError) as exc:
            raise ValueError(f"failed to parse targets: {exc}") from exc
    if not target_plan:
        if targets and getattr(args, "out_targets", None):
            raise ValueError("all targets were excluded by --out-target")
        raise ValueError("targets are required")

    port_option_provided = getattr(args, "_port_option_provided", None)
    if port_option_provided is None:
        # Programmatic callers that construct Namespace/SimpleNamespace by
        # hand have no argv provenance. Treat any supplied port value as an
        # explicit override; normal CLI parsing always sets the marker above.
        port_option_provided = port_value is not None or ports_raw is not None
    target_plan = target_plan.with_additional_ports_for_bare_explicit_targets(bool(port_option_provided))

    credential_runs = build_basic_credential_runs(args)
    port_tuple = tuple(int(port) for port in ports)

    plan = AuditCommandPlan(
        target_plan=target_plan,
        ports=port_tuple,
        credential_runs=credential_runs,
        output_path=cfg.output,
        output_format=cfg.output_format,
        workers=cfg.workers,
    )
    # CLI defaults depend on plan size. Explicit -w/--workers values and programmatic
    # Namespace callers without provenance remain untouched.
    if getattr(args, "_workers_option_provided", None) is False:
        effective_workers = (
            _LARGE_AUDIT_WORKERS if plan.target_count >= _LARGE_AUDIT_PLAN_ENDPOINTS else _DEFAULT_AUDIT_WORKERS
        )
        args.workers = effective_workers
        plan = replace(plan, workers=effective_workers)
        args._audit_worker_profile = {
            "endpoint_count": plan.target_count,
            "workers": effective_workers,
            "automatic": True,
        }
    else:
        args._audit_worker_profile = {
            "endpoint_count": plan.target_count,
            "workers": int(plan.workers),
            "automatic": False,
        }
    return plan


def build_basic_credential_runs(args: Any) -> tuple[AuditCredentialRun, ...]:
    custom_runs = getattr(args, "_audit_credential_runs", None)
    if custom_runs is not None:
        return tuple(custom_runs)
    cfg = AuditConfig.from_namespace(args)
    username = cfg.username
    password = cfg.password
    token = cfg.token
    try:
        credential_file_entries = parse_username_password_credential_file(username, password)
    except ValueError as exc:
        raise ValueError(str(exc)) from exc
    if credential_file_entries is not None:
        return tuple(
            AuditCredentialRun(username=entry.username, password=entry.password, source="file")
            for entry in credential_file_entries
        )
    return (AuditCredentialRun(username=username, password=password, token=token),)


def sort_default_audit_credential_runs(
    runs: Iterable[AuditCredentialRun],
) -> tuple[AuditCredentialRun, ...]:
    """Return one deterministic alphabetical ordering for built-in credentials.

    Default tokens have no login, so they retain authentication-type priority
    ahead of username/password candidates and are sorted by token value. Basic
    credentials are ordered case-insensitively by login and then password;
    original strings are tie-breakers so the result is deterministic even when
    values differ only by case. Anonymous placeholders sort last.

    Callers must apply this helper only to the built-in defaults group. Explicit
    credentials and credential-file entries intentionally keep user order and
    are merged before the sorted defaults with ``merge_audit_credential_runs``.
    """

    def _key(candidate: AuditCredentialRun) -> tuple[int, str, str, str, str]:
        if candidate.token is not None:
            token = str(candidate.token)
            return 0, token.casefold(), token, "", ""
        if candidate.username is not None or candidate.password is not None:
            username = "" if candidate.username is None else str(candidate.username)
            password = "" if candidate.password is None else str(candidate.password)
            return 1, username.casefold(), password.casefold(), username, password
        return 2, "", "", "", ""

    return tuple(sorted(tuple(runs), key=_key))


def merge_audit_credential_runs(
    *groups: Iterable[AuditCredentialRun],
) -> tuple[AuditCredentialRun, ...]:
    """Merge ordered credential groups with stable, type-aware deduplication.

    Module plans use this helper to implement the shared precedence contract:
    caller-supplied tokens/basic credentials first, credential-file entries
    next, and module defaults last.  A generic ``AuditCredentialRun`` may
    contain both a token and username/password; split it into two candidates so
    a rejected token can fall back to basic authentication.

    The first occurrence wins, which deliberately preserves a provided/file
    source when the same pair is also present in the default catalog.
    """

    merged: list[AuditCredentialRun] = []
    seen: set[tuple[object, ...]] = set()
    anonymous: AuditCredentialRun | None = None

    for group in groups:
        for candidate in group:
            source = candidate.source
            has_token = candidate.token is not None
            has_basic = candidate.username is not None or candidate.password is not None
            if (has_token or has_basic) and source == "anonymous":
                source = "provided"

            expanded: list[AuditCredentialRun] = []
            if has_token:
                expanded.append(AuditCredentialRun(token=candidate.token, source=source))
            if has_basic:
                expanded.append(
                    AuditCredentialRun(
                        username=candidate.username,
                        password=candidate.password,
                        source=source,
                    )
                )
            if not expanded:
                anonymous = anonymous or AuditCredentialRun(source=source)
                continue

            for item in expanded:
                if item.token is not None:
                    key: tuple[object, ...] = ("token", item.token)
                else:
                    key = ("basic", item.username, item.password)
                if key in seen:
                    continue
                seen.add(key)
                merged.append(item)

    if merged:
        return tuple(merged)
    return (anonymous or AuditCredentialRun(source="anonymous"),)


def has_username_password_credential_file(args: Any) -> bool:
    """Return true when -u/--username points at a username/password file."""

    return (
        parse_username_password_credential_file(
            getattr(args, "username", None),
            getattr(args, "password", None),
        )
        is not None
    )


def validate_basic_module_args(
    args: Any,
    console: Any,
    *,
    module: str,
    pure_http: bool = False,
) -> int | None:
    """Validate shared staged-module command rules before plan construction."""

    targets = getattr(args, "targets", None) or getattr(args, "hosts", None) or getattr(args, "hosts_file", None)
    if not targets:
        console.error(f"{module} requires -t/--targets")
        return 2

    timeout = getattr(args, "timeout", None)
    if timeout is not None and float(timeout) <= 0:
        console.error("--timeout must be > 0")
        return 2
    retries = getattr(args, "retries", None)
    if retries is not None and int(retries) < 0:
        console.error("--retries must be >= 0")
        return 2

    username_value = getattr(args, "username", None)
    password_value = getattr(args, "password", None)
    credential_file_entries = None
    if username_value is not None and str(username_value) == "":
        console.error("--username must not be empty")
        return 2
    if username_value is not None:
        try:
            credential_file_entries = parse_username_password_credential_file(username_value, password_value)
        except (OSError, ValueError) as exc:
            console.error(str(exc))
            return 2
    allow_password_only = module in {"redis"}
    if (
        credential_file_entries is None
        and (username_value is None) != (password_value is None)
        and not (allow_password_only and username_value is None and password_value is not None)
    ):
        if (
            username_value is not None
            and password_value is None
            and module
            in {
                "grafana",
                "postgres",
                "mongodb",
                "oracle",
                "clickhouse",
            }
        ):
            console.error("--password is required when --username is set")
        else:
            console.error("--username and --password must be set together")
        return 2

    dump_value = getattr(args, "dump", None)
    if dump_value is not None and dump_value not in (False, True):
        try:
            if int(dump_value) <= 0:
                raise ValueError
        except (TypeError, ValueError):
            console.error("--dump count must be a positive integer")
            return 2

    if module == "kafka":
        dump_limit = dump_flag_limit(dump_value)
        max_messages = getattr(args, "max_messages", None)
        if dump_limit is not None and max_messages is not None and int(max_messages) != int(dump_limit):
            console.error("--dump count cannot conflict with --max-messages")
            return 2

    if pure_http:
        try:
            target_plan = stream_scan_target_specs(
                str(targets),
                policy=TargetParsePolicy(url_mode="preserve", path_policy="preserve"),
                exclude_targets=getattr(args, "out_targets", None),
            )
        except (OSError, ValueError) as exc:
            console.error(f"failed to parse targets: {exc}")
            return 2
        if target_plan.has_scheme("https"):
            console.error(f"{module} accepts only http:// URL targets for -t/--targets")
            return 2

    return None


def _credential_is_anonymous(ctx: AuditHookContext) -> bool:
    credential = ctx.credential
    return credential.username is None and credential.password is None and credential.token is None


@functools.cache
def _cached_signature(func: Callable[..., Any]) -> inspect.Signature:
    """Cache `inspect.signature` per function (called per host / per render record)."""
    return inspect.signature(func)


def _resolve_host_stage(func: Callable[..., Any]) -> Callable[..., Any]:
    """Re-resolve a host action by its qualified name at call time.

    Specs capture the host action at import time, but tests monkeypatch it by
    name on the actions module. Resolving `module.<name>` here keeps that late
    binding working without the old multi-candidate name guessing.
    """

    module_name = getattr(func, "__module__", "") or ""
    name = getattr(func, "__name__", "") or ""
    owner = sys.modules.get(module_name)
    if owner is not None and name:
        return getattr(owner, name, func)
    return func


_HOST_STAGE_RUNTIME_ARGUMENTS = frozenset(
    {
        "host",
        "port",
        "target",
        "target_spec",
        "target_path",
        "url_path",
        "path",
        "target_query",
        "url_query",
        "query_string",
        "timeout",
        "retries",
        "workers",
        "username",
        "password",
        "token",
        "api_token",
        "apitoken",
        "pve_api_token",
        "api_key",
        "defcreds",
        "credential_candidates",
        "run_deep_checks",
        "phase",
        "debug",
        "debug_emit",
        "ssrf_capture",
        "proxy",
        "use_https",
        "preferred_scheme",
        "insecure",
        "ca_file",
        "tls_ca",
        "tls_cert",
        "tls_key",
        "cert_file",
        "key_file",
    }
)


@dataclass(frozen=True)
class _StrictHostStageBinding:
    func: Callable[..., Any]
    signature: inspect.Signature
    options: Mapping[str, Any]


def _build_strict_host_stage_binding(
    func: Callable[..., Any],
    options: Mapping[str, Any],
    *,
    module: str,
) -> _StrictHostStageBinding:
    resolved = _resolve_host_stage(func)
    # Validate against the callable captured by the spec. Compatibility tests
    # and embedders may replace the module attribute later with a variadic
    # recorder; invocation remains late-bound, but the production contract
    # stays anchored to the original explicit signature.
    signature = _cached_signature(func)
    normalized = dict(options)
    parameters = signature.parameters

    variadic = [
        name
        for name, parameter in parameters.items()
        if parameter.kind in {inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD}
    ]
    if variadic:
        raise ValueError(f"{module} strict host_stage cannot use variadic parameter(s): {', '.join(sorted(variadic))}")

    reserved = sorted(set(normalized) & _HOST_STAGE_RUNTIME_ARGUMENTS)
    if reserved:
        raise ValueError(f"{module} host_stage_options cannot override runtime parameter(s): {', '.join(reserved)}")

    unknown = sorted(set(normalized) - set(parameters))
    if unknown:
        raise ValueError(f"{module} host_stage_options contain unknown parameter(s): {', '.join(unknown)}")

    missing = sorted(
        name
        for name, parameter in parameters.items()
        if parameter.kind not in {inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD}
        and name not in _HOST_STAGE_RUNTIME_ARGUMENTS
        and name not in normalized
    )
    if missing:
        raise ValueError(f"{module} host_stage_options are missing parameter(s): {', '.join(missing)}")

    return _StrictHostStageBinding(func=resolved, signature=signature, options=normalized)


def _prepare_host_stage_call(
    func: Callable[..., Any],
    *,
    module: str,
    ctx: AuditHookContext,
    run_deep_checks: bool | None = None,
    strict_binding: _StrictHostStageBinding | None = None,
) -> tuple[Callable[..., Any], list[Any], dict[str, Any]]:
    if strict_binding is not None:
        func = strict_binding.func
        signature = strict_binding.signature
    else:
        func = _resolve_host_stage(func)
        signature = _cached_signature(func)
    if run_deep_checks is not None:
        ctx = replace(ctx, run_deep_checks=bool(run_deep_checks))

    # C6 fix: cache the resolved AuditConfig on the argparse Namespace so
    # repeated per-host stage invocations don't re-coerce every field of the
    # same namespace. `_cached_audit_config` is a plain attribute the harness
    # never inspects; if the object is not a Namespace (test doubles etc)
    # we quietly fall back to the eager path.
    #
    # E9 fix: invalidate the cache whenever the caller mutates AuditConfig-
    # relevant fields on args between invocations. We hash a lightweight
    # sentinel of the fields AuditConfig reads (timeout, retries, workers,
    # debug, defcreds, username, password, token, output, output_format) and
    # rebuild when the sentinel changes.
    def _cfg_sentinel(ns: Any) -> tuple[Any, ...]:
        return (
            getattr(ns, "timeout", None),
            getattr(ns, "retries", None),
            getattr(ns, "workers", None),
            getattr(ns, "debug", None),
            getattr(ns, "defcreds", None),
            getattr(ns, "username", None),
            getattr(ns, "password", None),
            getattr(ns, "token", None),
            getattr(ns, "output", None),
            getattr(ns, "output_format", None),
        )

    sentinel = _cfg_sentinel(ctx.args)
    cached_sentinel = getattr(ctx.args, "_cached_audit_config_sentinel", None)
    cfg = getattr(ctx.args, "_cached_audit_config", None)
    if cfg is None or cached_sentinel != sentinel:
        cfg = AuditConfig.from_namespace(ctx.args)
        try:
            ctx.args._cached_audit_config = cfg
            ctx.args._cached_audit_config_sentinel = sentinel
        except AttributeError:
            pass
    positional: list[Any] = []
    keyword: dict[str, Any] = {}
    for name, parameter in signature.parameters.items():
        if strict_binding is not None and name not in _HOST_STAGE_RUNTIME_ARGUMENTS:
            value = strict_binding.options[name]
        else:
            value = _argument_value_for_hook(name, ctx, cfg)
        if parameter.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD):
            positional.append(value)
        elif parameter.kind is inspect.Parameter.KEYWORD_ONLY:
            keyword[name] = value
        elif parameter.kind is inspect.Parameter.VAR_POSITIONAL:
            positional.extend(
                [
                    ctx.host,
                    int(ctx.port),
                    cfg.timeout,
                    cfg.retries,
                ]
            )
        elif parameter.kind is inspect.Parameter.VAR_KEYWORD:
            continue
    return func, positional, keyword


def _invoke_host_stage(
    func: Callable[..., Any],
    *,
    module: str,
    ctx: AuditHookContext,
    run_deep_checks: bool | None = None,
    strict_binding: _StrictHostStageBinding | None = None,
) -> AuditRecord:
    func, positional, keyword = _prepare_host_stage_call(
        func, module=module, ctx=ctx, run_deep_checks=run_deep_checks, strict_binding=strict_binding
    )
    payload = func(*positional, **keyword)
    if isinstance(payload, AuditRecord):
        return payload
    if isinstance(payload, dict):
        return AuditRecord.from_mapping(payload, module=module, service=module)
    raise TypeError(f"{module} host hook must return AuditRecord-compatible payload")


@dataclass(frozen=True)
class RenderPlan:
    """Precomputed render dispatch for a module (constant across records)."""

    detect: Callable[..., Any] | None
    summary: Callable[..., Any] | None
    details: tuple[tuple[Callable[..., Any], bool], ...]  # (func, takes_debug)


def build_render_plan(render_module: Any) -> RenderPlan:
    """Resolve a module's `_format_*` renderers once (reflection done here, not per record)."""
    detect = getattr(render_module, "_format_detect_record", None) or getattr(render_module, "_detect_line", None)
    summary = getattr(render_module, "_format_record", None)
    details: list[tuple[Callable[..., Any], bool]] = []
    # E7 fix: modules without `__all__` used to lose every detail renderer
    # silently (TXT output collapsed to detect+summary only). Fall back to
    # `dir(render_module)` filtered by the same naming convention.
    candidate_names = getattr(render_module, "__all__", None)
    if not candidate_names:
        candidate_names = tuple(name for name in dir(render_module) if name.startswith("_format"))
    for name in candidate_names:
        if name in {"_format_detect_record", "_format_record", "_detect_line"}:
            continue
        if not (name.startswith("_format") and (name.endswith("_records") or name.endswith("_lines"))):
            continue
        func = getattr(render_module, name, None)
        if not callable(func) or not _can_call_detail_renderer(func):
            continue
        details.append((func, "debug" in _cached_signature(func).parameters))
    return RenderPlan(
        detect if callable(detect) else None,
        summary if callable(summary) else None,
        tuple(details),
    )


def render_with_plan(
    plan: RenderPlan, record_payload: dict[str, Any], output_format: str, *, debug: bool = False
) -> list[str]:
    lines: list[str] = []
    if plan.detect is not None and _record_looks_detected(record_payload):
        try:
            lines.append(str(plan.detect(record_payload, output_format)))
        except TypeError:
            pass
    if plan.summary is not None:
        try:
            lines.append(str(plan.summary(record_payload, output_format)))
        except Exception as exc:  # noqa: BLE001 — render must never abort the scan
            # E5 fix: a broken _format_record used to propagate any exception
            # other than TypeError out through _finalize_record → the whole
            # scan loop was killed. Emit a marker line so operators see the
            # per-record failure but the scan finishes.
            lines.append(f"[!] render summary failed for record: {exc.__class__.__name__}: {exc}")
    for func, takes_debug in plan.details:
        try:
            rendered = (
                func(record_payload, output_format, debug=debug) if takes_debug else func(record_payload, output_format)
            )
        except TypeError:
            continue
        except Exception as exc:  # noqa: BLE001 — see E5 fix above
            lines.append(f"[!] render detail {func.__name__} failed: {exc.__class__.__name__}: {exc}")
            continue
        if rendered:
            lines.extend(str(line) for line in rendered if line)
    return [order_detection_fields(line) if output_format == "txt" else line for line in lines if line]


def render_record_with_module(
    render_module: Any, record: AuditRecord, output_format: str, *, debug: bool = False
) -> list[str]:
    return render_with_plan(build_render_plan(render_module), record.to_dict(), output_format, debug=debug)


def _record_looks_detected(record: AuditRecord | dict[str, Any]) -> bool:
    payload = record.extra if isinstance(record, AuditRecord) else record
    marker_values = [value for key, value in payload.items() if key.startswith("is_")]
    if any(value is True for value in marker_values):
        return True
    if any(value is False for value in marker_values):
        return False
    status_value = (
        payload.get("status") if "status" in payload else record.status if isinstance(record, AuditRecord) else None
    )
    status = str(status_value or "").strip().lower()
    if not status or status == "fail" or status.startswith(("not_", "unknown")):
        return False
    return True


_PRE_DETECT_NOISE_MARKERS = (
    "connect call failed",
    "connection refused",
    "connection reset",
    "reset by peer",
    "connection aborted",
    "operation not permitted",
    "connection timeout",
    "timed out",
    "timeout",
    "unexpected eof",
    "connection has been closed (eof)",
    "protocol closed before",
    "closed before",
    "remote end closed",
    "server closed",
    "no route to host",
    "network unreachable",
    "host is down",
    "dns lookup failed",
    "name or service not known",
    "temporary failure in name resolution",
    "nodename nor servname",
    "getaddrinfo",
    "proxy tunnel",
    "proxy connect",
    "socks",
    "tunnel failed",
    # Cross-module marker for hosts where the peer clearly speaks a
    # different protocol (HTTP admin panel, misconfigured proxy, ...). The
    # Kafka client emits "not a Kafka broker: peer sent HTTP request ..."
    # from `_recv_kafka_frame`; suppressing the whole line in default TXT
    # output keeps scans of large target lists clean while `--debug` still
    # surfaces the full non-Kafka response for diagnosis.
    "not a kafka broker",
    # TLS-side mirror of the same story: hosts on port 9093 (or any TLS-
    # first Kafka port) where the peer isn't actually Kafka/TLS at all.
    # `open_kafka_socket` auto-falls-back to plaintext when TLS was
    # inferred, but if the caller pinned TLS explicitly we surface
    # `TLS handshake failed: peer answered plaintext to TLS ClientHello`
    # or similar — those are non-Kafka network noise, drop them by
    # default and let --debug show them.
    "tls handshake failed",
    "peer answered plaintext to tls",
    "peer closed tls handshake",
    "peer requires client certificate",
    "certificate required",
    "certificate_required",
    "tlsv13_alert_certificate_required",
    "peer rejected tls handshake",
    "wrong_version_number",
    "unexpected_eof_while_reading",
    "sslv3_alert",
)

_PRE_DETECT_OPERATIONAL_MARKERS = (
    "connect call failed",
    "connection refused",
    "connection reset",
    "reset by peer",
    "connection aborted",
    "operation not permitted",
    "connection timeout",
    "timed out",
    "timeout",
    "unexpected eof",
    "connection has been closed (eof)",
    "protocol closed before",
    "closed before",
    "remote end closed",
    "server closed",
    "no route to host",
    "network unreachable",
    "host is down",
    "dns lookup failed",
    "name or service not known",
    "temporary failure in name resolution",
    "nodename nor servname",
    "getaddrinfo",
    "proxy tunnel",
    "proxy connect",
    "socks",
    "tunnel failed",
    "certificate verify failed",
    "peer requires client certificate",
    "certificate required",
    "certificate_required",
    "tlsv13_alert_certificate_required",
    "tlsv1 alert unknown ca",
)


def _record_noise_text(record: AuditRecord | dict[str, Any]) -> str:
    payload = record.extra if isinstance(record, AuditRecord) else record
    values: list[str] = []
    for key in ("error", "protocol_error", "detect_error", "last_error"):
        value = payload.get(key)
        if value:
            values.append(str(value))
    stage_failed_at = payload.get("stage_failed_at")
    if stage_failed_at:
        values.append(f"stage_failed_at={stage_failed_at}")
    stages = payload.get("stages", record.stages if isinstance(record, AuditRecord) else None)
    if isinstance(stages, list) or (isinstance(record, AuditRecord) and isinstance(stages, tuple)):
        for stage in stages:
            stage_error = stage.get("error") if isinstance(stage, dict) else getattr(stage, "error", None)
            if stage_error:
                values.append(str(stage_error))
    debug_events = payload.get("debug_events")
    if isinstance(debug_events, list):
        for event in debug_events:
            if isinstance(event, str):
                values.append(event)
    return " ".join(values).lower()


def _credential_attempt_rate_limited(record: AuditRecord) -> bool:
    """Stop a weak-password sweep when the server limits or locks login attempts."""

    payload = record.to_dict()
    if payload.get("credential_stop_reason") in {"rate_limited", "account_locked", "locked_out"}:
        return True
    if str(payload.get("status") or "").lower() in {"rate_limited", "account_locked", "locked_out"}:
        return True
    for key in ("http_status", "auth_probe_http_status", "auth_http_status"):
        if str(payload.get(key) or "") == "429":
            return True
    message = " ".join(str(payload.get(key) or "") for key in ("error", "auth_error_detail")).lower()
    return any(
        marker in message
        for marker in (
            "rate limit",
            "too many login attempts",
            "too many requests",
            "http 429",
            "status=429",
            "account locked",
            "account has been locked",
        )
    )


def is_pre_detect_network_noise(record: AuditRecord | dict[str, Any]) -> bool:
    """Return true for non-service network/protocol noise before detection.

    These records are useful in debug/JSON, but noisy in normal TXT scans over
    large target lists. The check intentionally refuses to suppress anything
    that already looks like a detected service or an auth/data failure.
    """

    payload = record.extra if isinstance(record, AuditRecord) else record
    if _record_looks_detected(record):
        return False
    status_value = (
        payload.get("status") if "status" in payload else record.status if isinstance(record, AuditRecord) else None
    )
    status = str(status_value or "").lower()
    if status and status not in {"fail", "not_detected", "not_found", "not_service"} and not status.startswith("not_"):
        return False
    if payload.get("error_kind") == "transport_error":
        return True
    text = _record_noise_text(record)
    if not text:
        return False
    return any(marker in text for marker in _PRE_DETECT_NOISE_MARKERS)


def is_pre_detect_operational_failure(record: AuditRecord | dict[str, Any]) -> bool:
    """Return true when detection failed operationally before service proof.

    Runtime-isolated exceptions carry a failed ``detect_protocol`` trace even
    when their message is not one of the known network strings. Legacy module
    records do not always carry phase traces, so the existing bounded network
    marker classifier remains the compatibility fallback.
    """

    payload = record.extra if isinstance(record, AuditRecord) else record
    if _record_looks_detected(record):
        return False
    if (
        payload.get("operational_failure") is True
        or payload.get("detection_status") == "transport_failure"
        or payload.get("error_kind") == "transport_error"
    ):
        return True
    text = _record_noise_text(record)
    return bool(text and any(marker in text for marker in _PRE_DETECT_OPERATIONAL_MARKERS))


def _can_call_detail_renderer(func: Callable[..., Any]) -> bool:
    signature = _cached_signature(func)
    required = [
        name
        for name, parameter in signature.parameters.items()
        if parameter.default is inspect.Parameter.empty
        and parameter.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]
    return len(required) <= 2


def _argument_value_for_hook(name: str, ctx: AuditHookContext, cfg: AuditConfig) -> Any:
    args = ctx.args
    credential = ctx.credential
    if name == "audit_ctx":
        return ctx
    if name == "lifecycle_state":
        return ctx.lifecycle_state
    target_scheme = str(ctx.target.scheme).lower() if ctx.target is not None and ctx.target.scheme else None
    if name == "host":
        return ctx.host
    if name == "port":
        return int(ctx.port)
    if name in {"target", "target_spec"}:
        return ctx.target
    if name in {"target_path", "url_path", "path"}:
        return ctx.target.path if ctx.target is not None and ctx.target.path else None
    if name in {"target_query", "url_query", "query_string"}:
        return ctx.target.query if ctx.target is not None and ctx.target.query else None
    if name == "use_https" and target_scheme in {"http", "https"}:
        return target_scheme == "https"
    if name == "preferred_scheme" and target_scheme in {"http", "https"}:
        return target_scheme
    if name == "timeout":
        return cfg.timeout
    if name == "retries":
        return cfg.retries
    if name == "workers":
        return cfg.workers
    if name == "username":
        return credential.username
    if name == "password":
        return credential.password
    if name in {"token", "api_token", "apitoken", "pve_api_token", "api_key"}:
        return credential.token
    if name == "defcreds":
        return ctx.phase != "detect" and cfg.defcreds and credential.source != "file"
    if name == "run_deep_checks":
        return bool(ctx.run_deep_checks)
    if name == "phase":
        return ctx.phase
    if name == "debug":
        return cfg.debug
    if name == "debug_emit":
        return ctx.debug_emit
    if name == "discover":
        return bool(getattr(args, "discover", False))
    if name == "discover_implicit_dump":
        return bool(getattr(args, "_discover_implicit_dump", False))
    if name == "discovery_started_at":
        return ctx.discovery_started_at
    if name == "discover_ctx":
        return ctx
    if name in {"discover_time", "discover_max_bytes"}:
        return getattr(args, name, None)
    if name == "ssrf_capture":
        return getattr(args, "ssrf_capture", None)
    if name == "proxy":
        # `cli.py` parses --proxy once into `args._proxy_config` (a ProxyConfig).
        # Hand that parsed object through so clients reuse it instead of
        # re-parsing the raw string. Bare test args fall back to the raw value.
        if hasattr(args, "_proxy_config"):
            return args._proxy_config
        return getattr(args, "proxy", None)
    if name == "insecure":
        return not any(
            getattr(args, field, None) for field in ("ca_file", "tls_ca", "ssl_ca", "ssl_server_dn", "wallet")
        )
    if name == "tls_insecure":
        return bool(
            (getattr(args, "tls", False) or getattr(args, "tls_cert_key", None)) and not getattr(args, "tls_ca", None)
        )
    if name == "tls":
        return bool(getattr(args, name, False))
    if name == "sslmode":
        return str(getattr(args, "sslmode", "disable") or "disable")
    if name in {"ssl_ca", "ssl_cert", "ssl_key", "ssl_server_name"}:
        return getattr(args, name, None)
    if name in {"ca_file", "tls_ca", "tls_cert", "tls_key", "cert_file", "key_file"}:
        transport_aliases = {
            "ca_file": ("ca_file", "tls_ca"),
            "tls_ca": ("tls_ca", "ca_file"),
            "tls_cert": ("tls_cert", "cert_file"),
            "tls_key": ("tls_key", "key_file"),
            "cert_file": ("cert_file", "tls_cert"),
            "key_file": ("key_file", "tls_key"),
        }
        for attribute in transport_aliases[name]:
            value = getattr(args, attribute, None)
            if value is not None:
                return value
        return None
    if name == "max_messages":
        raw_max_messages = getattr(args, "max_messages", None)
        if raw_max_messages is not None:
            return int(raw_max_messages)
        dump_limit = dump_flag_limit(getattr(args, "dump", None))
        if dump_limit is not None:
            return int(dump_limit)
        return 10
    if name == "max_messages_explicit":
        # True if user actually set --max-messages OR --dump N; False when
        # the value is the internal default. Kafka renderer uses this to
        # suppress the noisy "(max:10)" header when the user didn't ask.
        if getattr(args, "max_messages", None) is not None:
            return True
        return dump_flag_limit(getattr(args, "dump", None)) is not None
    if name == "probe_write":
        # Kafka --probe-write flag: opt-in destructive per-topic Write-ACL
        # probe (attempts a Produce with a marker record). Silent False when
        # the flag isn't on the args namespace at all — same shape as other
        # opt-in module knobs.
        return bool(getattr(args, "probe_write", False))
    if name == "credential_candidates":
        if ctx.phase == "detect":
            return []
        candidates = ctx.credential_runs or (credential,)
        return [
            {
                "username": item.username,
                "password": item.password or "",
                "source": item.source,
                "default": item.source == "default",
            }
            for item in candidates
            if item.username is not None or item.password is not None
        ]
    if name.endswith("_limit"):
        base = name.removesuffix("_limit")
        raw = getattr(args, base, None)
        if raw is None and base.startswith("show_"):
            raw = getattr(args, base, None)
        if raw is None and base.startswith("dump_"):
            raw = getattr(args, "dump", None)
        if base.startswith("show_"):
            return show_flag_limit(raw)
        return dump_flag_limit(raw)
    if name.startswith("show_"):
        show_aliases = {
            "show_containers": "containers",
            "show_images": "images",
            "show_networks": "networks",
            "show_system": "system",
            "show_tags": "tags",
            "show_volumes": "volumes",
        }
        raw = getattr(args, name, None)
        alias = show_aliases.get(name)
        if raw is None and alias:
            raw = getattr(args, alias, False)
        return show_flag_enabled(raw if raw is not None else False)
    # Numeric dump-pacing controls (not boolean dump toggles): resolve to their int
    # value before the boolean `dump_*` branch below would coerce them via
    # dump_flag_enabled. Defaults mirror the CLI/audit defaults.
    if name in {"dump_batch", "dump_delay"}:
        raw = getattr(args, name, None)
        if raw is not None:
            return int(raw)
        return 10000 if name == "dump_batch" else 20
    if name.startswith("dump_") or name in {
        "dump",
        "dump_requested",
        "dump_all_requested",
        "dump_documents",
        "dump_table_rows",
    }:
        raw = getattr(args, name, getattr(args, "dump", False))
        return dump_flag_enabled(raw)

    aliases = {
        "query_key": "key",
        "kv_key": "key",
        "query_znode": "znode",
        "query_topic": "topic",
        "collection_name": "collection",
        "collection_targets": "collection",
        "query_filter": "query_filter",
        "document_selector": "document_selector",
        "index_filter": "index_filter",
        "nosql_command": "nosql_command",
        "database": "database",
        "table_targets": "table",
        "table_columns": "column",
        "dump_rows": "dump",
        "dump_keys": "dump",
        "execute_command": "execute",
        "sql_command": "sql_cmd",
        "os_read_path": "os_read",
        "pve_api_token": "pveapitoken",
        "use_https": "https",
        "tls_ca": "tls_ca",
        "tls_cert": "tls_cert",
        "tls_key": "tls_key",
        "tls_cert_key": "tls_cert_key",
        "ca_file": "ca_file",
        "preferred_scheme": "scheme",
        "container_selector": "container",
        "exec_cmd": "exec_cmd",
        "exec_command": "exec_cmd",
        "schema_descriptor_bytes": "descriptor_set",
        "invoke_path": "invoke",
        "invoke_request_json": "invoke_json",
        "metadata": "metadata",
        "repository": "repository",
        "tag": "tag",
        "image": "image",
        "download_dir": "download_dir",
    }
    if hasattr(args, name):
        return getattr(args, name)
    alias = aliases.get(name)
    if alias and hasattr(args, alias):
        return getattr(args, alias)
    if name in {"collection_targets_by_database", "table_targets_by_database"}:
        return getattr(args, name, None) or {}
    if name in {"project_filters", "namespace_filters", "service_list", "sid_list", "ssrf_urls"}:
        return getattr(args, name, None) or []
    if name in {"console"}:
        return None
    if name.endswith("s") or name.endswith("_list") or name.endswith("_targets") or name.endswith("_urls"):
        return []
    if name.startswith(("do_", "delete_", "insecure", "clone", "harbor", "gitlab", "nexus", "assets", "inspect")):
        return False
    # Optional scalar inputs that default to None when absent on args. Declared
    # explicitly so the catch-all below stays loud for genuinely-unknown names.
    if name in {
        "agent_dump_name",
        "check_dump_id",
        "container_selector",
        "document_selector",
        "exec_cmd",
        "exec_pod",
        "fs_mode",
        "index_filter",
        "invoke_path",
        "invoke_request_json",
        "listener_dump",
        "metadata",
        "nne_check",
        "node_dump_name",
        "nosql_command",
        "tls_cert_key",
        "on_credential_finding",
        "on_discovered_url",
        "on_status_ready",
        "os_read_path",
        "preferred_scheme",
        "privesc_check",
        "protocol",
        "query_filter",
        "revshell_enabled",
        "service_name",
        "tls_ca",
        "tls_cert",
        "tls_key",
    }:
        return getattr(args, aliases.get(name, name), None)
    raise ValueError(
        f"unresolved hook argument {name!r}: add an explicit mapping in _argument_value_for_hook "
        "(silent None fallback was removed)"
    )


_HTTP_DETECTION_MODULES = frozenset(
    {
        "airflow",
        "consul",
        "docker",
        "elastic",
        "etcd",
        "gitlab",
        "grafana",
        "keycloak",
        "jenkins",
        "vault",
        "nomad",
        "jupyter",
        "kubeapi",
        "minio",
        "proxmox",
        "qdrant",
        "rabbitmq",
        "docker-registry",
        "harbor",
        "nexus",
        "clickhouse",
        "grpc",
    }
)


def _with_http_detection_diagnostics(record: AuditRecord, *, confirmed: bool) -> AuditRecord:
    """Attach a comparable detection verdict without changing legacy fields."""

    module = str(record.module or record.service or "").lower()
    if module not in _HTTP_DETECTION_MODULES:
        return record
    extra = dict(record.extra)
    if confirmed:
        status = "confirmed"
    elif record.status == "cancelled":
        # An unfinished probe is not a conclusive negative fingerprint.
        status = "cancelled"
    elif (
        str(record.status or "").lower() == "probable" or str(extra.get("detection_status") or "").lower() == "probable"
    ):
        status = "probable"
    elif is_pre_detect_operational_failure(record) or str(record.status or "").lower() == "connection_failed":
        status = "transport_failure"
    else:
        status = "not_service"
    signals = extra.get("detection_signals")
    if not isinstance(signals, list):
        signals = []
    signals = [str(signal) for signal in signals if isinstance(signal, str) and signal]
    if not signals:
        signals = [f"{module}.probe"]
    if confirmed and f"{module}.product_fingerprint" not in signals:
        # This code denotes acceptance by the module's strict product parser;
        # it does not assert that any particular optional header was present.
        signals.append(f"{module}.product_fingerprint")
    previous_status = extra.get("detection_status")
    if isinstance(previous_status, str) and previous_status and previous_status != status:
        extra.setdefault("detection_detail_status", previous_status)
    extra.update({"detection_status": status, "detection_signals": signals})
    return replace(record, extra=extra)


class AuditCommandRunner:
    """Command-level runner for staged audit modules.

    The runner owns target grouping execution, command progress, output sinks,
    typed record serialization, and the detect/auth/capabilities/data lifecycle.
    Module hooks at this boundary must return `AuditRecord`.
    """

    def __init__(
        self,
        *,
        args: Any,
        spec: ModuleAuditSpec,
        logger: Any = None,
        emit_line: Callable[[str], None] | None = None,
        console: Any = None,
    ) -> None:
        self.args = args
        self.spec = spec
        self.logger = logger
        self.console = console
        self._strict_host_stage_binding: _StrictHostStageBinding | None
        host_stage_options = getattr(spec, "host_stage_options", None)
        if host_stage_options is not None:
            if spec.host_stage is None:
                raise ValueError(f"{spec.module} host_stage_options require host_stage")
            self._strict_host_stage_binding = _build_strict_host_stage_binding(
                spec.host_stage,
                host_stage_options,
                module=spec.module,
            )
        else:
            self._strict_host_stage_binding = None
        host_stage_signature = (
            self._strict_host_stage_binding.signature
            if self._strict_host_stage_binding is not None
            else (_cached_signature(_resolve_host_stage(spec.host_stage)) if spec.host_stage is not None else None)
        )
        self._host_stage_is_monolithic = bool(
            spec.host_stage is not None
            and spec.detect is None
            and spec.auth is None
            and spec.capabilities is None
            and spec.data is None
            and host_stage_signature is not None
            and "phase" not in host_stage_signature.parameters
        )
        self._host_stage_accepts_credential_batch = bool(
            host_stage_signature is not None and "credential_candidates" in host_stage_signature.parameters
        )
        self._lifecycle_states: dict[int, Any] = {}
        self._lifecycle_states_lock = threading.Lock()
        self._transport_stats_lock = threading.RLock()
        self._transport_pool_refs: dict[int, weakref.ReferenceType[Any]] = {}
        self._transport_owner_ref = weakref.ref(self)
        self._transport_uncertain_pools = 0
        self._transport_stats = {"connections": 0, "reused": 0, "requests": 0, "retries": 0}
        self._fallback_stats = FallbackDiagnostics()
        self._runtime_stats: RuntimeDiagnostics | None = getattr(args, "_runtime_observer", None)
        if self._runtime_stats is None and bool(getattr(args, "debug", False)):
            self._runtime_stats = RuntimeDiagnostics()
        self._collect_transport_stats = bool(getattr(args, "debug", False)) or self._runtime_stats is not None
        from .clients.http_handoff import HttpHandoffBudget

        self._http_handoff_budget = HttpHandoffBudget(64)
        self._nested_scheduler: SharedNestedScheduler | None = None
        self._cve_catalog: CveCatalog | None = None
        self._audit_cancelled = threading.Event()
        self._credential_ledger_lock = threading.RLock()
        self._active_credential_ledgers: dict[int, dict[str, Any]] = {}
        self._completed_credential_ledgers: dict[int, tuple[AuditRecord, Counter[str], int]] = {}
        self._credential_phase_counts: dict[int, Counter[str]] = {}
        self._claimed_logical_targets: set[object] = set()
        if emit_line is not None:
            self.emit_line = emit_line
        elif console is not None:
            colorize = spec.colorize
            if spec.module in web_panels.MODULE_PRODUCTS:

                def _colorize_with_ui(output_console: Any, line: str) -> bool:
                    return web_panels.colorize_panel_line(output_console, line, spec.label) or (
                        colorize(output_console, line) if colorize is not None else False
                    )

                self.emit_line = _build_colored_emit(console, _colorize_with_ui)
            else:
                self.emit_line = _build_colored_emit(console, colorize)
        else:
            self.emit_line = print

    @observe_phase("render")
    def _render_record(
        self, record: AuditRecord, render_plan: RenderPlan | None, output_format: str, debug: bool
    ) -> list[str]:
        if record.extra.get("surface") == "ui" and self.spec.module != "portainer":
            lines = (
                web_panels.render_panel(record.to_dict(), self.spec.label, include_discovery_findings=False)
                if output_format == "txt"
                else []
            )
        elif self.spec.render is not None:
            lines = [line for line in self.spec.render(record) if line]
        elif render_plan is not None:
            lines = render_with_plan(render_plan, record.to_dict(), output_format, debug=debug)
        else:
            lines = []
        if output_format != "txt":
            return lines
        lines = [order_detection_fields(line) for line in lines]
        if self.spec.module in data_discovery.DISCOVERY_MODULES:
            discovery = record.extra.get("content_discovery")
            spooled = isinstance(discovery, Mapping) and isinstance(discovery.get("findings"), SpoolingFindings)
            lines.extend(
                data_discovery.render_discovery(self.spec.module, record.to_dict(), include_findings=not spooled)
            )
        lines = suppress_redundant_auth_requirement(lines)
        cve_lines = render_finding_lines(record.to_dict(), label=self.spec.label, host=record.host, port=record.port)
        if cve_lines:
            if (
                self.spec.defer_phase_output_until_final
                and len(lines) > 1
                and lines[1].split("\t")[-1].lstrip().startswith(("[+]", "[-]"))
            ):
                return [*lines[:2], *cve_lines, *lines[2:]]
            return [*lines[:1], *cve_lines, *lines[1:]]
        return lines

    def _with_cve_enumeration(self, record: AuditRecord) -> AuditRecord:
        if self._cve_catalog is None:
            return record
        payload = record.to_dict()
        credentials_marker = payload.pop("_cve_credentials_verified", None)
        credentials_verified = (
            credentials_marker is True
            if credentials_marker is not None
            else self._record_reports_verified_credentials(payload)
        )
        payload["cve_enumeration"] = enumerate_record(
            self.spec.module,
            payload,
            catalog=self._cve_catalog,
            confirmed=self._is_detected(record),
            resolver=self.spec.cve_product_resolver,
            credentials_provided=credentials_verified,
        )
        return AuditRecord.from_mapping(payload, module=self.spec.module, service=record.service)

    def _cve_explicit_credentials_requested(self) -> bool:
        return any(
            getattr(self.args, field, None) is not None
            for field in (
                "username",
                "password",
                "token",
                "token_file",
                "api_token",
                "apitoken",
                "api_key",
                "pve_api_token",
                "private_token",
                "_jupyter_token",
                "_vault_token",
                "_nomad_token",
                "_keycloak_token",
            )
        )

    def _record_reports_verified_credentials(self, payload: dict[str, Any]) -> bool:
        """Accept PR:L CVEs only after explicitly supplied credentials verify."""

        if not self._cve_explicit_credentials_requested():
            return False
        proof_fields = (
            "provided_credentials_ok",
            "credential_verified",
            "auth_valid",
            "token_valid",
            "credentials_valid",
            "login_success",
        )
        if any(payload.get(field) is False for field in proof_fields):
            return False
        credential_state = str(payload.get("credential_state") or "").strip().lower()
        if credential_state in {"invalid", "unknown", "unverified", "verification_unavailable", "inconclusive"}:
            return False
        if any(payload.get(field) is True for field in (*proof_fields, "credential_accepted")):
            return True
        if credential_state in {"valid", "valid_but_restricted", "authenticated"}:
            return True
        return False

    def _mark_cve_credentials_verified(
        self,
        record: AuditRecord,
        credential: AuditCredentialRun,
        *,
        accepted: bool,
    ) -> AuditRecord:
        if self._cve_catalog is None:
            return record
        explicit_candidate = (
            credential.source != "default"
            and any(value is not None for value in (credential.username, credential.password, credential.token))
            and self._cve_explicit_credentials_requested()
        )
        payload = record.to_dict()
        payload["_cve_credentials_verified"] = bool(accepted and explicit_candidate)
        return AuditRecord.from_mapping(payload, module=self.spec.module, service=record.service)

    def _suppress_in_normal_text(self, record: AuditRecord) -> bool:
        if not self.spec.suppress_undetected_records_in_text or self._is_detected(record):
            return False
        status = str(record.status or "").strip().lower()
        return not status or status == "fail" or status.startswith(("not_", "unknown"))

    def run_plan(self, plan: AuditCommandPlan) -> AuditCommandResult:
        self._audit_cancelled.clear()
        self._active_credential_ledgers.clear()
        self._completed_credential_ledgers.clear()
        self._credential_phase_counts.clear()
        self._claimed_logical_targets.clear()
        if bool(getattr(self.args, "enum_cve", False)):
            self._cve_catalog = load_catalog()
        nested_default = (
            _LARGE_NESTED_WORKERS if plan.target_count >= _LARGE_AUDIT_PLAN_ENDPOINTS else _DEFAULT_NESTED_WORKERS
        )
        self._nested_scheduler = SharedNestedScheduler(max_workers=min(max(1, int(plan.workers or 1)), nested_default))
        try:
            self.args._audit_nested_workers = self._nested_scheduler.max_workers
        except AttributeError:
            # Minimal programmatic callers may pass an opaque sentinel instead
            # of an argparse-style mutable Namespace.
            pass
        if self.console is not None and hasattr(self.console, "set_structured_output"):
            self.console.set_structured_output(plan.output_format == "json")
        sink = LineOutputSink(
            plan.output_path, self.emit_line, append=plan.append, console=self.console, observer=self._runtime_stats
        )
        sink.prepare()
        if self.console is not None and bool(getattr(self.args, "debug", False)) and plan.target_count > 1:
            port_counts = plan.target_counts_by_port()
            credential_count = sum(
                run.username is not None or run.password is not None or run.token is not None
                for run in plan.credential_runs
            )
            debug = getattr(self.console, "debug", None)
            if callable(debug):
                debug(
                    f"Scan plan: addresses={plan.unique_host_count} "
                    f"host:port={plan.target_count} workers={plan.workers} "
                    f"nested_workers={self._nested_scheduler.max_workers} "
                    f"auth_attempts_up_to={plan.target_count * credential_count}"
                )
                debug("Ports: " + ", ".join(f"{port}={count}" for port, count in port_counts.items()))
        # Data hooks may stream lines live (real-time output) via this sink, but only
        # for TXT; JSON stays a single serialized record per target.
        live_cancelled = threading.Event()

        def _emit_live(lines: Iterable[str]) -> None:
            if not live_cancelled.is_set():
                sink.emit_many(lines)

        self._live_emit = _emit_live if plan.output_format == "txt" else None
        completed = False
        try:
            report_emit = None
            if bool(getattr(self.args, "debug", False)):
                report_emit = getattr(self.console, "debug", None) or getattr(self.args, "debug_emit", None)
            reporting = self._runtime_stats.reporting(report_emit) if self._runtime_stats is not None else nullcontext()
            with capture_fallbacks(self._fallback_stats), reporting:
                result = self._run_prepared_plan(plan, sink)
            completed = True
            return result
        finally:
            self._audit_cancelled.set()
            live_cancelled.set()
            if not completed and self._nested_scheduler is not None:
                self._nested_scheduler.cancel()
            self._close_all_lifecycle_states()
            if self._nested_scheduler is not None:
                if completed:
                    self._nested_scheduler.close()
            sink.close()
            if self.console is not None and bool(getattr(self.args, "debug", False)):
                tls_stats = tls_context_cache_stats()
                debug_method = getattr(self.console, "debug", None)
                if callable(debug_method):
                    debug_method(
                        "transport summary: "
                        f"requests={self._transport_stats['requests']} "
                        f"connections={self._transport_stats['connections']} "
                        f"reused={self._transport_stats['reused']} "
                        f"retries={self._transport_stats['retries']} "
                        f"tls_contexts={tls_stats['size']} tls_cache_hits={tls_stats['hits']} "
                        f"complete={self._transport_uncertain_pools == 0} "
                        f"untracked_snapshots={self._transport_uncertain_pools}"
                    )
                    for line in self._fallback_stats.debug_lines():
                        debug_method(line)
                    if self._runtime_stats is not None:
                        for line in self._runtime_stats.debug_lines():
                            debug_method(line)

    def _run_prepared_plan(self, plan: AuditCommandPlan, sink: LineOutputSink) -> AuditCommandResult:
        target_count = plan.target_count
        configured_retention_limit = getattr(self.spec, "record_retention_limit", None)
        retention_limit = (
            DEFAULT_RECORD_RETENTION_LIMIT
            if configured_retention_limit is None
            else max(0, int(configured_retention_limit))
        )
        retain_records = target_count <= retention_limit
        # E6 fix: when target_count exceeds the retention limit, downstream
        # consumers (exporters, summary renderers) that iterate
        # `AuditCommandResult.records` used to get an empty list without any
        # indication. Emit a one-shot debug marker so operators can trace
        # "0-length result but N hosts probed" in the run log.
        if not retain_records:
            debug_emit_early = getattr(self.args, "debug_emit", None)
            if callable(debug_emit_early):
                debug_emit_early(
                    f"[!] record retention disabled: {target_count} targets exceed limit "
                    f"{retention_limit}; AuditCommandResult.records will be empty"
                )
        progress_refresh_interval_s = getattr(self.spec, "progress_refresh_interval_s", None)
        if progress_refresh_interval_s is not None:
            # Carry the module opt-in through args so compatibility shims and
            # tests that replace ``start_command_progress`` keep its historical
            # call signature.
            self.args._progress_refresh_interval_s = float(progress_refresh_interval_s)
        progress = start_command_progress(
            self.args,
            self.spec.label,
            target_count,
            enabled=should_use_global_progress(plan.output_format, target_count),
            leave=False,
        )
        worker_count = max(1, int(plan.workers or getattr(self.args, "workers", 1) or 1))
        if self._runtime_stats is not None:
            self._runtime_stats.configure(targets=target_count, deep_workers=worker_count, detect_limit=0)
        self._http_handoff_budget.limit = min(64, worker_count)
        scheduler: BoundedScheduler[tuple[int, str, int, ScanTargetSpec | None], _AuditPipelineOutcome] = (
            BoundedScheduler(max_workers=worker_count, observer=self._runtime_stats)
        )
        emitted_lines = 0
        suppressed_records = 0
        retained_records: list[AuditRecord] = []
        record_count = 0
        detected_count = 0
        operational_failure_count = 0
        conclusive_negative_count = 0
        status_counts: dict[str, int] = {}
        record_callbacks = _record_callbacks_for_args(self.args)
        render_plan = build_render_plan(self.spec.render_module) if self.spec.render_module is not None else None
        debug = bool(getattr(self.args, "debug", False))
        raw_debug_emit = getattr(self.args, "debug_emit", None) if debug else None
        cancelled = self._audit_cancelled
        fallback_detect_started_at: dict[int, float] = {}
        fallback_start_lock = threading.Lock()

        def _emit_target_live(lines: Iterable[str]) -> None:
            # A long-running target must publish its confirmed findings while
            # other targets are still active. The sink serializes each batch
            # across threads and tees it to the console and TXT output.
            # A ledger phase holds _credential_ledger_lock until its counted
            # output is written. Cancellation waits for that lock before
            # flushing the remainder; dropping this batch would lose lines.
            if not cancelled.is_set() or _CREDENTIAL_PHASE_EMIT_ACTIVE.get():
                sink.emit_many(lines)

        def _emit_target_disk(*args: Any, **kwargs: Any) -> None:
            if not cancelled.is_set() or _CREDENTIAL_PHASE_EMIT_ACTIVE.get():
                sink.emit_discovery_value(*args, **kwargs)

        def _emit_target_stream(path: str) -> int:
            if not cancelled.is_set() or _CREDENTIAL_PHASE_EMIT_ACTIVE.get():
                return sink.emit_stream_file(path)
            return 0

        def _run_target(
            item: tuple[int, str, int, ScanTargetSpec | None], prepared: _AuditDetectOutcome | None = None
        ) -> _AuditPipelineOutcome:
            return run_paused_sync(_run_target_steps(item, prepared))

        def _run_target_steps(
            item: tuple[int, str, int, ScanTargetSpec | None], prepared: _AuditDetectOutcome | None = None
        ) -> Generator[WorkPause, None, _AuditPipelineOutcome]:
            job_token = _CREDENTIAL_JOB_ID.set(
                -next(_CREDENTIAL_JOB_IDS) if self.spec.auth_wait is not None else _CREDENTIAL_JOB_ID.get()
            )
            token = _TARGET_LIVE_EMIT.set(_emit_target_live if plan.output_format == "txt" else None)
            disk_token = _TARGET_DISK_EMIT.set(_emit_target_disk if plan.output_format == "txt" else None)
            stream_token = _TARGET_STREAM_EMIT.set(_emit_target_stream if plan.output_format == "txt" else None)
            with fallback_start_lock:
                fallback_started_at = fallback_detect_started_at.pop(item[0], None)
            discovery_token = _TARGET_DISCOVERY_STARTED_AT.set(
                prepared.started_at
                if prepared is not None and prepared.started_at is not None
                else fallback_started_at
                if fallback_started_at is not None
                else time.monotonic()
            )
            try:
                with (
                    capture_fallbacks(self._fallback_stats),
                    sync_fallback(self.spec.module if fallback_started_at is not None else None),
                ):
                    if self.spec.auth_wait is None:
                        # Keep the established synchronous hook for consumers
                        # without resumable authentication, including wrappers
                        # that track worker completion during cancellation.
                        outcome = (
                            self._run_target_pipeline(item[1], item[2], item[3], plan.credential_runs, debug_emit)
                            if prepared is None
                            else self._run_target_pipeline(
                                item[1], item[2], item[3], plan.credential_runs, debug_emit, prepared_detect=prepared
                            )
                        )
                    elif prepared is None:
                        outcome = yield from self._run_target_pipeline_steps(
                            item[1], item[2], item[3], plan.credential_runs, debug_emit
                        )
                    else:
                        outcome = yield from self._run_target_pipeline_steps(
                            item[1], item[2], item[3], plan.credential_runs, debug_emit, prepared_detect=prepared
                        )
                if self.spec.record_skipped_credential_attempts and not outcome.duplicate_target:
                    with self._credential_ledger_lock:
                        ledger = self._active_credential_ledgers.get(_credential_job_key())
                        if ledger is not None and not self._audit_cancelled.is_set():
                            worker_id = _credential_job_key()
                            phase_counts = self._credential_phase_counts.pop(worker_id, Counter()).copy()
                            # One atomic handoff: cancellation must see either
                            # the active ledger or the completed record, never both.
                            self._active_credential_ledgers.pop(worker_id, None)
                            self._completed_credential_ledgers[id(outcome.record)] = (
                                outcome.record,
                                phase_counts,
                                ledger["debug_count"],
                            )
                return outcome
            except BaseException as exc:
                if self.spec.record_skipped_credential_attempts or isinstance(exc, GeneratorExit):
                    self._audit_cancelled.set()
                raise
            finally:
                if self.spec.record_skipped_credential_attempts and not self._audit_cancelled.is_set():
                    with self._credential_ledger_lock:
                        self._active_credential_ledgers.pop(_credential_job_key(), None)
                        self._credential_phase_counts.pop(_credential_job_key(), None)
                _TARGET_DISCOVERY_STARTED_AT.reset(discovery_token)
                _TARGET_DISK_EMIT.reset(disk_token)
                _TARGET_STREAM_EMIT.reset(stream_token)
                _TARGET_LIVE_EMIT.reset(token)
                _CREDENTIAL_JOB_ID.reset(job_token)

        def _debug_emit(message: str) -> None:
            # BoundedScheduler deliberately detaches active daemon workers on
            # cancellation. Do not let those workers keep writing debug output
            # after the coordinator has returned control to the caller.
            if not cancelled.is_set() and callable(raw_debug_emit):
                raw_debug_emit(message)

        debug_emit = _debug_emit if callable(raw_debug_emit) else None
        if debug_emit is not None:
            debug_emit(format_pass_marker(1, "detect", "start", total=target_count, mode="pipeline"))
            nested_workers = self._nested_scheduler.max_workers if self._nested_scheduler is not None else 0
            debug_emit(f"worker profile: targets={target_count} workers={worker_count} nested_workers={nested_workers}")

        def _emit_record(record: AuditRecord, deferred_summaries: Iterable[str] = ()) -> None:
            nonlocal emitted_lines, suppressed_records
            # A record may buffer a large, pre-formatted section (e.g. a streamed
            # minio object listing) into a temp file; emit it after the static
            # content and always delete it, even when the record is suppressed.
            stream_file = record.extra.get("_stream_lines_file") if isinstance(record.extra, dict) else None
            discovery = record.extra.get("content_discovery") if isinstance(record.extra, dict) else None
            spooled = isinstance(discovery, Mapping) and isinstance(discovery.get("findings"), SpoolingFindings)
            airflow_discovery = record.extra.get("discover_report") if isinstance(record.extra, dict) else None
            airflow_spooled = isinstance(airflow_discovery, Mapping) and (
                isinstance(airflow_discovery.get("findings"), SpoolingFindings)
                or isinstance(airflow_discovery.get("variable_keys"), SpoolingStrings)
            )
            elastic_spooled = isinstance(record.extra.get("discover_findings"), SpoolingFindings)
            source_spooled = contains_spooled(record.extra)
            completion_lines = list(deferred_summaries)

            def emit_discovery_footer() -> None:
                nonlocal emitted_lines
                if record.extra.get("surface") == "ui" and self.spec.module != "portainer":
                    for chunks in web_panels.iter_panel_discovery_chunks(record.to_dict(), self.spec.label):
                        sink.emit_text_chunks(chunks)
                        emitted_lines += 1
                if debug:
                    for line in iter_discovery_source_lines(self.spec.module, record.host, record.port, record.extra):
                        sink.emit_many([line])
                        emitted_lines += 1
                    for chunks in iter_discovery_location_lines(
                        self.spec.module, record.host, record.port, record.extra
                    ):
                        sink.emit_text_chunks(chunks)
                        emitted_lines += 1
                sink.emit_many(completion_lines)
                emitted_lines += len(completion_lines)

            def emit_pending_clickhouse_disk_findings() -> int:
                if self.spec.module != "clickhouse" or record.extra.get("_clickhouse_disk_live_emitted"):
                    return 0
                report = record.extra.get("discover_report")
                pending = report.get("findings") if isinstance(report, Mapping) else None
                if not isinstance(pending, list):
                    return 0
                from .modules.clickhouse.actions import _clickhouse_discovery_place

                count = 0
                for finding in pending:
                    value = finding.get("value") if isinstance(finding, Mapping) else None
                    if isinstance(value, DiskBackedText):
                        sink.emit_discovery_value(
                            "CLICKHOUSE",
                            record.host,
                            record.port,
                            finding_type=finding.get("type"),
                            value=value,
                            place=_clickhouse_discovery_place(finding),
                        )
                        count += 1
                return count

            def emit_pending_spooled_findings() -> int:
                if not spooled:
                    return 0
                count = 0
                batch: list[str] = []
                assert isinstance(discovery, Mapping)
                pending = discovery["findings"]
                assert isinstance(pending, SpoolingFindings)
                for finding in pending.iter_unemitted():
                    value = finding.get("value")
                    if isinstance(value, DiskBackedText):
                        if batch:
                            sink.emit_many(batch)
                            count += len(batch)
                            batch.clear()
                        sink.emit_discovery_value(
                            self.spec.module.upper(),
                            record.host,
                            record.port,
                            finding_type=finding.get("type"),
                            value=value,
                            place=finding.get("object_path"),
                        )
                        count += 1
                        continue
                    batch.append(
                        format_discovery_finding_line(
                            self.spec.module.upper(),
                            record.host,
                            record.port,
                            severity=finding.get("confidence"),
                            finding_type=finding.get("type"),
                            value=value,
                            place=finding.get("object_path"),
                        )
                    )
                    if len(batch) >= 256:
                        sink.emit_many(batch)
                        count += len(batch)
                        batch.clear()
                if batch:
                    sink.emit_many(batch)
                    count += len(batch)
                return count

            def emit_pending_airflow_findings() -> int:
                if record.extra.get("_airflow_spooled_phase_emitted"):
                    return 0
                if not airflow_spooled or not isinstance(airflow_discovery, Mapping):
                    return 0
                pending = airflow_discovery.get("findings")
                if not isinstance(pending, SpoolingFindings):
                    return 0
                count = 0
                for finding in pending.iter_unemitted():
                    place = finding.get("place") or finding.get("object_path")
                    value = finding.get("value")
                    if isinstance(value, DiskBackedText):
                        sink.emit_discovery_value(
                            "AIRFLOW",
                            record.host,
                            record.port,
                            finding_type=finding.get("type"),
                            value=value,
                            place=place,
                        )
                    else:
                        sink.emit_many(
                            (
                                format_discovery_finding_line(
                                    "AIRFLOW",
                                    record.host,
                                    record.port,
                                    severity=finding.get("confidence"),
                                    finding_type=finding.get("type"),
                                    value=value,
                                    place=place,
                                ),
                            )
                        )
                    count += 1
                return count

            def emit_pending_elastic_disk_findings() -> int:
                if (
                    not elastic_spooled
                    or record.extra.get("_elastic_disk_live_emitted")
                    or record.extra.get("_elastic_disk_phase_emitted")
                ):
                    return 0
                pending = record.extra.get("discover_findings")
                if not isinstance(pending, SpoolingFindings):
                    return 0
                count = 0
                for finding in pending:
                    value = finding.get("value")
                    if not isinstance(value, DiskBackedText):
                        continue
                    locations = finding.get("locations")
                    first = locations[0] if isinstance(locations, list) and locations else None
                    parts = []
                    if isinstance(first, Mapping):
                        for key in ("source_kind", "object", "index", "id", "path"):
                            item = first.get(key)
                            if item is not None and str(item).strip():
                                parts.append(f"{key}:{item}")
                    sink.emit_discovery_value(
                        "ELASTIC",
                        record.host,
                        record.port,
                        finding_type=finding.get("secret_type"),
                        value=value,
                        place="/".join(parts) or "unknown",
                    )
                    count += 1
                return count

            try:
                if plan.output_format == "json":
                    payload = record.to_dict()
                    for field_name in self.spec.structured_output_redact_fields:
                        payload.pop(field_name, None)
                    if "provided_password" in self.spec.structured_output_redact_fields:
                        attempts = payload.get("attempted_credentials")
                        if isinstance(attempts, list):
                            payload["attempted_credentials"] = [
                                {**item, "password": "<redacted>"}
                                if isinstance(item, dict) and item.get("password") is not None
                                else item
                                for item in attempts
                            ]
                    payload.pop("_stream_lines_file", None)
                    emitted_lines += 1
                    if source_spooled or contains_disk_backed(payload):
                        sink.emit_json_chunks(iter_json_chunks(payload))
                    elif spooled or airflow_spooled or elastic_spooled or source_spooled:
                        sink.emit_json_chunks(json.JSONEncoder(ensure_ascii=False).iterencode(payload))
                    else:
                        sink.emit_many((json.dumps(payload, ensure_ascii=False),))
                    if stream_file:
                        emitted_lines += sink.emit_stream_file(stream_file)
                    return
                if isinstance(record.extra, dict) and record.extra.get("_self_emitted"):
                    # A data hook already streamed this record's TXT lines live
                    # (real-time discovery); do not render it again.
                    emitted_lines += int(record.extra.get("_self_emitted_lines") or 0)
                    if not record.extra.get("_cve_self_emitted"):
                        cve_lines = render_finding_lines(
                            record.to_dict(), label=self.spec.label, host=record.host, port=record.port
                        )
                        emitted_lines += len(cve_lines)
                        sink.emit_many(cve_lines)
                    if not record.extra.get("_spooled_findings_phase_emitted"):
                        emitted_lines += emit_pending_spooled_findings()
                    emitted_lines += emit_pending_airflow_findings()
                    emitted_lines += emit_pending_elastic_disk_findings()
                    emitted_lines += emit_pending_clickhouse_disk_findings()
                    if stream_file:
                        emitted_lines += sink.emit_stream_file(stream_file)
                    emit_discovery_footer()
                    return
                if self.spec.render is None and self.spec.render_module is None:
                    return
                if not debug and self._suppress_in_normal_text(record):
                    suppressed_records += 1
                    return
                lines = self._render_record(record, render_plan, plan.output_format, debug)
                completion_lines.extend(line for line in lines if _is_discovery_summary_line(line))
                lines = [line for line in lines if not _is_discovery_summary_line(line)]
                emitted_lines += len(lines)
                if self.spec.module == "clickhouse":
                    summary_index = next(
                        (index for index, line in enumerate(lines) if "Discover Secrets (status:" in line), len(lines)
                    )
                    sink.emit_many(lines[:summary_index])
                    emitted_lines += emit_pending_clickhouse_disk_findings()
                    sink.emit_many(lines[summary_index:])
                elif spooled:
                    summary_index = next(
                        (index for index, line in enumerate(lines) if "Discover Secrets (status:" in line), len(lines)
                    )
                    sink.emit_many(lines[:summary_index])
                    emitted_lines += emit_pending_spooled_findings()
                    sink.emit_many(lines[summary_index:])
                elif airflow_spooled:
                    summary_index = next(
                        (index for index, line in enumerate(lines) if "Discover Secrets (status:" in line), len(lines)
                    )
                    sink.emit_many(lines[:summary_index])
                    emitted_lines += emit_pending_airflow_findings()
                    sink.emit_many(lines[summary_index:])
                elif elastic_spooled:
                    summary_index = next(
                        (
                            index
                            for index, line in enumerate(lines)
                            if "Discover Complete (status:" in line or "Discover Secrets (status:" in line
                        ),
                        len(lines),
                    )
                    sink.emit_many(lines[:summary_index])
                    emitted_lines += emit_pending_elastic_disk_findings()
                    sink.emit_many(lines[summary_index:])
                else:
                    sink.emit_many(lines)
                if stream_file:
                    emitted_lines += sink.emit_stream_file(stream_file)
                emit_discovery_footer()
            finally:
                if stream_file:
                    try:
                        os.remove(stream_file)
                    except OSError:
                        pass

        def _finalize_record(record: AuditRecord) -> None:
            nonlocal operational_failure_count, record_count, conclusive_negative_count
            deferred_summaries = record.extra.pop("_discovery_summary_lines", ())
            ledger_record_id = id(record)
            record_detected = self._is_detected(record)
            record = _with_http_detection_diagnostics(record, confirmed=record_detected)
            record = self._with_cve_enumeration(record)
            if debug_emit is not None and self.spec.module in _HTTP_DETECTION_MODULES:
                debug_emit(
                    f"detection: host={record.host} port={record.port} "
                    f"status={record.extra.get('detection_status')} "
                    f"signals={','.join(record.extra.get('detection_signals') or []) or '-'}"
                )
            if debug_emit is not None and self._cve_catalog is not None:
                cve_result = record.extra.get("cve_enumeration")
                if isinstance(cve_result, dict):
                    products = (
                        ",".join(
                            f"{item.get('product_key')}:{item.get('normalized_version') or '-'}"
                            for item in cve_result.get("products", [])
                            if isinstance(item, dict)
                        )
                        or "-"
                    )
                    debug_emit(
                        f"cve enumeration: host={record.host} port={record.port} "
                        f"catalog={cve_result.get('catalog_version')} status={cve_result.get('status')} "
                        f"products={products} evidence={len(cve_result.get('additional_evidence') or [])} "
                        f"reason={cve_result.get('reason') or '-'}"
                    )
            record_count += 1
            # A confirmed product can still fail operationally in auth/data.
            # Keep its detection evidence, but count the explicit failure so
            # the run is partial and exits nonzero.
            operational_failure = record.extra.get("operational_failure") is True or is_pre_detect_operational_failure(
                record
            )
            operational_failure_count += int(operational_failure)
            # Count records, including companion surfaces, independently of
            # the root-only detected_count. A confirmed service is never a
            # conclusive negative, even when a later auth/data phase fails.
            conclusive_negative_count += int(not record_detected and not operational_failure)
            status = str(record.status or "")
            status_counts[status] = status_counts.get(status, 0) + 1
            if retain_records:
                retained_records.append(record)
            if record_callbacks:
                payload = record.to_dict()
                for record_callback in record_callbacks:
                    record_callback(dict(payload))
            _emit_record(record, deferred_summaries)
            if self.spec.record_skipped_credential_attempts:
                with self._credential_ledger_lock:
                    self._completed_credential_ledgers.pop(ledger_record_id, None)

        total_deep_candidates = 0
        processed_deep = 0
        from .async_detection import (
            AsyncDetectScheduler,
            async_detection_allowed,
            automatic_detect_concurrency,
        )

        use_async_detect = (
            getattr(self.spec, "detect_async", None) is not None
            and self.spec.detect is getattr(self.spec, "async_detect_sync_hook", None)
            and target_count >= 32
            and async_detection_allowed(self.args)
        )
        detect_concurrency = 0
        if use_async_detect:
            override = getattr(self.args, "_async_detect_concurrency", None)
            detect_concurrency = (
                max(1, int(override))
                if override is not None
                else automatic_detect_concurrency(
                    target_count, deep_workers=worker_count, retained_fds=self._http_handoff_budget.limit
                )
            )
        if use_async_detect and detect_concurrency > 0:

            async def _detect_item(item: tuple[int, str, int, ScanTargetSpec | None]) -> _AuditDetectOutcome | None:
                started_at = time.monotonic()
                outcome = await self._run_async_detect_with_state(item[1], item[2], item[3], debug_emit)
                if outcome is not None and self._is_detected(outcome.record):
                    other_target = self._additional_surface_target(outcome.record, item[3], item[2])
                    if other_target is not None:
                        outcome = replace(outcome, additional_surface_scheduled=True)
                if outcome is None:
                    with fallback_start_lock:
                        fallback_detect_started_at[item[0]] = started_at
                return outcome

            def _detect_children(
                item: tuple[int, str, int, ScanTargetSpec | None], prepared: _AuditDetectOutcome | None
            ) -> Iterable[tuple[int, str, int, ScanTargetSpec | None]]:
                if prepared is not None and prepared.additional_surface_scheduled:
                    target = self._additional_surface_target(prepared.record, item[3], item[2])
                    if target is not None:
                        yield (-item[0] - 1, item[1], item[2], target)

            # The runner also sets its ledger flag when a hook raises. Feeding
            # that flag into the async watch would discard the worker's error
            # as an operator cancellation before it reaches this consumer.
            # Closing outcomes below already cancels the async scheduler.
            finish_options: dict[str, Any] = (
                {"finish_steps": _run_target_steps} if self.spec.auth_wait is not None else {}
            )
            outcomes = AsyncDetectScheduler[
                tuple[int, str, int, ScanTargetSpec | None], _AuditDetectOutcome | None, _AuditPipelineOutcome
            ](
                detect_workers=detect_concurrency,
                deep_workers=worker_count,
                observer=self._runtime_stats,
            ).iter_completed(
                plan.iter_target_specs(),
                _detect_item,
                _run_target,
                inline_finish=lambda _item, prepared: (
                    prepared is not None and prepared.lifecycle_state is None and not self._is_detected(prepared.record)
                ),
                detect_children=_detect_children,
                **finish_options,
            )
            if debug_emit is not None:
                debug_emit(
                    f"detection engine: native_async concurrency={detect_concurrency} "
                    f"deep_workers={worker_count} policy=fixed"
                )
        else:
            if self.spec.auth_wait is not None:
                outcomes = scheduler.iter_paused(plan.iter_target_specs(), _run_target_steps, cancelled=cancelled)
            else:
                outcomes = scheduler.iter_completed(plan.iter_target_specs(), _run_target)
        try:
            for (_idx, _host, _port, _target), outcome in outcomes:
                if _idx < 0:
                    # Secondary surfaces are independent records, not extra
                    # logical input targets in progress/run-level counts.
                    if outcome.detected and not outcome.duplicate_target:
                        _finalize_record(outcome.record)
                    continue
                if outcome.duplicate_target:
                    progress.advance(1)
                    continue
                detected_count += int(outcome.detected)
                total_deep_candidates += int(outcome.deep_candidate)
                processed_deep += int(outcome.deep_processed)
                # The progress total retains the historical detect+deep
                # accounting, but both units are advanced only when that
                # target's corresponding lifecycle has actually completed.
                progress.advance(1)
                if outcome.detected:
                    progress.add_total(1)
                    progress.advance(1)
                _finalize_record(outcome.record)
                for surface_record in outcome.additional_records:
                    _finalize_record(surface_record)
        except BaseException:
            cancelled.set()
            if self.spec.record_skipped_credential_attempts:
                cancelled_records = self._cancelled_credential_records()
                self._close_all_lifecycle_states()
                for record, prior_counts, debug_start in cancelled_records:
                    if callable(raw_debug_emit):
                        self._debug_credential_ledger(record, raw_debug_emit, start=debug_start)
                    if plan.output_format == "txt":
                        rendered = self._render_record(record, render_plan, "txt", debug)
                        counts: Counter[str] = Counter()
                        pending = []
                        for line in rendered:
                            key = self.spec.phase_output_key(record, line) if self.spec.phase_output_key else line
                            counts[key] += 1
                            if counts[key] > prior_counts[key]:
                                pending.append(line)
                        summaries = [line for line in pending if _is_discovery_summary_line(line)]
                        pending = [line for line in pending if not _is_discovery_summary_line(line)]
                        if summaries:
                            record.extra["_discovery_summary_lines"] = summaries
                        sink.emit_many(pending)
                        record = replace(
                            record, extra={**record.extra, "_self_emitted": True, "_self_emitted_lines": len(pending)}
                        )
                    _finalize_record(record)
            raise
        finally:
            close_outcomes = getattr(outcomes, "close", None)
            if callable(close_outcomes):
                close_outcomes()
            progress.close()
        if debug_emit is not None:
            debug_emit(
                format_pass_marker(
                    1,
                    "detect",
                    "complete",
                    detected=detected_count,
                    deep_candidates=total_deep_candidates,
                    mode="pipeline",
                )
            )
            # Keep the legacy aggregate phase marker for log consumers while
            # declaring that no global detect-before-deep barrier exists.
            debug_emit(format_pass_marker(2, "deep", "start", total=total_deep_candidates, mode="pipeline"))
            debug_emit(format_pass_marker(2, "deep", "complete", processed=processed_deep, mode="pipeline"))

        fallback_target_count = record_count or plan.fallback_target_count
        inconclusive = detected_count == 0 and operational_failure_count > 0
        partial = detected_count > 0 and operational_failure_count > 0
        no_service_message = (
            f"No {self.spec.label} service detected on {fallback_target_count} target(s)"
            if fallback_target_count > 1
            else f"No {self.spec.label} service detected on target"
        )
        summary_emitted = False
        if (inconclusive or partial) and plan.output_format == "json":
            summary = {
                "type": "summary",
                "module": self.spec.module,
                "service": self.spec.module,
                "status": "inconclusive" if inconclusive else "partial",
                "requested_targets": int(plan.fallback_target_count),
                "processed_targets": int(record_count),
                "record_count": int(record_count),
                "detected_count": int(detected_count),
                "operational_failure_count": int(operational_failure_count),
                "conclusive_negative_count": int(conclusive_negative_count),
                "reason": "operational_failures_before_detection" if inconclusive else "partial_operational_failure",
            }
            emitted_lines += 1
            summary_emitted = True
            sink.emit_many((json.dumps(summary, ensure_ascii=False),))
        elif record_count == 0 and plan.fallback_target_count > 0 and plan.output_format == "json":
            summary = {
                "type": "summary",
                "module": self.spec.module,
                "service": self.spec.module,
                "status": "no_results",
                "requested_targets": int(plan.fallback_target_count),
                "processed_targets": 0,
                "record_count": 0,
                "detected_count": 0,
                "reason": "no_service_detected",
            }
            emitted_lines += 1
            summary_emitted = True
            sink.emit_many((json.dumps(summary, ensure_ascii=False),))
        elif inconclusive and plan.output_format != "json":
            total = fallback_target_count
            target_word = "target" if total == 1 else "targets"
            fallback_lines = (
                f"[!] {no_service_message}; "
                f"{operational_failure_count}/{total} {target_word} unreachable or failed before detection",
            )
            emitted_lines += len(fallback_lines)
            summary_emitted = True
            sink.emit_many(fallback_lines)
        elif detected_count == 0 and emitted_lines == 0 and fallback_target_count > 0 and plan.output_format != "json":
            fallback_lines = (f"[*] {no_service_message}",)
            emitted_lines += len(fallback_lines)
            summary_emitted = True
            sink.emit_many(fallback_lines)

        return AuditCommandResult(
            records=[record.to_dict() for record in retained_records],
            detected_count=detected_count,
            emitted_lines=emitted_lines,
            typed_records=retained_records,
            suppressed_records=suppressed_records,
            record_count=record_count,
            status_counts=status_counts,
            record_retention_truncated=not retain_records,
            operational_failure_count=operational_failure_count,
            summary_emitted=summary_emitted,
        )

    def _ctx(
        self,
        host: str,
        port: int,
        target: ScanTargetSpec | None,
        credential: AuditCredentialRun,
        *,
        phase: AuditPhase,
        run_deep_checks: bool,
        debug_emit: Callable[[str], None] | None,
        credential_runs: tuple[AuditCredentialRun, ...] = (),
        lifecycle_state: Any = None,
    ) -> AuditHookContext:
        return AuditHookContext(
            args=self.args,
            logger=self.logger,
            host=str(host),
            port=int(port),
            credential=credential,
            target=target,
            run_deep_checks=bool(run_deep_checks),
            debug_emit=debug_emit,
            phase=phase,
            credential_runs=credential_runs,
            lifecycle_state=lifecycle_state,
            nested_scheduler=self._nested_scheduler,
            live_emit=(
                None
                if phase == "data"
                and self.spec.defer_discovery_findings_until_final
                and bool(getattr(self.args, "discover", False))
                else _TARGET_LIVE_EMIT.get() or getattr(self, "_live_emit", None)
            ),
            live_discovery_value=_TARGET_DISK_EMIT.get(),
            discovery_started_at=_TARGET_DISCOVERY_STARTED_AT.get(),
            cancelled=self._audit_cancelled.is_set,
            reuse_http=True,
            session_budget=self._http_handoff_budget,
        )

    def _register_lifecycle_state(self, state: Any) -> None:
        if state is None:
            return
        with self._lifecycle_states_lock:
            self._lifecycle_states[id(state)] = state

    def _close_lifecycle_state(self, state: Any) -> None:
        if state is None:
            return
        with self._lifecycle_states_lock:
            registered = self._lifecycle_states.pop(id(state), None)
        if registered is None:
            return
        self._capture_transport_stats(registered)
        self._close_panel_http(registered)
        close = getattr(self.spec, "lifecycle_state_close", None)
        if close is None:
            return
        try:
            close(registered)
        except Exception:  # noqa: BLE001 - cleanup must not replace the audit result
            return

    def _close_all_lifecycle_states(self) -> None:
        with self._lifecycle_states_lock:
            states = list(self._lifecycle_states.values())
            self._lifecycle_states.clear()
        close = getattr(self.spec, "lifecycle_state_close", None)
        for state in states:
            self._capture_transport_stats(state)
            self._close_panel_http(state)
            if close is None:
                continue
            try:
                close(state)
            except Exception:  # noqa: BLE001 - best-effort outer cleanup
                continue

    @staticmethod
    def _close_panel_http(state: Any) -> None:
        from .web_panels import close_panel_http

        close_panel_http(state)

    def _capture_transport_stats(self, state: Any) -> None:
        if not self._collect_transport_stats:
            return
        local_seen: set[int] = set()
        for candidate in (
            state,
            getattr(state, "http", None),
            getattr(state, "pool", None),
            getattr(state, "http_session", None),
            getattr(state, "http_pool", None),
            getattr(state, "_panel_http", None),
        ):
            stats_fn = getattr(candidate, "stats", None)
            if candidate is None or not callable(stats_fn):
                continue
            identity = id(candidate)
            if identity in local_seen:
                continue
            local_seen.add(identity)
            with self._transport_stats_lock:
                previous = self._transport_pool_refs.get(identity)
                if previous is not None and previous() is candidate:
                    continue

                def discard(
                    reference: weakref.ReferenceType[Any],
                    *,
                    key: int = identity,
                    owner: weakref.ReferenceType[AuditCommandRunner] = self._transport_owner_ref,
                ) -> None:
                    runner = owner()
                    if runner is not None:
                        with runner._transport_stats_lock:
                            if runner._transport_pool_refs.get(key) is reference:
                                runner._transport_pool_refs.pop(key)

                try:
                    self._transport_pool_refs[identity] = weakref.ref(candidate, discard)
                except TypeError:
                    # Third-party opaque objects cannot be tracked without
                    # retaining them. Their counters are explicitly approximate,
                    # rather than growing an unbounded set of recyclable IDs.
                    self._transport_uncertain_pools += 1
            try:
                stats = stats_fn()
                values = {name: int(stats.get(name, 0) or 0) for name in self._transport_stats}
            except Exception:
                # A failed diagnostic must not skip closing its owned sockets.
                with self._transport_stats_lock:
                    self._transport_uncertain_pools += 1
                continue
            with self._transport_stats_lock:
                for name, value in values.items():
                    self._transport_stats[name] += value

    @observe_phase("detect_sync")
    def _run_detect_with_state(
        self,
        host: str,
        port: int,
        target: ScanTargetSpec | None,
        debug_emit: Callable[[str], None] | None,
    ) -> _AuditDetectOutcome:
        base_ctx = self._ctx(
            host,
            port,
            target,
            AuditCredentialRun(source="anonymous"),
            phase="detect",
            run_deep_checks=False,
            debug_emit=debug_emit,
        )
        state_factory = getattr(self.spec, "lifecycle_state_factory", None)
        state = state_factory(base_ctx) if state_factory is not None else None
        self._register_lifecycle_state(state)
        ctx = self._ctx(
            host,
            port,
            target,
            AuditCredentialRun(source="anonymous"),
            phase="detect",
            run_deep_checks=False,
            debug_emit=debug_emit,
            lifecycle_state=state,
        )
        started_at = time.monotonic()
        try:
            record = self._detect(ctx)
            configured_timeout = float(getattr(self.args, "timeout", 3.0))
            if not self._is_detected(record) and configured_timeout < 7.0:
                timeout_text = _record_noise_text(record)
            else:
                timeout_text = ""
            if "timed out" in timeout_text or "connection timeout" in timeout_text:
                # Retry only a timed-out detect, with a fresh transport state.
                # Fast positives and definite negatives retain their original
                # latency; the caller's args and later auth timeout stay intact.
                retry_args = copy.copy(self.args)
                try:
                    retry_args.timeout = 7.0
                except (AttributeError, TypeError):
                    pass  # minimal embedded callers may not have a mutable namespace
                else:
                    self._close_lifecycle_state(state)
                    retry_base_ctx = replace(base_ctx, args=retry_args)
                    state = state_factory(retry_base_ctx) if state_factory is not None else None
                    self._register_lifecycle_state(state)
                    retry_ctx = replace(ctx, args=retry_args, lifecycle_state=state)
                    if debug_emit is not None:
                        debug_emit(f"detect_timeout_retry host={host} port={port} timeout=7.0")
                    record = self._detect(retry_ctx)
            runtime_stage_telemetry = not bool(record.stages)
            if runtime_stage_telemetry:
                result, error = _runtime_phase_outcome("detect", record)
                record, _added = _attach_runtime_phase_trace(
                    record,
                    phase="detect",
                    duration_ms=max(1, int((time.monotonic() - started_at) * 1000)),
                    result=result,
                    error=error,
                    debug_emit=debug_emit,
                )
            return _AuditDetectOutcome(
                record=record,
                lifecycle_state=state,
                runtime_stage_telemetry=runtime_stage_telemetry,
                started_at=started_at,
            )
        except TypeError:
            self._close_lifecycle_state(state)
            raise
        except Exception as exc:  # noqa: BLE001 - per-target detect isolation
            self._close_lifecycle_state(state)

            def _raise(error: Exception = exc) -> AuditRecord:
                raise error

            record = self._safe_record(host, port, _raise)
            record, _added = _attach_runtime_phase_trace(
                record,
                phase="detect",
                duration_ms=max(1, int((time.monotonic() - started_at) * 1000)),
                result="error",
                error=str(exc).strip() or exc.__class__.__name__,
                debug_emit=debug_emit,
            )
            return _AuditDetectOutcome(
                record=record,
                runtime_stage_telemetry=True,
                started_at=started_at,
            )

    @observe_async_phase("detect_async")
    async def _run_async_detect_with_state(
        self,
        host: str,
        port: int,
        target: ScanTargetSpec | None,
        debug_emit: Callable[[str], None] | None,
    ) -> _AuditDetectOutcome | None:
        # Verified native adapters can repeat the same complete detection
        # without occupying an auth/data worker. Keep the existing
        # native + sync + escalated-sync attempt budgets, now all native.
        if self.spec.module not in _NATIVE_TIMEOUT_RECOVERY_MODULES:
            return await self._run_async_detect_attempt(
                host, port, target, debug_emit, self.args, sync_timeout_fallback=True
            )
        configured = float(getattr(self.args, "timeout", 3))
        started = time.monotonic()
        detect_args = self.args
        for attempt, timeout in enumerate((configured, configured, 7.0), start=1):
            if attempt > 1:
                detect_args = copy.copy(self.args)
                try:
                    detect_args.timeout = timeout
                except (AttributeError, TypeError):
                    return None  # Preserve the sync fallback for embedded callers.
                if debug_emit is not None:
                    debug_emit(f"detect_timeout_retry host={host} port={port} attempt={attempt} timeout={timeout}")
            outcome = await self._run_async_detect_attempt(
                host, port, target, debug_emit, detect_args, sync_timeout_fallback=False
            )
            if outcome is None:
                return None  # Unsupported native semantics still use the sync detector.
            noise = _record_noise_text(outcome.record)
            if (
                configured >= 7
                or attempt == 3
                or self._is_detected(outcome.record)
                or ("timed out" not in noise and "connection timeout" not in noise)
            ):
                if attempt > 1 and outcome.runtime_stage_telemetry:
                    duration = max(1, int((time.monotonic() - started) * 1000))
                    record = replace(
                        outcome.record,
                        stages=tuple(
                            replace(trace, attempt=attempt, duration_ms=duration)
                            if trace.stage_name == "detect_protocol"
                            else trace
                            for trace in outcome.record.stages
                        ),
                        extra={
                            **outcome.record.extra,
                            "stage_durations_ms": {
                                **outcome.record.extra.get("stage_durations_ms", {}),
                                "detect_protocol": duration,
                            },
                            "stage_attempts": {
                                **outcome.record.extra.get("stage_attempts", {}),
                                "detect_protocol": attempt,
                            },
                        },
                    )
                    outcome = replace(outcome, record=record)
                return replace(outcome, started_at=started)
            self._close_lifecycle_state(outcome.lifecycle_state)
        raise AssertionError("unreachable detect retry state")

    async def _run_async_detect_attempt(
        self,
        host: str,
        port: int,
        target: ScanTargetSpec | None,
        debug_emit: Callable[[str], None] | None,
        detect_args: Any,
        *,
        sync_timeout_fallback: bool,
    ) -> _AuditDetectOutcome | None:
        import asyncio

        from .clients.async_http_detect import AsyncHttpFallback
        from .clients.http_handoff import RetainedDetectionHttp
        from .clients.tls_cache import shared_client_ssl_context
        from .detection_steps import NATIVE_DETECT_BODY_MAX_BYTES

        base_ctx = self._ctx(
            host,
            port,
            target,
            AuditCredentialRun(source="anonymous"),
            phase="detect",
            run_deep_checks=False,
            debug_emit=debug_emit,
        )
        base_ctx = replace(base_ctx, args=detect_args)
        factory = self.spec.lifecycle_state_factory
        state = factory(base_ctx) if factory is not None else None
        self._register_lifecycle_state(state)
        ctx = replace(base_ctx, lifecycle_state=state)
        http = RetainedDetectionHttp(
            budget=self._http_handoff_budget,
            timeout=float(getattr(detect_args, "timeout", 3)),
            retries=int(getattr(detect_args, "retries", 0)),
            max_bytes=NATIVE_DETECT_BODY_MAX_BYTES,
            ssl_context=shared_client_ssl_context(
                insecure=not bool(getattr(detect_args, "tls_ca", None)),
                ca_file=getattr(detect_args, "tls_ca", None),
                cert_file=getattr(detect_args, "tls_cert", None),
                key_file=getattr(detect_args, "tls_key", None),
            ),
        )
        from .clients.async_resolver import resolver_fallbacks

        resolution_failures: list[str] = []
        resolution_token = resolver_fallbacks.set(resolution_failures)
        started = time.monotonic()
        try:
            assert self.spec.detect_async is not None
            record = await self._detect_async(ctx, http)
            if resolution_failures:
                raise AsyncHttpFallback("driver resolver failure: " + resolution_failures[0])
            # Preserve the existing synchronous timeout escalation policy.
            if (
                sync_timeout_fallback
                and not self._is_detected(record)
                and float(getattr(detect_args, "timeout", 3)) < 7
            ):
                noise = _record_noise_text(record)
                if "timed out" in noise or "connection timeout" in noise:
                    self._close_lifecycle_state(state)
                    return None
            telemetry = not bool(record.stages)
            if telemetry:
                result, error = _runtime_phase_outcome("detect", record)
                record, _ = _attach_runtime_phase_trace(
                    record,
                    phase="detect",
                    duration_ms=max(1, int((time.monotonic() - started) * 1000)),
                    result=result,
                    error=error,
                    debug_emit=debug_emit,
                )
            handoff = getattr(http, "handoff", None)
            if handoff is not None and state is not None and self._is_detected(record):
                handoff()
            return _AuditDetectOutcome(
                record=record, lifecycle_state=state, runtime_stage_telemetry=telemetry, started_at=started
            )
        except AsyncHttpFallback as exc:
            self._close_lifecycle_state(state)
            surface = None
            if self._collect_transport_stats:
                hint = getattr(target, "surface_hint", None)
                surface = (
                    hint
                    if hint in {"backend", "ui"}
                    else ("mixed" if self.spec.module in web_panels.MODULE_PRODUCTS else "backend")
                )
            self._fallback_stats.record(
                self.spec.module,
                str(exc),
                seconds=time.monotonic() - started,
                requests=http.stats().get("requests", 0),
                surface=surface,
            )
            if debug_emit is not None:
                debug_emit(f"async_detect_fallback host={host} port={port} reason={exc}")
            return None
        except (asyncio.CancelledError, TypeError):
            self._close_lifecycle_state(state)
            raise
        except Exception as exc:
            self._close_lifecycle_state(state)

            def failed(error: Exception = exc) -> AuditRecord:
                raise error

            record = self._safe_record(host, port, failed)
            record, _ = _attach_runtime_phase_trace(
                record,
                phase="detect",
                duration_ms=max(1, int((time.monotonic() - started) * 1000)),
                result="error",
                error=str(exc),
                debug_emit=debug_emit,
            )
            return _AuditDetectOutcome(record=record, runtime_stage_telemetry=True, started_at=started)
        finally:
            resolver_fallbacks.reset(resolution_token)
            await http.close()
            if self._collect_transport_stats:
                stats = http.stats()
                with self._transport_stats_lock:
                    for key in self._transport_stats:
                        self._transport_stats[key] += int(stats.get(key, 0))

    def _run_target_pipeline(
        self,
        host: str,
        port: int,
        target: ScanTargetSpec | None,
        credential_runs: tuple[AuditCredentialRun, ...],
        debug_emit: Callable[[str], None] | None,
        *,
        prepared_detect: _AuditDetectOutcome | None = None,
    ) -> _AuditPipelineOutcome:
        return run_paused_sync(
            self._run_target_pipeline_steps(
                host, port, target, credential_runs, debug_emit, prepared_detect=prepared_detect
            )
        )

    def _run_target_pipeline_steps(
        self,
        host: str,
        port: int,
        target: ScanTargetSpec | None,
        credential_runs: tuple[AuditCredentialRun, ...],
        debug_emit: Callable[[str], None] | None,
        *,
        prepared_detect: _AuditDetectOutcome | None = None,
    ) -> Generator[WorkPause, None, _AuditPipelineOutcome]:
        """Run one target's entire lifecycle in a single scheduler worker."""

        discovery_started_at = _TARGET_DISCOVERY_STARTED_AT.get() or time.monotonic()

        phase_emit: Callable[..., None] | None = None

        def _ignore_rce_record(_record: AuditRecord) -> None:
            return None

        emit_rce_record: Callable[[AuditRecord], None] = _ignore_rce_record
        phase_line_counts: Counter[str] = Counter()
        if self.spec.record_skipped_credential_attempts:
            with self._credential_ledger_lock:
                self._credential_phase_counts[_credential_job_key()] = phase_line_counts
                self._active_credential_ledgers[_credential_job_key()] = {
                    "detect": AuditRecord(
                        host=host, port=port, module=self.spec.module, service=self.spec.module, status="unknown"
                    ),
                    # Detection has not proved this product yet. Publishing
                    # candidate identities here invents an auth history if
                    # cancellation interrupts detection.
                    "candidates": (),
                    "attempts": [],
                    "current": None,
                    "debug_count": 0,
                }
        phase_emitted_lines = 0
        live_emit = _TARGET_LIVE_EMIT.get() or getattr(self, "_live_emit", None)
        disk_emit = _TARGET_DISK_EMIT.get()
        if (
            (
                bool(getattr(self.args, "discover", False))
                or bool(getattr(self.args, "enum_cve", False))
                or self.spec.live_phase_output
            )
            and callable(live_emit)
            and (self.spec.render is not None or self.spec.render_module is not None)
        ):
            render_plan = build_render_plan(self.spec.render_module) if self.spec.render_module is not None else None
            debug = bool(getattr(self.args, "debug", False))

            def _emit_phase(
                record: AuditRecord,
                include_cve: bool = False,
                *,
                final: bool = False,
                detect_only: bool = False,
                before_data: bool = False,
                stream_file: str | None = None,
            ) -> None:
                nonlocal phase_emitted_lines
                if self.spec.defer_phase_output_until_final and not (final or detect_only or before_data):
                    return
                phase_record = self._with_cve_enumeration(record) if include_cve else record
                if bool(getattr(self.args, "discover", False)) and self.spec.module in data_discovery.DISCOVERY_MODULES:
                    phase_record = AuditRecord.from_mapping(
                        data_discovery.project_discovery_output(self.args, phase_record.to_dict()),
                        module=self.spec.module,
                        service=phase_record.service or self.spec.module,
                    )
                rendered = self._render_record(phase_record, render_plan, "txt", debug)
                if detect_only:
                    rendered = rendered[:1]
                if final:
                    summaries = [line for line in rendered if _is_discovery_summary_line(line)]
                    if summaries:
                        record.extra["_discovery_summary_lines"] = summaries
                # Locations are emitted by the coordinator with bounded text
                # chunks. Keep completion there too, after the debug footer.
                rendered = [line for line in rendered if not _is_discovery_summary_line(line)]
                elastic_findings = phase_record.extra.get("discover_findings")
                elastic_spooled = isinstance(elastic_findings, SpoolingFindings)
                elastic_findings_iter: SpoolingFindings | tuple[()] = (
                    elastic_findings if isinstance(elastic_findings, SpoolingFindings) else ()
                )
                if (
                    elastic_spooled
                    and not final
                    and any(isinstance(finding.get("value"), DiskBackedText) for finding in elastic_findings_iter)
                ):
                    rendered = [
                        line
                        for line in rendered
                        if "Discover Complete (status:" not in line and "Discover Secrets (status:" not in line
                    ]
                current_counts: Counter[str] = Counter()
                new_lines: list[str] = []
                for line in rendered:
                    key = self.spec.phase_output_key(phase_record, line) if self.spec.phase_output_key else line
                    current_counts[key] += 1
                    if current_counts[key] > phase_line_counts[key]:
                        new_lines.append(line)
                for line, count in current_counts.items():
                    phase_line_counts[line] = max(phase_line_counts[line], count)
                discovery = phase_record.extra.get("content_discovery")
                spooled = isinstance(discovery, Mapping) and isinstance(discovery.get("findings"), SpoolingFindings)
                airflow_discovery = phase_record.extra.get("discover_report")
                airflow_spooled = isinstance(airflow_discovery, Mapping) and isinstance(
                    airflow_discovery.get("findings"), SpoolingFindings
                )
                if spooled and final:
                    summary_index = next(
                        (index for index, line in enumerate(new_lines) if "Discover Secrets (status:" in line),
                        len(new_lines),
                    )
                    if summary_index:
                        live_emit(new_lines[:summary_index])
                    batch: list[str] = []
                    assert isinstance(discovery, Mapping)
                    pending = discovery["findings"]
                    assert isinstance(pending, SpoolingFindings)
                    for finding in pending.iter_unemitted():
                        value = finding.get("value")
                        if isinstance(value, DiskBackedText):
                            if batch:
                                live_emit(batch)
                                phase_emitted_lines += len(batch)
                                batch.clear()
                            if callable(disk_emit):
                                disk_emit(
                                    self.spec.module.upper(),
                                    phase_record.host,
                                    phase_record.port,
                                    finding_type=finding.get("type"),
                                    value=value,
                                    place=finding.get("object_path"),
                                )
                                phase_emitted_lines += 1
                            continue
                        batch.append(
                            format_discovery_finding_line(
                                self.spec.module.upper(),
                                phase_record.host,
                                phase_record.port,
                                severity=finding.get("confidence"),
                                finding_type=finding.get("type"),
                                value=value,
                                place=finding.get("object_path"),
                            )
                        )
                        if len(batch) >= 256:
                            live_emit(batch)
                            phase_emitted_lines += len(batch)
                            batch.clear()
                    if batch:
                        live_emit(batch)
                        phase_emitted_lines += len(batch)
                    if summary_index < len(new_lines):
                        live_emit(new_lines[summary_index:])
                    phase_record.extra["_spooled_findings_phase_emitted"] = True
                    record.extra["_spooled_findings_phase_emitted"] = True
                    phase_emitted_lines += len(new_lines)
                elif airflow_spooled and final:
                    summary_index = next(
                        (index for index, line in enumerate(new_lines) if "Discover Secrets (status:" in line),
                        len(new_lines),
                    )
                    if summary_index:
                        live_emit(new_lines[:summary_index])
                    assert isinstance(airflow_discovery, Mapping)
                    pending = airflow_discovery["findings"]
                    assert isinstance(pending, SpoolingFindings)
                    for finding in pending.iter_unemitted():
                        value = finding.get("value")
                        place = finding.get("place") or finding.get("object_path")
                        if isinstance(value, DiskBackedText):
                            if callable(disk_emit):
                                disk_emit(
                                    "AIRFLOW",
                                    phase_record.host,
                                    phase_record.port,
                                    finding_type=finding.get("type"),
                                    value=value,
                                    place=place,
                                )
                                phase_emitted_lines += 1
                        else:
                            live_emit(
                                [
                                    format_discovery_finding_line(
                                        "AIRFLOW",
                                        phase_record.host,
                                        phase_record.port,
                                        severity=finding.get("confidence"),
                                        finding_type=finding.get("type"),
                                        value=value,
                                        place=place,
                                    )
                                ]
                            )
                            phase_emitted_lines += 1
                    if summary_index < len(new_lines):
                        live_emit(new_lines[summary_index:])
                    phase_record.extra["_airflow_spooled_phase_emitted"] = True
                    record.extra["_airflow_spooled_phase_emitted"] = True
                    phase_emitted_lines += len(new_lines)
                elif elastic_spooled and final:
                    summary_index = next(
                        (
                            index
                            for index, line in enumerate(new_lines)
                            if "Discover Complete (status:" in line or "Discover Secrets (status:" in line
                        ),
                        len(new_lines),
                    )
                    if summary_index:
                        live_emit(new_lines[:summary_index])
                    if not phase_record.extra.get("_elastic_disk_live_emitted") and callable(disk_emit):
                        for finding in elastic_findings_iter:
                            value = finding.get("value")
                            if not isinstance(value, DiskBackedText):
                                continue
                            locations = finding.get("locations")
                            first = locations[0] if isinstance(locations, list) and locations else None
                            parts = []
                            if isinstance(first, Mapping):
                                for key in ("source_kind", "object", "index", "id", "path"):
                                    item = first.get(key)
                                    if item is not None and str(item).strip():
                                        parts.append(f"{key}:{item}")
                            disk_emit(
                                "ELASTIC",
                                phase_record.host,
                                phase_record.port,
                                finding_type=finding.get("secret_type"),
                                value=value,
                                place="/".join(parts) or "unknown",
                            )
                            phase_emitted_lines += 1
                    if summary_index < len(new_lines):
                        live_emit(new_lines[summary_index:])
                    phase_record.extra["_elastic_disk_phase_emitted"] = True
                    record.extra["_elastic_disk_phase_emitted"] = True
                    phase_emitted_lines += len(new_lines)
                elif new_lines:
                    live_emit(new_lines)
                    phase_emitted_lines += len(new_lines)
                if stream_file is not None:
                    stream_emit = _TARGET_STREAM_EMIT.get()
                    if stream_emit is not None:
                        phase_emitted_lines += stream_emit(stream_file)

            if self.spec.record_skipped_credential_attempts:

                def _emit_locked_phase(*args: Any, **kwargs: Any) -> None:
                    with self._credential_ledger_lock:
                        if not self._audit_cancelled.is_set():
                            token = _CREDENTIAL_PHASE_EMIT_ACTIVE.set(True)
                            try:
                                _emit_phase(*args, **kwargs)
                            finally:
                                _CREDENTIAL_PHASE_EMIT_ACTIVE.reset(token)

                phase_emit = _emit_locked_phase
            else:
                phase_emit = _emit_phase

            raw_phase_emit = phase_emit
            rce_output_ready = self.spec.rce_probe is None
            if callable(raw_phase_emit) and self.spec.rce_probe is not None:

                def _deferred_rce_phase(record: AuditRecord, *args: Any, **kwargs: Any) -> None:
                    if rce_output_ready:
                        raw_phase_emit(record, *args, **kwargs)

                phase_emit = _deferred_rce_phase

                def emit_rce_record(record: AuditRecord) -> None:
                    nonlocal rce_output_ready
                    rce_output_ready = True
                    raw_phase_emit(record, False)
            else:
                emit_rce_record = _ignore_rce_record

        with measure_sync_detect():
            detect_outcome = (
                prepared_detect
                if prepared_detect is not None
                else self._run_detect_with_state(host, port, target, debug_emit)
            )
        detect_record = detect_outcome.record
        detected = self._is_detected(detect_record)
        if self.spec.record_skipped_credential_attempts:
            with self._credential_ledger_lock:
                ledger = self._active_credential_ledgers.get(_credential_job_key())
                if ledger is not None:
                    # Preserve proof even if cancellation happens before the
                    # deep lifecycle installs its auth ledger.
                    ledger["detect"] = detect_record
                    if detected:
                        ledger["candidates"] = merge_audit_credential_runs(credential_runs)
        if detected and self.spec.logical_target_key is not None:
            logical_key = self.spec.logical_target_key(detect_record)
            if logical_key is not None:
                with self._credential_ledger_lock:
                    duplicate = logical_key in self._claimed_logical_targets
                    self._claimed_logical_targets.add(logical_key)
                    if duplicate and self.spec.record_skipped_credential_attempts:
                        worker_id = _credential_job_key()
                        self._active_credential_ledgers.pop(worker_id, None)
                        self._credential_phase_counts.pop(worker_id, None)
                if duplicate:
                    self._close_lifecycle_state(detect_outcome.lifecycle_state)
                    return _AuditPipelineOutcome(detect_record, False, False, False, duplicate_target=True)
        deep_candidate = detected and self._deep_gate(detect_record)[0]
        has_credential_candidate = any(
            any(value is not None for value in (credential.username, credential.password, credential.token))
            for credential in credential_runs
        )
        defer_detect_output = bool(
            self.spec.rce_probe is not None or (self.spec.defer_detect_output_until_auth and has_credential_candidate)
        )
        if detected and phase_emit is not None and not defer_detect_output:
            phase_emit(detect_record, False)
        if debug_emit is not None:
            debug_emit(
                format_pass_marker(
                    1,
                    "detect",
                    "target_complete",
                    host=host,
                    port=int(port),
                    detected=int(detected),
                    deep_candidate=int(deep_candidate),
                    mode="pipeline",
                )
            )
        if not detected:
            self._close_lifecycle_state(detect_outcome.lifecycle_state)
            if debug_emit is not None:
                debug_emit(format_stage2_gate(host, int(port), "skip", self._not_detected_reason(detect_record)))
            return _AuditPipelineOutcome(
                record=detect_record,
                detected=False,
                deep_candidate=False,
                deep_processed=False,
            )

        if debug_emit is not None:
            debug_emit(
                format_pass_marker(
                    2,
                    "deep",
                    "target_start",
                    host=host,
                    port=int(port),
                    mode="pipeline",
                )
            )
        final_record = yield from self._run_deep_and_close_state_steps(
            host,
            port,
            target,
            detect_outcome,
            credential_runs,
            debug_emit,
            phase_emit,
            emit_rce_record if self.spec.rce_probe is not None else None,
        )
        if self.spec.rce_probe is not None and "rce" not in final_record.extra:
            final_record = replace(
                final_record, extra={**final_record.extra, "rce": None, "rce_probe_performed": False}
            )
            emit_rce_record(final_record)
        if bool(getattr(self.args, "discover", False)) and self.spec.module in data_discovery.DISCOVERY_MODULES:
            payload = final_record.to_dict()
            if not isinstance(payload.get("content_discovery"), dict):
                payload["content_discovery"] = data_discovery.inspect_record(
                    self.spec.module,
                    payload,
                    max_bytes=int(getattr(self.args, "discover_max_bytes", None) or UNLIMITED_DISCOVER_BYTES),
                    max_seconds=float(getattr(self.args, "discover_time", None) or DEFAULT_DISCOVER_TIME),
                    started_at=discovery_started_at,
                )
            payload = data_discovery.project_discovery_output(self.args, payload)
            final_record = AuditRecord.from_mapping(
                payload, module=self.spec.module, service=final_record.service or self.spec.module
            )
        if phase_emit is not None:
            phase_emit(final_record, True, final=True)
            payload = final_record.to_dict()
            payload["_self_emitted"] = True
            payload["_self_emitted_lines"] = phase_emitted_lines
            payload["_cve_self_emitted"] = bool(getattr(self.args, "enum_cve", False))
            final_record = AuditRecord.from_mapping(
                payload,
                module=self.spec.module,
                service=final_record.service or self.spec.module,
            )
        deep_processed = self._deep_gate(final_record)[0]
        if debug_emit is not None:
            debug_emit(
                format_pass_marker(
                    2,
                    "deep",
                    "target_complete",
                    host=host,
                    port=int(port),
                    processed=int(deep_processed),
                    mode="pipeline",
                )
            )
        additional_records: tuple[AuditRecord, ...] = ()
        other_target = self._additional_surface_target(detect_record, target, port)
        if other_target is not None and not (prepared_detect and prepared_detect.additional_surface_scheduled):
            other = yield from self._run_target_pipeline_steps(
                host,
                port,
                other_target,
                credential_runs,
                debug_emit,
            )
            if other.detected:
                additional_records = (other.record,)
        return _AuditPipelineOutcome(
            record=final_record,
            detected=True,
            deep_candidate=deep_candidate,
            deep_processed=deep_processed,
            additional_records=additional_records,
        )

    def _additional_surface_target(
        self, record: AuditRecord, target: ScanTargetSpec | None, port: int
    ) -> ScanTargetSpec | None:
        if (
            self.spec.module not in web_panels.MODULE_PRODUCTS
            or self.spec.module == "portainer"
            or target is None
            or target.surface_hint is not None
            or (target.scheme not in {"http", "https"} and target.explicit_port is None)
        ):
            return None
        surface = "backend" if record.extra.get("surface") == "ui" else "ui"
        # A backend result on a UI-first endpoint already includes a failed
        # panel probe. Keep that proof instead of probing the same UI again.
        if surface == "ui" and (
            target.scheme in {"http", "https"} or int(port) in web_panels.UI_PORTS[self.spec.module]
        ):
            return None
        return replace(target, surface_hint=surface)

    def _run_deep_and_close_state(
        self,
        host: str,
        port: int,
        target: ScanTargetSpec | None,
        detect_outcome: _AuditDetectOutcome,
        credential_runs: tuple[AuditCredentialRun, ...],
        debug_emit: Callable[[str], None] | None,
        phase_emit: Callable[..., None] | None = None,
        emit_rce_record: Callable[[AuditRecord], None] | None = None,
    ) -> AuditRecord:
        return run_paused_sync(
            self._run_deep_and_close_state_steps(
                host, port, target, detect_outcome, credential_runs, debug_emit, phase_emit, emit_rce_record
            )
        )

    def _run_deep_and_close_state_steps(
        self,
        host: str,
        port: int,
        target: ScanTargetSpec | None,
        detect_outcome: _AuditDetectOutcome,
        credential_runs: tuple[AuditCredentialRun, ...],
        debug_emit: Callable[[str], None] | None,
        phase_emit: Callable[..., None] | None = None,
        emit_rce_record: Callable[[AuditRecord], None] | None = None,
    ) -> Generator[WorkPause, None, AuditRecord]:
        try:
            try:
                return (
                    yield from self._run_deep_lifecycle_steps(
                        host,
                        port,
                        target,
                        detect_outcome.record,
                        credential_runs,
                        debug_emit,
                        lifecycle_state=detect_outcome.lifecycle_state,
                        runtime_stage_telemetry=detect_outcome.runtime_stage_telemetry,
                        phase_emit=phase_emit,
                        emit_rce_record=emit_rce_record,
                    )
                )
            except Exception as exc:

                def fail(error: Exception = exc) -> AuditRecord:
                    raise error

                return self._safe_record(host, port, fail, prior_record=detect_outcome.record)
        finally:
            self._close_lifecycle_state(detect_outcome.lifecycle_state)

    def _run_detect(
        self,
        host: str,
        port: int,
        target: ScanTargetSpec | None,
        debug_emit: Callable[[str], None] | None,
    ) -> AuditRecord:
        ctx = self._ctx(
            host,
            port,
            target,
            AuditCredentialRun(source="anonymous"),
            phase="detect",
            run_deep_checks=False,
            debug_emit=debug_emit,
        )
        return self._detect(ctx)

    def _runtime_phase_failure(
        self,
        *,
        host: str,
        port: int,
        prior: AuditRecord,
        detect_record: AuditRecord,
        phase: AuditPhase,
        started_at: float,
        exc: Exception,
        debug_emit: Callable[[str], None] | None,
    ) -> AuditRecord:
        def _raise(error: Exception = exc) -> AuditRecord:
            raise error

        failed = self._safe_record(host, port, _raise, prior_record=prior)
        if self._is_detected(detect_record):
            failed_payload = failed.to_dict()
            failed_payload["detected_status"] = str(detect_record.status)
            failed_payload["detection_preserved"] = True
            failed = AuditRecord.from_mapping(
                failed_payload,
                module=self.spec.module,
                service=detect_record.service or self.spec.module,
            )
        failed, _added = _attach_runtime_phase_trace(
            failed,
            prior=prior,
            phase=phase,
            duration_ms=max(1, int((time.monotonic() - started_at) * 1000)),
            result="error",
            error=str(exc).strip() or exc.__class__.__name__,
            debug_emit=debug_emit,
        )
        return failed

    @staticmethod
    def _runtime_skip_phases(
        record: AuditRecord,
        phases: Iterable[AuditPhase],
        *,
        reason: str,
        debug_emit: Callable[[str], None] | None,
    ) -> AuditRecord:
        current = record
        for phase in phases:
            current, _added = _attach_runtime_phase_trace(
                current,
                prior=current,
                phase=phase,
                duration_ms=0,
                result="skip",
                error=reason,
                debug_emit=debug_emit,
            )
        return current

    def _run_deep_lifecycle(
        self,
        host: str,
        port: int,
        target: ScanTargetSpec | None,
        detect_record: AuditRecord,
        credential_runs: tuple[AuditCredentialRun, ...],
        debug_emit: Callable[[str], None] | None,
        lifecycle_state: Any = None,
        runtime_stage_telemetry: bool = False,
        phase_emit: Callable[..., None] | None = None,
        emit_rce_record: Callable[[AuditRecord], None] | None = None,
    ) -> AuditRecord:
        return run_paused_sync(
            self._run_deep_lifecycle_steps(
                host,
                port,
                target,
                detect_record,
                credential_runs,
                debug_emit,
                lifecycle_state,
                runtime_stage_telemetry,
                phase_emit,
                emit_rce_record,
            )
        )

    def _run_deep_lifecycle_steps(
        self,
        host: str,
        port: int,
        target: ScanTargetSpec | None,
        detect_record: AuditRecord,
        credential_runs: tuple[AuditCredentialRun, ...],
        debug_emit: Callable[[str], None] | None,
        lifecycle_state: Any = None,
        runtime_stage_telemetry: bool = False,
        phase_emit: Callable[..., None] | None = None,
        emit_rce_record: Callable[[AuditRecord], None] | None = None,
    ) -> Generator[WorkPause, None, AuditRecord]:
        if self._host_stage_is_monolithic:
            return self._run_monolithic_deep_lifecycle(
                host,
                port,
                target,
                detect_record,
                credential_runs,
                debug_emit,
                lifecycle_state,
                phase_emit,
            )

        auth_records: list[tuple[AuditCredentialRun, AuditRecord]] = []
        candidates = credential_runs or (AuditCredentialRun(source="anonymous"),)
        if self.spec.record_skipped_credential_attempts:
            candidates = merge_audit_credential_runs(candidates)
        if bool(getattr(self.args, "defcreds", False)) and detect_record.extra.get("surface") == "ui":
            extra_defaults = (
                AuditCredentialRun(username=user, password=password, source="default")
                for user, password in web_panels.default_pairs(str(detect_record.extra.get("ui_product") or ""))
            )
            candidates = merge_audit_credential_runs(candidates, tuple(extra_defaults))
        retain_all_attempts = (
            self.spec.record_all_credential_attempts
            or self.spec.continue_after_credential_success
            or self.spec.record_skipped_credential_attempts
        )
        stop_reason: str | None = None
        if self.spec.record_skipped_credential_attempts:
            with self._credential_ledger_lock:
                self._active_credential_ledgers[_credential_job_key()] = {
                    "detect": detect_record,
                    "candidates": candidates,
                    "attempts": auth_records,
                    "current": None,
                    "debug_count": 0,
                }
        verifier_unavailable = bool(
            (self.spec.skip_credentials_without_verifier or detect_record.extra.get("surface") == "ui")
            and detect_record.extra.get("credential_verification_status") == "unavailable"
        )
        if self._should_keep_anonymous_detect_record(detect_record) or verifier_unavailable:
            selected_credential = AuditCredentialRun(source="anonymous")
            selected_record = detect_record
            if runtime_stage_telemetry:
                selected_record, _added = _attach_runtime_phase_trace(
                    selected_record,
                    prior=detect_record,
                    phase="auth",
                    duration_ms=0,
                    result="ok",
                    debug_emit=debug_emit,
                )
            gate_reason = "credential verification unavailable" if verifier_unavailable else "status=open_no_auth"
            stop_reason = gate_reason
        else:
            for credential in candidates:
                ctx = self._ctx(
                    host,
                    port,
                    target,
                    credential,
                    phase="auth",
                    run_deep_checks=False,
                    debug_emit=debug_emit,
                    credential_runs=(credential,),
                    lifecycle_state=lifecycle_state,
                )
                if self.spec.record_skipped_credential_attempts:
                    with self._credential_ledger_lock:
                        if callable(ctx.cancelled) and ctx.cancelled():
                            stop_reason = "cancelled"
                            break
                        ledger = self._active_credential_ledgers.get(_credential_job_key())
                        if ledger is not None:
                            ledger["current"] = credential
                auth_started_at = time.monotonic()
                try:
                    admission = (
                        self.spec.auth_wait(ctx, detect_record) if self.spec.auth_wait is not None else nullcontext(())
                    )
                    with admission as pauses:
                        yield from pauses
                        auth_record = self._auth(ctx, detect_record)
                except TypeError:
                    raise
                except Exception as exc:  # noqa: BLE001 - isolate a single target/identity
                    auth_record = self._runtime_phase_failure(
                        host=host,
                        port=port,
                        prior=detect_record,
                        detect_record=detect_record,
                        phase="auth",
                        started_at=auth_started_at,
                        exc=exc,
                        debug_emit=debug_emit,
                    )
                    if runtime_stage_telemetry:
                        auth_record = self._runtime_skip_phases(
                            auth_record,
                            ("capabilities", "data"),
                            reason="deep checks disabled",
                            debug_emit=debug_emit,
                        )
                    auth_record = self._record_credential_attempt(credential, auth_record, auth_records, debug_emit)
                    if phase_emit is not None:
                        phase_emit(auth_record, False)
                    if bool(getattr(self.args, "defcreds", False)) and _credential_attempt_rate_limited(auth_record):
                        stop_reason = str(auth_record.extra.get("credential_stop_reason") or "rate_limited")
                        break
                    if self.spec.continue_after_credential_error:
                        continue
                    failed_record = self._preserve_detected_deep_failure(detect_record, auth_record)
                    if retain_all_attempts:
                        return self._with_attempted_credentials(failed_record, auth_records, force=True)
                    return failed_record
                if runtime_stage_telemetry:
                    result, error = _runtime_phase_outcome("auth", auth_record, detect_record)
                    auth_record, _added = _attach_runtime_phase_trace(
                        auth_record,
                        prior=detect_record,
                        phase="auth",
                        duration_ms=max(1, int((time.monotonic() - auth_started_at) * 1000)),
                        result=result,
                        error=error,
                        debug_emit=debug_emit,
                    )
                auth_record = self._record_credential_attempt(credential, auth_record, auth_records, debug_emit)
                if phase_emit is not None:
                    phase_emit(auth_record, False)
                if bool(getattr(self.args, "defcreds", False)) and _credential_attempt_rate_limited(auth_record):
                    stop_reason = str(auth_record.extra.get("credential_stop_reason") or "rate_limited")
                    break
                if (
                    self._credential_gate(credential, auth_record)[0]
                    and not self.spec.continue_after_credential_success
                ):
                    break
            selected_credential, selected_record, gate_reason = self._select_deep_record(detect_record, auth_records)
        skipped_credentials = sum(
            candidate.username is not None or candidate.password is not None or candidate.token is not None
            for candidate in candidates[len(auth_records) :]
        )
        if skipped_credentials:
            import dataclasses as _dc

            selected_record = _dc.replace(
                selected_record,
                extra={**selected_record.extra, "credential_attempts_skipped": skipped_credentials},
            )
        if self.spec.record_skipped_credential_attempts:
            with self._credential_ledger_lock:
                completed = len(auth_records)
                auth_records.extend(
                    self._skipped_credential_records(
                        detect_record, candidates[completed:], stop_reason or "credential sweep stopped"
                    )
                )
                if stop_reason:
                    selected_record = replace(
                        selected_record, extra={**selected_record.extra, "credential_stop_reason": stop_reason}
                    )
                ledger = self._active_credential_ledgers.get(_credential_job_key())
                if ledger is not None and debug_emit is not None:
                    history = self._with_attempted_credentials(selected_record, auth_records, force=True)
                    self._debug_credential_ledger(history, debug_emit, start=ledger["debug_count"])
                    ledger["debug_count"] = len(history.extra.get("attempted_credentials") or [])
        credentials_verified = self._credential_gate(selected_credential, selected_record)[0]
        selected_record = self._mark_cve_credentials_verified(
            selected_record,
            selected_credential,
            accepted=credentials_verified,
        )
        if retain_all_attempts:
            selected_record = self._with_attempted_credentials(selected_record, auth_records, force=True)
        if self.spec.rce_probe is not None:
            probe_ctx = self._ctx(
                host,
                port,
                target,
                selected_credential,
                phase="capabilities",
                run_deep_checks=True,
                debug_emit=debug_emit,
                credential_runs=(selected_credential,),
                lifecycle_state=lifecycle_state,
            )
            try:
                if self._runtime_stats is None:
                    selected_record = self.spec.rce_probe(probe_ctx, selected_record)
                else:
                    with self._runtime_stats.measure("rce_probe"):
                        selected_record = self.spec.rce_probe(probe_ctx, selected_record)
            except Exception as exc:  # noqa: BLE001 - keep a failed proof inconclusive
                selected_record = replace(
                    selected_record, extra={**selected_record.extra, "rce": None, "rce_probe_error": str(exc)}
                )
            if emit_rce_record is not None:
                emit_rce_record(selected_record)
        if self.spec.record_skipped_credential_attempts and stop_reason in {
            "cancelled",
            "rate_limited",
            "account_locked",
            "locked_out",
        }:
            if phase_emit is not None:
                phase_emit(selected_record, False)
            return selected_record
        gate = self._deep_gate(selected_record)
        if not gate[0]:
            # No credential gated (all attempts failed). Record every attempted credential
            # so renderers can surface all of them instead of only the last-tried one.
            # Generic + harmless: modules whose renderers ignore this key are unaffected.
            if not retain_all_attempts:
                selected_record = self._with_attempted_credentials(selected_record, auth_records, force=False)
            if debug_emit is not None:
                debug_emit(format_stage2_gate(host, int(port), "skip", gate[1] or gate_reason))
            if runtime_stage_telemetry:
                selected_record = self._runtime_skip_phases(
                    selected_record,
                    ("capabilities", "data"),
                    reason="deep checks disabled",
                    debug_emit=debug_emit,
                )
            if phase_emit is not None:
                phase_emit(selected_record, True)
            return self._preserve_detected_deep_failure(detect_record, selected_record)
        if debug_emit is not None:
            debug_emit(format_stage2_gate(host, int(port), "run", gate[1] or gate_reason))

        capabilities_ctx = self._ctx(
            host,
            port,
            target,
            selected_credential,
            phase="capabilities",
            run_deep_checks=True,
            debug_emit=debug_emit,
            credential_runs=(selected_credential,),
            lifecycle_state=lifecycle_state,
        )
        capabilities_started_at = time.monotonic()
        try:
            record = self._capabilities(capabilities_ctx, selected_record)
        except TypeError:
            raise
        except Exception as exc:  # noqa: BLE001 - isolate a single target
            record = self._runtime_phase_failure(
                host=host,
                port=port,
                prior=selected_record,
                detect_record=detect_record,
                phase="capabilities",
                started_at=capabilities_started_at,
                exc=exc,
                debug_emit=debug_emit,
            )
            if runtime_stage_telemetry:
                record = self._runtime_skip_phases(
                    record,
                    ("data",),
                    reason="deep checks disabled",
                    debug_emit=debug_emit,
                )
            failed_record = self._preserve_detected_deep_failure(detect_record, record)
            if retain_all_attempts:
                return self._with_attempted_credentials(failed_record, auth_records, force=True)
            return failed_record
        if runtime_stage_telemetry:
            result, error = _runtime_phase_outcome("capabilities", record, selected_record)
            record, _added = _attach_runtime_phase_trace(
                record,
                prior=selected_record,
                phase="capabilities",
                duration_ms=max(1, int((time.monotonic() - capabilities_started_at) * 1000)),
                result=result,
                error=error,
                debug_emit=debug_emit,
            )
        record = self._mark_cve_credentials_verified(
            record,
            selected_credential,
            accepted=credentials_verified,
        )
        if phase_emit is not None:
            if self.spec.emit_capabilities_before_data:
                phase_emit(record, False, before_data=True)
                phase_emit(record, True, before_data=True)
            else:
                if self.spec.defer_phase_output_until_final:
                    phase_emit(record, False, detect_only=True)
                phase_emit(record, False)
                phase_emit(record, True)
        data_ctx = self._ctx(
            host,
            port,
            target,
            selected_credential,
            phase="data",
            run_deep_checks=True,
            debug_emit=debug_emit,
            credential_runs=(selected_credential,),
            lifecycle_state=lifecycle_state,
        )
        if phase_emit is not None and callable(data_ctx.live_emit):
            ready_phase_emit = phase_emit

            def emit_ready_inventory(payload: dict[str, Any]) -> None:
                stream_path = payload.get("_stream_lines_file")
                if stream_path and _TARGET_STREAM_EMIT.get() is None:
                    return
                stream_path = payload.pop("_stream_lines_file", None)
                try:
                    ready = AuditRecord.from_mapping(payload, module=self.spec.module, service=record.service)
                    ready_phase_emit(ready, True, before_data=True, stream_file=stream_path)
                finally:
                    if stream_path:
                        try:
                            os.remove(stream_path)
                        except OSError:
                            pass

            data_ctx = replace(data_ctx, emit_ready_inventory=emit_ready_inventory)
        data_started_at = time.monotonic()
        prior_data_record = record
        try:
            record = self._data(data_ctx, prior_data_record)
        except TypeError:
            raise
        except Exception as exc:  # noqa: BLE001 - isolate a single target
            record = self._runtime_phase_failure(
                host=host,
                port=port,
                prior=prior_data_record,
                detect_record=detect_record,
                phase="data",
                started_at=data_started_at,
                exc=exc,
                debug_emit=debug_emit,
            )
            failed_record = self._preserve_detected_deep_failure(detect_record, record)
            if retain_all_attempts:
                return self._with_attempted_credentials(failed_record, auth_records, force=True)
            return failed_record
        if runtime_stage_telemetry:
            result, error = _runtime_phase_outcome("data", record, prior_data_record)
            record, _added = _attach_runtime_phase_trace(
                record,
                prior=prior_data_record,
                phase="data",
                duration_ms=max(1, int((time.monotonic() - data_started_at) * 1000)),
                result=result,
                error=error,
                debug_emit=debug_emit,
            )
        final_record = self._preserve_detected_deep_failure(detect_record, record)
        final_record = self._mark_cve_credentials_verified(
            final_record,
            selected_credential,
            accepted=credentials_verified,
        )
        if retain_all_attempts:
            return self._with_attempted_credentials(final_record, auth_records, force=True)
        return final_record

    def _run_monolithic_deep_lifecycle(
        self,
        host: str,
        port: int,
        target: ScanTargetSpec | None,
        detect_record: AuditRecord,
        credential_runs: tuple[AuditCredentialRun, ...],
        debug_emit: Callable[[str], None] | None,
        lifecycle_state: Any,
        phase_emit: Callable[..., None] | None = None,
    ) -> AuditRecord:
        """Run each monolithic credential attempt once with actions enabled.

        The old generic lifecycle called the same host_stage for auth with
        ``run_deep_checks=False`` and then called it again for data with
        ``run_deep_checks=True``. The selected credential therefore repeated
        its connection, authentication and baseline queries. A monolithic stage
        already owns auth+actions, so its deep result is final.
        """

        candidates = credential_runs or (AuditCredentialRun(source="anonymous"),)
        if self.spec.module == "docker" and detect_record.extra.get("surface") != "ui":
            # Docker Engine has no username/password verifier. Portainer is a
            # separate product and receives these candidates only when proven.
            candidates = (AuditCredentialRun(source="anonymous"),)
        if bool(getattr(self.args, "defcreds", False)) and detect_record.extra.get("surface") == "ui":
            extra_defaults = (
                AuditCredentialRun(username=user, password=password, source="default")
                for user, password in web_panels.default_pairs(str(detect_record.extra.get("ui_product") or ""))
            )
            candidates = merge_audit_credential_runs(candidates, tuple(extra_defaults))
        if (
            detect_record.extra.get("surface") == "ui"
            and detect_record.extra.get("credential_verification_status") == "unavailable"
        ):
            candidates = (AuditCredentialRun(source="anonymous"),)
        has_application_credentials = any(
            candidate.username is not None or candidate.password is not None or candidate.token is not None
            for candidate in candidates
        )
        if (
            not has_application_credentials
            and not bool(getattr(self.args, "defcreds", False))
            and not self._deep_gate(detect_record)[0]
        ):
            gate = self._deep_gate(detect_record)
            if debug_emit is not None:
                debug_emit(format_stage2_gate(host, int(port), "skip", gate[1]))
            return detect_record
        if self._host_stage_accepts_credential_batch:
            selected = candidates[0] if candidates else AuditCredentialRun(source="anonymous")
            ctx = self._ctx(
                host,
                port,
                target,
                selected,
                phase="data",
                run_deep_checks=True,
                debug_emit=debug_emit,
                credential_runs=tuple(candidates),
                lifecycle_state=lifecycle_state,
            )
            record = self._host_stage(ctx, run_deep_checks=True)
            gate = self._deep_gate(record)
            record = self._mark_cve_credentials_verified(
                record,
                selected,
                accepted=self._credential_gate(selected, record)[0],
            )
            if phase_emit is not None:
                phase_emit(record, False)
            if debug_emit is not None:
                debug_emit(
                    format_stage2_gate(
                        host,
                        int(port),
                        "run" if gate[0] else "skip",
                        gate[1],
                    )
                )
            return self._preserve_detected_deep_failure(detect_record, record)

        attempts: list[tuple[AuditCredentialRun, AuditRecord]] = []
        retain_all_attempts = self.spec.record_all_credential_attempts or self.spec.continue_after_credential_success
        for credential in candidates:
            ctx = self._ctx(
                host,
                port,
                target,
                credential,
                phase="data",
                run_deep_checks=True,
                debug_emit=debug_emit,
                credential_runs=(credential,),
                lifecycle_state=lifecycle_state,
            )
            attempt_started_at = time.monotonic()
            try:
                record = self._host_stage(ctx, run_deep_checks=True)
            except TypeError:
                raise
            except Exception as exc:  # noqa: BLE001 - isolate one credential candidate
                if not self.spec.continue_after_credential_error:
                    raise
                record = self._runtime_phase_failure(
                    host=host,
                    port=port,
                    prior=detect_record,
                    detect_record=detect_record,
                    phase="data",
                    started_at=attempt_started_at,
                    exc=exc,
                    debug_emit=debug_emit,
                )
            attempts.append((credential, record))
            gate = self._credential_gate(credential, record)
            record = self._mark_cve_credentials_verified(record, credential, accepted=gate[0])
            attempts[-1] = (credential, record)
            if phase_emit is not None:
                phase_emit(record, False)
            if bool(getattr(self.args, "defcreds", False)) and _credential_attempt_rate_limited(record):
                break
            # A monolithic adapter has already completed anonymous data
            # actions despite the rejected pair; repeating the same public
            # actions for every candidate adds no evidence.
            if str(record.status or "") == "invalid_credentials_anonymous" and self._deep_gate(record)[0]:
                break
            if gate[0]:
                if debug_emit is not None:
                    debug_emit(format_stage2_gate(host, int(port), "run", gate[1]))
                if self.spec.continue_after_credential_success:
                    continue
                if retain_all_attempts:
                    return self._with_attempted_credentials(record, attempts, force=True)
                return record

        if not attempts:
            return detect_record
        selected_credential, selected_record, _reason = self._select_deep_record(detect_record, attempts)
        selected_record = self._mark_cve_credentials_verified(
            selected_record,
            selected_credential,
            accepted=self._credential_gate(selected_credential, selected_record)[0],
        )
        if (
            selected_credential.username is None
            and selected_credential.password is None
            and selected_credential.token is None
            and selected_record is detect_record
        ):
            anonymous_ctx = self._ctx(
                host,
                port,
                target,
                selected_credential,
                phase="data",
                run_deep_checks=True,
                debug_emit=debug_emit,
                credential_runs=(selected_credential,),
                lifecycle_state=lifecycle_state,
            )
            selected_record = self._host_stage(anonymous_ctx, run_deep_checks=True)
        selected_record = self._with_attempted_credentials(
            selected_record,
            attempts,
            force=retain_all_attempts,
        )
        if debug_emit is not None:
            gate = self._deep_gate(selected_record)
            debug_emit(format_stage2_gate(host, int(port), "run" if gate[0] else "skip", gate[1]))
        return self._preserve_detected_deep_failure(detect_record, selected_record)

    def _preserve_detected_deep_failure(
        self,
        detect_record: AuditRecord,
        deep_record: AuditRecord,
    ) -> AuditRecord:
        if self._is_detected(deep_record) or not self._is_detected(detect_record):
            return deep_record
        payload = deep_record.to_dict()
        message = str(payload.get("error") or payload.get("deep_error") or deep_record.status)
        payload.update(
            {
                "module": self.spec.module,
                "service": detect_record.service or self.spec.module,
                f"is_{self.spec.module}": True,
                "detected_status": str(detect_record.status),
                "detection_preserved": True,
                "deep_error": message,
            }
        )
        return AuditRecord.from_mapping(
            payload,
            module=self.spec.module,
            service=detect_record.service or self.spec.module,
        )

    def _should_keep_anonymous_detect_record(self, detect_record: AuditRecord) -> bool:
        """When detect confirmed anonymous access + defcreds is on, skip the
        credential loop.

        E3 fix (narrow): the original kafka-only guard is preserved as the
        default. Modules that opt in via the `keep_anonymous_open_no_auth`
        attribute on their ModuleAuditSpec ALSO short-circuit — this lets
        redis/docker/grpc/elastic/clickhouse register the same fast-path
        gradually without changing the credential loop for every module in
        one sweep (which broke proxmox's URL-scheme test that relied on the
        current 2-call behavior when creds were not provided).
        """
        if not bool(getattr(self.args, "defcreds", False)):
            return False
        if self.spec.continue_after_credential_success:
            return False
        if str(detect_record.status or "") != "open_no_auth":
            return False
        if self.spec.module == "kafka":
            return True
        return bool(getattr(self.spec, "keep_anonymous_open_no_auth", False))

    def _safe_record(
        self,
        host: str,
        port: int,
        task: Callable[[], AuditRecord],
        *,
        prior_record: AuditRecord | None = None,
    ) -> AuditRecord:
        """Run a per-host task, converting an operational exception into a fail record.

        Without this, a single host raising (e.g. a driver bug or a malformed
        response) would propagate out of `scheduler.iter_completed`, abort the
        whole batch, and crash the command (`run_*_stage` only catches `OSError`).
        Isolating it keeps the scan going; the bad host surfaces as `status=fail`.

        `TypeError` is deliberately re-raised: the runner's typed-hook/spec contract
        checks raise `TypeError`, and those are configuration/dev errors that affect
        every host identically — they should fail loud, not produce N fail records.
        """

        try:
            return task()
        except TypeError:
            raise
        except Exception as exc:  # noqa: BLE001 - deliberate per-host isolation boundary
            message = str(exc).strip() or exc.__class__.__name__
            if prior_record is not None and self._is_detected(prior_record):
                payload = prior_record.to_dict()
                payload.update(
                    {
                        "host": str(host),
                        "port": int(port),
                        "module": self.spec.module,
                        "service": prior_record.service or self.spec.module,
                        "status": "fail",
                        "error": message,
                        "deep_error": message,
                        "detected_status": str(prior_record.status),
                        "detection_preserved": True,
                        "operational_failure": True,
                        f"is_{self.spec.module}": True,
                    }
                )
                return AuditRecord.from_mapping(
                    payload,
                    module=self.spec.module,
                    service=prior_record.service or self.spec.module,
                )
            return AuditRecord(
                host=str(host),
                port=int(port),
                module=self.spec.module,
                service=self.spec.module,
                status="fail",
                extra={"error": message, "operational_failure": True, f"is_{self.spec.module}": False},
            )

    def _host_stage(self, ctx: AuditHookContext, *, run_deep_checks: bool) -> AuditRecord:
        steps = self._host_stage_steps(ctx, run_deep_checks=run_deep_checks)
        value: Any
        try:
            action, prior = next(steps)
            while True:
                if action == "backend":
                    assert self.spec.host_stage is not None
                    value = _invoke_host_stage(
                        self.spec.host_stage,
                        module=self.spec.module,
                        ctx=ctx,
                        run_deep_checks=prior,
                        strict_binding=self._strict_host_stage_binding,
                    )
                elif action == "panel":
                    value = web_panels.detect_panel(self.spec.module, ctx)
                elif action == "auth":
                    value = web_panels.authenticate_panel(ctx, prior)
                else:
                    value = web_panels.enumerate_panel(ctx, prior)
                action, prior = steps.send(value)
        except StopIteration as result:
            return result.value
        finally:
            steps.close()

    async def _host_stage_async_detect(self, ctx: AuditHookContext, http: Any) -> AuditRecord:
        from .clients.async_http_detect import AsyncHttpFallback

        steps = self._host_stage_steps(ctx, run_deep_checks=False)
        value: Any
        try:
            action, prior = next(steps)
            while True:
                if action == "backend" and not prior and self.spec.detect_async is not None:
                    value = _record_to_model(await self.spec.detect_async(ctx, http))
                elif action == "panel":
                    value = await web_panels.detect_panel_async(self.spec.module, ctx, http)
                else:
                    raise AsyncHttpFallback("host-stage action belongs to synchronous auth/data")
                action, prior = steps.send(value)
        except StopIteration as result:
            return result.value
        finally:
            steps.close()

    def _host_stage_steps(self, ctx: AuditHookContext, *, run_deep_checks: bool) -> Any:
        if self.spec.host_stage is None:
            raise TypeError(f"{self.spec.module} spec exposes neither hook overrides nor host_stage")
        forced_surface = getattr(ctx.target, "surface_hint", None)
        ui_first = forced_surface == "ui" or (forced_surface != "backend" and (self._ui_first(ctx) or run_deep_checks))
        native_record: AuditRecord | None = None
        if self.spec.module in web_panels.MODULE_PRODUCTS and not ui_first:
            native_record = yield ("backend", False)
            if self._is_detected(native_record):
                return native_record
        if self.spec.module in web_panels.MODULE_PRODUCTS and forced_surface != "backend":
            panel = yield ("panel", None)
            if panel is not None:
                if (
                    ctx.credential.username is not None
                    and ctx.credential.password is not None
                    and panel.get("credential_verification_status") == "available"
                ):
                    panel = yield ("auth", panel)
                if run_deep_checks and panel.get("status") in {"open_no_auth", "valid_credentials"}:
                    panel = yield ("data", panel)
                panel["provided_username"] = ctx.credential.username
                panel["provided_password"] = ctx.credential.password
                panel_ui = panel.get("ui")
                if isinstance(panel_ui, dict):
                    panel_ui.pop("session_cookie", None)
                    panel_ui.pop("session_token", None)
                    panel_ui.pop("session_authorization", None)
                return AuditRecord.from_mapping(panel, module=self.spec.module, service=self.spec.module)
        if native_record is not None:
            return native_record
        return (yield ("backend", run_deep_checks))

    def _ui_first(self, ctx: AuditHookContext) -> bool:
        if getattr(ctx.target, "surface_hint", None) == "ui":
            return True
        if getattr(ctx.target, "surface_hint", None) == "backend":
            return False
        scheme = str(getattr(getattr(ctx, "target", None), "scheme", "") or "").lower()
        return scheme in {"http", "https"} or int(ctx.port) in web_panels.UI_PORTS.get(self.spec.module, ())

    def _detect(self, ctx: AuditHookContext) -> AuditRecord:
        steps = self._detect_steps(ctx)
        value: Any
        try:
            action = next(steps)
            while True:
                if action == "panel":
                    value = web_panels.detect_panel(self.spec.module, ctx)
                elif action == "host_stage":
                    value = self._host_stage(ctx, run_deep_checks=False)
                else:
                    assert self.spec.detect is not None
                    value = _record_to_model(self.spec.detect(ctx))
                action = steps.send(value)
        except StopIteration as result:
            return result.value
        finally:
            steps.close()

    async def _detect_async(self, ctx: AuditHookContext, http: Any) -> AuditRecord:

        steps = self._detect_steps(ctx)
        value: Any
        try:
            action = next(steps)
            while True:
                if action == "panel":
                    value = await web_panels.detect_panel_async(self.spec.module, ctx, http)
                elif action == "host_stage":
                    value = await self._host_stage_async_detect(ctx, http)
                else:
                    assert self.spec.detect_async is not None
                    value = _record_to_model(await self.spec.detect_async(ctx, http))
                action = steps.send(value)
        except StopIteration as result:
            return result.value
        finally:
            steps.close()

    def _detect_steps(self, ctx: AuditHookContext) -> Any:
        if self.spec.module == "portainer" and self.spec.detect is not None:
            return (yield "backend")
        forced_surface = getattr(ctx.target, "surface_hint", None)
        if self.spec.module in web_panels.MODULE_PRODUCTS:
            if forced_surface == "ui":
                panel = yield "panel"
                if panel is not None:
                    return AuditRecord.from_mapping(panel, module=self.spec.module, service=self.spec.module)
                return AuditRecord(
                    host=str(ctx.host),
                    port=int(ctx.port),
                    module=self.spec.module,
                    service=self.spec.module,
                    status="not_service",
                    extra={f"is_{self.spec.module}": False},
                )
            if (forced_surface == "backend" or not self._ui_first(ctx)) and self.spec.detect is not None:
                backend = yield "backend"
                if self.spec.module == "minio" and backend.extra.get("detection_status") == "console":
                    if forced_surface != "backend":
                        panel = yield "panel"
                        if panel is not None:
                            return AuditRecord.from_mapping(panel, module=self.spec.module, service=self.spec.module)
                    return AuditRecord(
                        host=str(ctx.host),
                        port=int(ctx.port),
                        module="minio",
                        service="minio",
                        status="probable",
                        extra={"is_minio": False, "detection_status": "probable"},
                    )
                if forced_surface == "backend" or self._is_detected(backend):
                    return backend
                panel = yield "panel"
                return (
                    AuditRecord.from_mapping(panel, module=self.spec.module, service=self.spec.module)
                    if panel
                    else backend
                )
            if forced_surface != "backend":
                panel = yield "panel"
                if panel is not None:
                    return AuditRecord.from_mapping(panel, module=self.spec.module, service=self.spec.module)
        if self.spec.detect is not None:
            return (yield "backend")
        if self.spec.host_stage is not None:
            return (yield "host_stage")
        raise TypeError(f"{self.spec.module} spec requires either detect or host_stage")

    @observe_phase("auth")
    def _auth(self, ctx: AuditHookContext, detect_record: AuditRecord) -> AuditRecord:
        if self.spec.module == "portainer" and self.spec.auth is not None:
            return _record_to_model(self.spec.auth(ctx, detect_record))
        if detect_record.extra.get("surface") == "ui":
            if ctx.credential.username is None or ctx.credential.password is None:
                return detect_record
            if detect_record.extra.get("credential_verification_status") != "available":
                return detect_record
            panel = web_panels.authenticate_panel(ctx, detect_record.to_dict())
            panel["provided_username"] = ctx.credential.username
            panel["provided_password"] = ctx.credential.password
            ui = panel.get("ui")
            if isinstance(ui, dict):
                cookie = ui.pop("session_cookie", None)
                token = ui.pop("session_token", None)
                authorization = ui.pop("session_authorization", None)
                if ctx.lifecycle_state is not None:
                    ctx.lifecycle_state.ui_session_cookie = cookie
                    ctx.lifecycle_state.ui_session_token = token
                    ctx.lifecycle_state.ui_session_authorization = authorization
            return AuditRecord.from_mapping(panel, module=self.spec.module, service=self.spec.module)
        if self.spec.auth is not None:
            return _record_to_model(self.spec.auth(ctx, detect_record))
        if self.spec.host_stage is not None:
            if _credential_is_anonymous(ctx) and not bool(getattr(ctx.args, "defcreds", False)):
                return detect_record
            return self._host_stage(ctx, run_deep_checks=False)
        return detect_record

    @observe_phase("capabilities")
    def _capabilities(self, ctx: AuditHookContext, record: AuditRecord) -> AuditRecord:
        if record.extra.get("surface") == "ui":
            return record
        if self.spec.capabilities is not None:
            return _record_to_model(self.spec.capabilities(ctx, record))
        return record

    @observe_phase("data")
    def _data(self, ctx: AuditHookContext, record: AuditRecord) -> AuditRecord:
        if self.spec.module == "portainer" and self.spec.data is not None:
            return _record_to_model(self.spec.data(ctx, record))
        if record.extra.get("surface") == "ui":
            if record.status not in {"open_no_auth", "valid_credentials"}:
                return record
            panel = record.to_dict()
            ui = panel.get("ui")
            if isinstance(ui, dict) and ctx.lifecycle_state is not None:
                if cookie := getattr(ctx.lifecycle_state, "ui_session_cookie", None):
                    ui["session_cookie"] = cookie
                if token := getattr(ctx.lifecycle_state, "ui_session_token", None):
                    ui["session_token"] = token
                if authorization := getattr(ctx.lifecycle_state, "ui_session_authorization", None):
                    ui["session_authorization"] = authorization
            panel = web_panels.enumerate_panel(ctx, panel)
            panel_ui = panel.get("ui")
            if isinstance(panel_ui, dict):
                panel_ui.pop("session_cookie", None)
                panel_ui.pop("session_token", None)
                panel_ui.pop("session_authorization", None)
            return AuditRecord.from_mapping(panel, module=self.spec.module, service=self.spec.module)
        if self.spec.data is not None:
            return _record_to_model(self.spec.data(ctx, record))
        if self.spec.host_stage is not None:
            return self._host_stage(ctx, run_deep_checks=True)
        return record

    def _select_deep_record(
        self,
        detect_record: AuditRecord,
        auth_records: list[tuple[AuditCredentialRun, AuditRecord]],
    ) -> tuple[AuditCredentialRun, AuditRecord, str]:
        if self._should_keep_anonymous_detect_record(detect_record):
            return AuditCredentialRun(source="anonymous"), detect_record, "status=open_no_auth"
        for credential, record in auth_records:
            gate = self._credential_gate(credential, record)
            if gate[0]:
                return credential, record, gate[1]
        if (
            self.spec.fallback_to_anonymous_detect_record
            and str(detect_record.status or "") == "open_no_auth"
            and self._deep_gate(detect_record)[0]
        ):
            fallback_record = detect_record
            if auth_records:
                import dataclasses as _dc

                last_attempt = auth_records[-1][1]
                diagnostic_fields: dict[str, Any] = {
                    key: last_attempt.extra.get(key)
                    for key in (
                        "auth_valid",
                        "auth_probe_status",
                        "auth_probe_http_status",
                        "auth_probe_endpoint",
                        "auth_error_detail",
                        "network_attempted",
                        "verification_capability",
                        "credential_verification",
                        "effective_username",
                        "error",
                    )
                    if key in last_attempt.extra
                }
                fallback_record = _dc.replace(
                    detect_record,
                    extra={**detect_record.extra, **diagnostic_fields},
                )
            return (
                AuditCredentialRun(source="anonymous"),
                fallback_record,
                "anonymous fallback after credential attempts",
            )
        if auth_records:
            return auth_records[-1][0], auth_records[-1][1], "no accepted credentials"
        return AuditCredentialRun(source="anonymous"), detect_record, "no credentials"

    def _credential_gate(
        self,
        credential: AuditCredentialRun,
        record: AuditRecord,
    ) -> tuple[bool, str]:
        if record.extra.get("surface") == "ui":
            state = str(record.extra.get("credential_state") or "")
            return state == "valid", f"UI credential {state or 'unverified'}"
        supplied = any(value is not None for value in (credential.username, credential.password, credential.token))
        proof_fields: tuple[str, ...] = (
            "provided_credentials_ok",
            "credential_verified",
            "auth_valid",
            "token_valid",
            "credentials_valid",
            "login_success",
        )
        # Exhaustive sweeps may retain the explicit pair's verdict after a
        # later default candidate succeeds. Proof must be candidate-specific.
        if credential.source == "default":
            proof_fields = tuple(field for field in proof_fields if field != "provided_credentials_ok")
        credential_state = str(record.extra.get("credential_state") or "").lower()
        if supplied and (
            any(record.extra.get(field) is False for field in proof_fields)
            or credential_state in {"invalid", "unknown", "unverified", "verification_unavailable", "inconclusive"}
        ):
            return False, "credential rejected or unverified"
        if self.spec.credential_gate is not None:
            return self.spec.credential_gate(credential, record)
        if supplied:
            if any(record.extra.get(field) is True for field in proof_fields):
                return True, "credential verified by product"
            status = str(record.status or "")
            # Legacy native-protocol adapters report a successful handshake
            # with one of these statuses. A public/anonymous response, generic
            # HTTP success, or a denied resource never verifies a credential.
            if status in {
                "valid_credentials",
                "weak_default_creds",
                "auth_valid",
                "token_ok",
                "valid_token",
                "token_accepted",
            }:
                return True, f"status={status}"
            return False, "credential unverified"
        return self._deep_gate(record)

    def _record_credential_attempt(
        self,
        credential: AuditCredentialRun,
        record: AuditRecord,
        attempts: list[tuple[AuditCredentialRun, AuditRecord]],
        debug_emit: Callable[[str], None] | None,
    ) -> AuditRecord:
        if not self.spec.record_skipped_credential_attempts:
            attempts.append((credential, record))
            return record
        record = replace(
            record,
            extra={
                **record.extra,
                "credential_state": record.extra.get("credential_state")
                or (
                    "valid"
                    if record.status == "valid_credentials"
                    else "invalid"
                    if record.status == "invalid_credentials"
                    else "unknown"
                ),
                "auth_http_status": record.extra.get("auth_http_status", 0),
                "credential_results": [{"username": credential.username}],
                "credential_password": credential.password,
                "credential_source": credential.source,
                "credential_verification_reason": record.extra.get("credential_verification_reason")
                or record.extra.get("error")
                or str(record.status),
            },
        )
        with self._credential_ledger_lock:
            if self._audit_cancelled.is_set():
                return record
            attempts.append((credential, record))
            ledger = self._active_credential_ledgers.get(_credential_job_key())
            if ledger is not None:
                ledger["current"] = None
                if debug_emit is not None:
                    history = self._with_attempted_credentials(record, attempts, force=True)
                    self._debug_credential_ledger(history, debug_emit, start=ledger["debug_count"])
                    ledger["debug_count"] = len(history.extra.get("attempted_credentials") or [])
        return record

    def _skipped_credential_records(
        self,
        detect_record: AuditRecord,
        candidates: Iterable[AuditCredentialRun],
        reason: str,
    ) -> list[tuple[AuditCredentialRun, AuditRecord]]:
        return [
            (
                credential,
                replace(
                    detect_record,
                    status="skipped",
                    extra={
                        **detect_record.extra,
                        "credential_state": "unknown",
                        "reason": reason,
                        "credential_verification_reason": reason,
                    },
                ),
            )
            for credential in candidates
            if any(value is not None for value in (credential.username, credential.password, credential.token))
        ]

    def _debug_credential_ledger(
        self,
        record: AuditRecord,
        emit: Callable[[str], None],
        *,
        start: int = 0,
    ) -> None:
        for attempt in (record.extra.get("attempted_credentials") or [])[start:]:
            emit(
                f"credential_attempt host={record.host} port={record.port} result="
                + json.dumps(attempt, ensure_ascii=False)
            )

    def _cancelled_credential_records(self) -> list[tuple[AuditRecord, Counter[str], int]]:
        """Snapshot active opt-in ledgers while workers are being abandoned.

        No socket or worker wait is needed: cancellation makes the in-flight
        identity unverified and every remaining planned pair explicitly skipped.
        """
        records: list[tuple[AuditRecord, Counter[str], int]] = []
        with self._credential_ledger_lock:
            records.extend(self._completed_credential_ledgers.values())
            self._completed_credential_ledgers.clear()
            for worker_id, ledger in self._active_credential_ledgers.items():
                detect = ledger["detect"]
                if not self._is_detected(detect):
                    # Keep a structured cancellation diagnostic, without
                    # claiming any credential phase for an unproven target.
                    records.append(
                        (
                            replace(
                                detect,
                                status="cancelled",
                                extra={**detect.extra, "reason": "cancelled", "cancelled_stage": "detect"},
                            ),
                            self._credential_phase_counts.get(worker_id, Counter()).copy(),
                            ledger["debug_count"],
                        )
                    )
                    continue
                attempts = list(ledger["attempts"])
                current = ledger["current"]
                if current is not None:
                    attempts.append(
                        (
                            current,
                            replace(
                                detect,
                                status="auth_required",
                                extra={
                                    **detect.extra,
                                    "credential_state": "unknown",
                                    "reason": "cancelled",
                                    "credential_verification_reason": "cancelled during identity verification",
                                },
                            ),
                        )
                    )
                _credential, selected, _reason = self._select_deep_record(detect, attempts)
                remaining = ledger["candidates"][len(attempts) :]
                skipped = self._skipped_credential_records(detect, remaining, "cancelled")
                attempts.extend(skipped)
                selected = replace(
                    selected,
                    extra={
                        **selected.extra,
                        "credential_stop_reason": "cancelled",
                        "credential_attempts_skipped": len(skipped),
                    },
                )
                record = self._with_attempted_credentials(selected, attempts, force=True)
                counts = self._credential_phase_counts.get(worker_id, Counter()).copy()
                records.append((record, counts, ledger["debug_count"]))
            self._active_credential_ledgers.clear()
        return records

    def _with_attempted_credentials(
        self,
        record: AuditRecord,
        auth_records: list[tuple[AuditCredentialRun, AuditRecord]],
        *,
        force: bool,
    ) -> AuditRecord:
        attempts_payload: list[dict[str, Any]] = []
        for credential, attempt in auth_records:
            if force and credential.username is None and credential.password is None and credential.token is None:
                continue
            payload: dict[str, Any] = {
                "username": credential.username,
                "password": credential.password,
                "source": credential.source,
                "status": str(attempt.status),
            }
            if force:
                payload["error"] = attempt.extra.get("error")
            if self.spec.record_skipped_credential_attempts:
                payload["reason"] = (
                    attempt.extra.get("reason")
                    or attempt.extra.get("credential_verification_reason")
                    or attempt.extra.get("error")
                    or str(attempt.status)
                )
            for field_name in self.spec.credential_attempt_detail_fields:
                if field_name in attempt.extra:
                    payload[field_name] = attempt.extra.get(field_name)
            attempts_payload.append(payload)
        if not force and len(attempts_payload) <= 1:
            return record
        import dataclasses as _dc

        extra = {**record.extra, "attempted_credentials": attempts_payload}
        if self.spec.record_skipped_credential_attempts:
            skipped = sum(item["status"] == "skipped" for item in attempts_payload)
            extra.update(
                {
                    "credential_attempts_planned": len(attempts_payload),
                    "credential_attempts_executed": len(attempts_payload) - skipped,
                    "credential_attempts_unverified": sum(
                        item["status"] not in {"valid_credentials", "invalid_credentials", "skipped"}
                        for item in attempts_payload
                    ),
                    "credential_attempts_skipped": skipped,
                }
            )
        return _dc.replace(record, extra=extra)

    def _is_detected(self, record: AuditRecord) -> bool:
        if self.spec.module in web_panels.MODULE_PRODUCTS and record.extra.get("is_ui") is True:
            return True
        if self.spec.is_detected is not None:
            return bool(self.spec.is_detected(record))
        marker = f"is_{self.spec.module}"
        marker_value = record.extra.get(marker)
        if marker_value is True:
            return True
        # A status word describes the outcome only after product identity has
        # been established; it is not a fingerprint.  Treating arbitrary
        # non-failure statuses as detection let generic HTTP responses enter
        # authentication, discovery, and CVE phases.  Real module specs must
        # either expose their strict ``is_<module>`` marker or provide an
        # explicit ``is_detected`` predicate.
        return False

    def _not_detected_reason(self, record: AuditRecord) -> str:
        status = str(record.status or "")
        if status.startswith("not_"):
            return status
        marker = f"is_{self.spec.module}"
        if record.extra.get(marker) is False:
            return f"not_{self.spec.module}"
        return "not_detected"

    def _deep_gate(self, record: AuditRecord) -> tuple[bool, str]:
        if self.spec.deep_gate is not None:
            return self.spec.deep_gate(record)
        if (
            self.spec.discover_public_on_auth_required
            and bool(getattr(self.args, "discover", False))
            and record.status == "auth_required"
            and record.extra.get("provided_credentials") is False
        ):
            return True, "public content discovery requested"
        return self._default_deep_gate(record)

    def _default_deep_gate(self, record: AuditRecord) -> tuple[bool, str]:
        status = str(record.status or "unknown")
        allowed = {
            "ok",
            "open",
            "open_no_auth",
            "anonymous_access",
            "detected",
            "token_ok",
            "valid_credentials",
            "auth_valid",
            "weak_default_creds",
            "invalid_credentials_anonymous",
            "valid_token",
            "token_accepted",
            "insufficient_privileges",
        }
        if status in allowed:
            return True, f"status={status}"
        if status.startswith("not_"):
            return False, status
        return False, f"status={status}"


def run_basic_host_audit(
    args: Any,
    logger: Any,
    *,
    console: Any,
    label: str,
    validate: Callable[[Any, Any], int | None],
    build_plan: Callable[[Any], AuditCommandPlan],
    build_spec: Callable[[Any], ModuleAuditSpec],
) -> int:
    """Standard module entrypoint: validate args, plan targets, run the staged
    audit, emit colored results. Modules with extra pre/post logic (shells,
    listeners, credential expansion) keep their own `run_*_stage`; the byte
    -identical ones delegate here to avoid duplicating the skeleton. The module
    creates and passes `console` so it stays patchable in module-level tests."""
    name = label.lower()
    cfg = AuditConfig.from_namespace(args)
    if hasattr(console, "set_structured_output"):
        console.set_structured_output(cfg.output_format == "json")
    validation_rc = validate(args, console)
    if validation_rc is not None:
        return int(validation_rc)
    try:
        plan = build_plan(args)
    except ValueError as exc:
        console.error(str(exc))
        return 2
    if bool(getattr(args, "os_shell", False)):
        from .modules.execution_api import validate_os_shell_plan

        if validate_os_shell_plan(plan, console) is not None:
            return 2
    if cfg.debug and not getattr(args, "debug_emit", None):
        args.debug_emit = console.info
    if cfg.debug:
        suffix = f" format={cfg.output_format}"
        if cfg.output:
            suffix += f" output={cfg.output}"
        console.info(f"{name} audit started:" + suffix)
    try:
        runner = AuditCommandRunner(args=args, spec=build_spec(args), logger=logger, console=console)
        result = runner.run_plan(plan)
    except ValueError as exc:
        console.error(str(exc))
        return 2
    except OSError as exc:
        console.error(f"failed to process {name} output: {exc}")
        return 2
    if cfg.debug and result.detected_count == 0 and not result.summary_emitted and hasattr(console, "warn"):
        # Only a last-resort note: when run_plan already emitted a no-service
        # summary (with a failure count where needed), this coarser and
        # potentially misleading "unreachable" line would duplicate it.
        console.warn(f"all {name} targets are unreachable")
    return command_result_exit_code(result)


def get_command_progress_owner(args: Any) -> CommandProgressOwner | None:
    owner = getattr(args, "_progress_owner", None)
    return owner if isinstance(owner, CommandProgressOwner) else None


def start_command_progress(
    args: Any,
    label: str,
    total: int,
    *,
    enabled: bool = True,
    leave: bool = True,
    render_initial: bool | None = None,
    refresh_interval_s: float | None = None,
) -> ProgressHandle:
    """Start a command-owned progress handle.

    Stage modules should not instantiate `ProgressBar` directly. The CLI owns
    the lifecycle through `CommandProgressOwner`; stages only request a handle
    and advance it as work units complete.
    """

    owner = get_command_progress_owner(args)
    if owner is None:
        return NoOpProgress()
    initial = bool(getattr(args, "output", None)) if render_initial is None else bool(render_initial)
    effective_refresh_interval_s = (
        getattr(args, "_progress_refresh_interval_s", None) if refresh_interval_s is None else refresh_interval_s
    )
    return owner.start(
        label,
        total,
        enabled=enabled,
        leave=leave,
        render_initial=initial,
        refresh_interval_s=effective_refresh_interval_s,
    )


def start_audit_progress(
    label: str,
    total: int,
    *,
    enabled: bool = False,
    leave: bool = True,
    owner: CommandProgressOwner | None = None,
) -> ProgressHandle:
    """Compatibility hook for low-level audit helpers.

    Direct audit functions no longer own progress. If a command owner is
    explicitly provided it can be used, otherwise this is a no-op even when the
    legacy `show_progress` flag is true.
    """

    if owner is None:
        return NoOpProgress()
    return owner.start(label, total, enabled=enabled, leave=leave)


class StageTelemetryBuilder:
    """Small per-host telemetry helper for staged modules.

    It centralizes debug event buffering, stage trace formatting, and additive
    JSON fields. Modules still decide their own transition semantics.
    """

    def __init__(
        self,
        *,
        host: str,
        port: int,
        attempts: int,
        debug: bool,
        debug_emit: Any = None,
    ) -> None:
        self.host = str(host)
        self.port = int(port)
        self.attempts = max(1, int(attempts))
        self.debug_enabled = bool(debug)
        self.debug_emit = debug_emit
        self.events: list[str] = []
        self.stages: list[dict[str, Any]] = []

    def debug(self, message: str) -> None:
        if not self.debug_enabled:
            return
        text = str(message)
        self.events.append(text)
        if self.debug_emit is not None:
            self.debug_emit(f"{self.host}:{self.port} {text}")

    def retry(self, stage: str, attempt: int, backoff: float, reason: str) -> None:
        self.debug(format_retry_decision(stage, attempt, self.attempts, backoff, reason))

    def stage(self, stage_name: str, result: str, error: str | None = None, duration_ms: int = 0) -> None:
        entry = StageTrace(
            stage_name=stage_name,
            attempt=1,
            duration_ms=duration_ms,
            result=result,
            error=error or None,
        ).to_dict()
        self.stages.append(entry)
        self.debug(format_stage_trace(stage_name, 1, entry["duration_ms"], result, entry["error"]))

    def attach(self, record: dict[str, Any], *, status: str, total_ms: int) -> dict[str, Any]:
        stage_failed_at: str | None = None
        for stage_entry in self.stages:
            if str(stage_entry.get("result") or "") == "error":
                stage_failed_at = str(stage_entry.get("stage_name") or "")
                break

        stage_durations_ms = {
            str(item.get("stage_name") or ""): int(item.get("duration_ms") or 0) for item in self.stages
        }
        stage_attempts = {str(item.get("stage_name") or ""): self.attempts for item in self.stages}
        record["stages"] = self.stages
        record["stage_failed_at"] = stage_failed_at
        record["stage_durations_ms"] = stage_durations_ms
        record["stage_attempts"] = stage_attempts
        record["debug_events"] = self.events
        record["debug_events_streamed"] = bool(self.debug_enabled and self.debug_emit is not None)
        record["stage_timing_status"] = status
        total_ms_int = int(max(0, total_ms))
        record["stage_timing_total_ms"] = total_ms_int
        # Unify the timer contract across modules: every record that goes through telemetry
        # gets `elapsed_ms` populated as well. Some modules (e.g. docker) historically
        # omitted it; fail-path records lost both top-level timers entirely. Without this
        # the JSON contract is uneven and downstream consumers must check both fields.
        existing_elapsed = record.get("elapsed_ms")
        if not isinstance(existing_elapsed, int) or existing_elapsed <= 0:
            record["elapsed_ms"] = total_ms_int
        return record
