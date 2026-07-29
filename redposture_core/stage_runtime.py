"""Shared runtime helpers for staged audit modules."""

from __future__ import annotations

import functools
import inspect
import json
import os
import sys
import threading
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Literal

from . import audit_models as _audit_models
from .audit_config import AuditConfig
from .audit_models import StageTrace
from .progress import CommandProgressOwner, NoOpProgress, ProgressHandle
from .scheduler import BoundedScheduler
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

    current_payload = current.to_dict()
    current_stages = [stage.to_dict() for stage in current.stages]
    current_names = {str(stage.get("stage_name") or "") for stage in current_stages}

    carried: list[dict[str, Any]] = []
    if prior is not None:
        for stage in prior.stages:
            if stage.stage_name not in current_names:
                carried.append(stage.to_dict())

    stages = carried + current_stages
    stage_name = _PHASE_STAGE_NAMES[phase]
    added = stage_name not in {str(stage.get("stage_name") or "") for stage in stages}
    duration = max(0, int(duration_ms))
    if added:
        trace = StageTrace(
            stage_name=stage_name,
            attempt=1,
            duration_ms=duration,
            result=str(result or "ok"),
            error=str(error).strip() if error else None,
        )
        stages.append(trace.to_dict())
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
        prior_payload = prior.to_dict()
        prior_durations = prior_payload.get("stage_durations_ms")
        prior_attempts = prior_payload.get("stage_attempts")
        if isinstance(prior_durations, Mapping):
            stage_durations.update({str(key): int(value or 0) for key, value in prior_durations.items()})
        if isinstance(prior_attempts, Mapping):
            stage_attempts.update({str(key): int(value or 0) for key, value in prior_attempts.items()})
    current_durations = current_payload.get("stage_durations_ms")
    current_attempts = current_payload.get("stage_attempts")
    if isinstance(current_durations, Mapping):
        stage_durations.update({str(key): int(value or 0) for key, value in current_durations.items()})
    if isinstance(current_attempts, Mapping):
        stage_attempts.update({str(key): int(value or 0) for key, value in current_attempts.items()})
    if added:
        stage_durations.setdefault(stage_name, duration)
        stage_attempts.setdefault(stage_name, 1)

    current_payload["stages"] = stages
    current_payload["stage_durations_ms"] = stage_durations
    current_payload["stage_attempts"] = stage_attempts
    current_payload.setdefault("timestamp", utc_now_iso())
    if not current_payload.get("stage_failed_at") and added and str(result).lower() in {"error", "fail", "timeout"}:
        current_payload["stage_failed_at"] = stage_name
    return (
        AuditRecord.from_mapping(
            current_payload,
            module=current.module,
            service=current.service,
        ),
        added,
    )


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

    def __init__(self, output_path: str | None, emit_line: Callable[[str], None], *, append: bool = False) -> None:
        self.output_path = output_path
        self.emit_line = emit_line
        self.output_written = bool(append)
        self._append = bool(append)
        self._handle: Any = None
        self._lock = threading.Lock()

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
            self._prepare_unlocked()

    def emit_many(self, lines: Iterable[str]) -> None:
        buffered = [line for line in lines if line]
        if not buffered:
            return
        with self._lock:
            if self.output_path:
                self._prepare_unlocked()
                for line in buffered:
                    self._handle.write(line + "\n")
                self._handle.flush()
            # Emit to console inside the lock too: without it a second thread's
            # `print()` can splice its output into the first thread's partial
            # write on POSIX (write(2) is atomic per-syscall but Python's
            # `print(...)` performs two writes).
            for line in buffered:
                self.emit_line(line)
            self.output_written = True

    def close(self) -> None:
        with self._lock:
            if self._handle is not None:
                self._handle.close()
                self._handle = None


def _build_colored_emit(console: Any, colorize: Callable[[Any, str], bool] | None) -> Callable[[str], None]:
    """Build a stdout emitter that colorizes marker lines via the spec's explicit
    `colorize` hook, falling back to plain output. The colorizer no-ops (returns
    `False`) on lines that don't start with its tag, so JSON output stays clean;
    file output never reaches here (the sink writes files directly)."""

    def emit(line: str) -> None:
        if colorize is not None and colorize(console, line):
            return
        console.plain(line)

    return emit


AuditPhase = Literal["detect", "auth", "capabilities", "data"]


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
    # E3 opt-in: when True + `--defcreds` + detect status==open_no_auth, the
    # runner returns the detect record instead of re-running the host_stage
    # against every default credential. Kafka hardcodes this behavior in
    # `_should_keep_anonymous_detect_record`; other modules opt in via this
    # flag as their credential loop is proven safe to skip on anon-open.
    keep_anonymous_open_no_auth: bool = False
    # Opt-in text-output policy for discovery-oriented modules. The runner
    # retains matching records for callbacks, debug output, and JSON.
    suppress_undetected_records_in_text: bool = False
    # A module may distinguish successful identity verification from a record
    # that merely remains usable through anonymous access.
    credential_gate: Callable[[AuditCredentialRun, AuditRecord], tuple[bool, str]] | None = None
    # Preserve every credential that was actually tried, including a
    # successful final candidate. Default-off keeps other module payloads
    # unchanged.
    record_all_credential_attempts: bool = False
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


@dataclass(frozen=True)
class _AuditDetectOutcome:
    record: AuditRecord
    lifecycle_state: Any = None
    runtime_stage_telemetry: bool = False


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
    try:
        target_plan = stream_scan_target_specs(
            targets,
            policy=TargetParsePolicy(url_mode="preserve", path_policy="preserve"),
        )
    except (OSError, ValueError) as exc:
        raise ValueError(f"failed to parse targets: {exc}") from exc
    if not target_plan:
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

    return AuditCommandPlan(
        target_plan=target_plan,
        ports=port_tuple,
        credential_runs=credential_runs,
        output_path=cfg.output,
        output_format=cfg.output_format,
        workers=cfg.workers,
    )


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
        except ValueError as exc:
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
            )
        except ValueError as exc:
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


def _invoke_host_stage(
    func: Callable[..., Any],
    *,
    module: str,
    ctx: AuditHookContext,
    run_deep_checks: bool | None = None,
    strict_binding: _StrictHostStageBinding | None = None,
) -> AuditRecord:
    if strict_binding is not None:
        func = strict_binding.func
        signature = strict_binding.signature
    else:
        func = _resolve_host_stage(func)
        signature = _cached_signature(func)
    if run_deep_checks is not None:
        ctx = AuditHookContext(
            args=ctx.args,
            logger=ctx.logger,
            host=ctx.host,
            port=ctx.port,
            credential=ctx.credential,
            target=ctx.target,
            run_deep_checks=bool(run_deep_checks),
            debug_emit=ctx.debug_emit,
            phase=ctx.phase,
            credential_runs=ctx.credential_runs,
            lifecycle_state=ctx.lifecycle_state,
        )

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
    return [line for line in lines if line]


def render_record_with_module(
    render_module: Any, record: AuditRecord, output_format: str, *, debug: bool = False
) -> list[str]:
    return render_with_plan(build_render_plan(render_module), record.to_dict(), output_format, debug=debug)


def _record_looks_detected(record: dict[str, Any]) -> bool:
    marker_values = [value for key, value in record.items() if key.startswith("is_")]
    if any(value is True for value in marker_values):
        return True
    if any(value is False for value in marker_values):
        return False
    status = str(record.get("status") or "").strip().lower()
    if not status or status == "fail" or status.startswith(("not_", "unknown")):
        return False
    return True


_PRE_DETECT_NOISE_MARKERS = (
    "connection refused",
    "connection reset",
    "reset by peer",
    "connection aborted",
    "operation not permitted",
    "connection timeout",
    "timed out",
    "timeout",
    "unexpected eof",
    "protocol closed before",
    "closed before",
    "remote end closed",
    "server closed",
    "no route to host",
    "network unreachable",
    "host is down",
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
    "peer rejected tls handshake",
    "wrong_version_number",
    "unexpected_eof_while_reading",
    "sslv3_alert",
)


def _record_noise_text(record: dict[str, Any]) -> str:
    values: list[str] = []
    for key in ("error", "protocol_error", "detect_error", "last_error"):
        value = record.get(key)
        if value:
            values.append(str(value))
    stage_failed_at = record.get("stage_failed_at")
    if stage_failed_at:
        values.append(f"stage_failed_at={stage_failed_at}")
    stages = record.get("stages")
    if isinstance(stages, list):
        for stage in stages:
            if isinstance(stage, dict) and stage.get("error"):
                values.append(str(stage.get("error")))
    debug_events = record.get("debug_events")
    if isinstance(debug_events, list):
        for event in debug_events:
            if isinstance(event, str):
                values.append(event)
    return " ".join(values).lower()


def is_pre_detect_network_noise(record: AuditRecord | dict[str, Any]) -> bool:
    """Return true for non-service network/protocol noise before detection.

    These records are useful in debug/JSON, but noisy in normal TXT scans over
    large target lists. The check intentionally refuses to suppress anything
    that already looks like a detected service or an auth/data failure.
    """

    payload = record.to_dict() if isinstance(record, AuditRecord) else dict(record)
    if _record_looks_detected(payload):
        return False
    status = str(payload.get("status") or "").lower()
    if status and status not in {"fail", "not_detected", "not_found", "not_service"} and not status.startswith("not_"):
        return False
    text = _record_noise_text(payload)
    if not text:
        return False
    return any(marker in text for marker in _PRE_DETECT_NOISE_MARKERS)


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
        return bool(getattr(args, "insecure", False))
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
        if emit_line is not None:
            self.emit_line = emit_line
        elif console is not None:
            self.emit_line = _build_colored_emit(console, spec.colorize)
        else:
            self.emit_line = print

    def _render_record(
        self, record: AuditRecord, render_plan: RenderPlan | None, output_format: str, debug: bool
    ) -> list[str]:
        if self.spec.render is not None:
            return [line for line in self.spec.render(record) if line]
        if render_plan is not None:
            return render_with_plan(render_plan, record.to_dict(), output_format, debug=debug)
        return []

    def _suppress_in_normal_text(self, record: AuditRecord) -> bool:
        if is_pre_detect_network_noise(record):
            return True
        if not self.spec.suppress_undetected_records_in_text or self._is_detected(record):
            return False
        status = str(record.status or "").strip().lower()
        return status == "fail" or status.startswith("not_")

    def run_plan(self, plan: AuditCommandPlan) -> AuditCommandResult:
        if self.console is not None and hasattr(self.console, "set_structured_output"):
            self.console.set_structured_output(plan.output_format == "json")
        sink = LineOutputSink(plan.output_path, self.emit_line, append=plan.append)
        sink.prepare()
        try:
            return self._run_prepared_plan(plan, sink)
        finally:
            self._close_all_lifecycle_states()
            sink.close()

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
        scheduler: BoundedScheduler[tuple[int, str, int, ScanTargetSpec | None], _AuditPipelineOutcome] = (
            BoundedScheduler(max_workers=worker_count)
        )
        emitted_lines = 0
        suppressed_records = 0
        retained_records: list[AuditRecord] = []
        record_count = 0
        detected_count = 0
        status_counts: dict[str, int] = {}
        record_callbacks = _record_callbacks_for_args(self.args)
        render_plan = build_render_plan(self.spec.render_module) if self.spec.render_module is not None else None
        debug = bool(getattr(self.args, "debug", False))
        raw_debug_emit = getattr(self.args, "debug_emit", None) if debug else None
        cancelled = threading.Event()

        def _debug_emit(message: str) -> None:
            # BoundedScheduler deliberately detaches active daemon workers on
            # cancellation. Do not let those workers keep writing debug output
            # after the coordinator has returned control to the caller.
            if not cancelled.is_set() and callable(raw_debug_emit):
                raw_debug_emit(message)

        debug_emit = _debug_emit if callable(raw_debug_emit) else None
        if debug_emit is not None:
            debug_emit(format_pass_marker(1, "detect", "start", total=target_count, mode="pipeline"))

        def _emit_record(record: AuditRecord) -> None:
            nonlocal emitted_lines, suppressed_records
            if plan.output_format == "json":
                payload = record.to_dict()
                for field_name in self.spec.structured_output_redact_fields:
                    payload.pop(field_name, None)
                emitted_lines += 1
                sink.emit_many((json.dumps(payload, ensure_ascii=False),))
                return
            if self.spec.render is None and self.spec.render_module is None:
                return
            if not debug and self._suppress_in_normal_text(record):
                suppressed_records += 1
                return
            lines = self._render_record(record, render_plan, plan.output_format, debug)
            emitted_lines += len(lines)
            sink.emit_many(lines)

        def _finalize_record(record: AuditRecord) -> None:
            nonlocal record_count
            record_count += 1
            status = str(record.status or "")
            status_counts[status] = status_counts.get(status, 0) + 1
            if retain_records:
                retained_records.append(record)
            if record_callbacks:
                payload = record.to_dict()
                for record_callback in record_callbacks:
                    record_callback(dict(payload))
            _emit_record(record)

        total_deep_candidates = 0
        processed_deep = 0
        try:
            for window in plan.iter_target_windows():
                for (_idx, _host, _port, _target), outcome in scheduler.iter_completed(
                    window,
                    lambda item: self._run_target_pipeline(
                        item[1],
                        item[2],
                        item[3],
                        plan.credential_runs,
                        debug_emit,
                    ),
                ):
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
        except BaseException:
            cancelled.set()
            raise
        finally:
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
        if record_count == 0 and plan.fallback_target_count > 0 and plan.output_format == "json":
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
            sink.emit_many((json.dumps(summary, ensure_ascii=False),))
        elif emitted_lines == 0 and fallback_target_count > 0 and plan.output_format != "json":
            if fallback_target_count > 1:
                fallback_lines = (f"[*] No {self.spec.label} service detected on {fallback_target_count} target(s)",)
            else:
                fallback_lines = (f"[*] No {self.spec.label} service detected on target",)
            emitted_lines += len(fallback_lines)
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
        if close is None:
            return
        for state in states:
            try:
                close(state)
            except Exception:  # noqa: BLE001 - best-effort outer cleanup
                continue

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
            )

    def _run_target_pipeline(
        self,
        host: str,
        port: int,
        target: ScanTargetSpec | None,
        credential_runs: tuple[AuditCredentialRun, ...],
        debug_emit: Callable[[str], None] | None,
    ) -> _AuditPipelineOutcome:
        """Run one target's entire lifecycle in a single scheduler worker."""

        detect_outcome = self._run_detect_with_state(host, port, target, debug_emit)
        detect_record = detect_outcome.record
        detected = self._is_detected(detect_record)
        deep_candidate = detected and self._deep_gate(detect_record)[0]
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
        final_record = self._run_deep_and_close_state(
            host,
            port,
            target,
            detect_outcome,
            credential_runs,
            debug_emit,
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
        return _AuditPipelineOutcome(
            record=final_record,
            detected=True,
            deep_candidate=deep_candidate,
            deep_processed=deep_processed,
        )

    def _run_deep_and_close_state(
        self,
        host: str,
        port: int,
        target: ScanTargetSpec | None,
        detect_outcome: _AuditDetectOutcome,
        credential_runs: tuple[AuditCredentialRun, ...],
        debug_emit: Callable[[str], None] | None,
    ) -> AuditRecord:
        try:
            return self._safe_record(
                host,
                port,
                lambda: self._run_deep_lifecycle(
                    host,
                    port,
                    target,
                    detect_outcome.record,
                    credential_runs,
                    debug_emit,
                    lifecycle_state=detect_outcome.lifecycle_state,
                    runtime_stage_telemetry=detect_outcome.runtime_stage_telemetry,
                ),
                prior_record=detect_outcome.record,
            )
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
    ) -> AuditRecord:
        if self._host_stage_is_monolithic:
            return self._run_monolithic_deep_lifecycle(
                host,
                port,
                target,
                detect_record,
                credential_runs,
                debug_emit,
                lifecycle_state,
            )

        auth_records: list[tuple[AuditCredentialRun, AuditRecord]] = []
        candidates = credential_runs or (AuditCredentialRun(source="anonymous"),)
        retain_all_attempts = self.spec.record_all_credential_attempts or self.spec.continue_after_credential_success
        if self._should_keep_anonymous_detect_record(detect_record):
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
            gate_reason = "status=open_no_auth"
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
                auth_started_at = time.monotonic()
                try:
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
                    auth_records.append((credential, auth_record))
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
                auth_records.append((credential, auth_record))
                if (
                    self._credential_gate(credential, auth_record)[0]
                    and not self.spec.continue_after_credential_success
                ):
                    break
            selected_credential, selected_record, gate_reason = self._select_deep_record(detect_record, auth_records)
        if retain_all_attempts:
            selected_record = self._with_attempted_credentials(selected_record, auth_records, force=True)
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
    ) -> AuditRecord:
        """Run each monolithic credential attempt once with actions enabled.

        The old generic lifecycle called the same host_stage for auth with
        ``run_deep_checks=False`` and then called it again for data with
        ``run_deep_checks=True``. The selected credential therefore repeated
        its connection, authentication and baseline queries. A monolithic stage
        already owns auth+actions, so its deep result is final.
        """

        candidates = credential_runs or (AuditCredentialRun(source="anonymous"),)
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
                extra={"error": message, f"is_{self.spec.module}": False},
            )

    def _host_stage(self, ctx: AuditHookContext, *, run_deep_checks: bool) -> AuditRecord:
        if self.spec.host_stage is None:
            raise TypeError(f"{self.spec.module} spec exposes neither hook overrides nor host_stage")
        return _invoke_host_stage(
            self.spec.host_stage,
            module=self.spec.module,
            ctx=ctx,
            run_deep_checks=run_deep_checks,
            strict_binding=self._strict_host_stage_binding,
        )

    def _detect(self, ctx: AuditHookContext) -> AuditRecord:
        if self.spec.detect is not None:
            return _record_to_model(self.spec.detect(ctx))
        if self.spec.host_stage is not None:
            return self._host_stage(ctx, run_deep_checks=False)
        raise TypeError(f"{self.spec.module} spec requires either detect or host_stage")

    def _auth(self, ctx: AuditHookContext, detect_record: AuditRecord) -> AuditRecord:
        if self.spec.auth is not None:
            return _record_to_model(self.spec.auth(ctx, detect_record))
        if self.spec.host_stage is not None:
            if _credential_is_anonymous(ctx) and not bool(getattr(ctx.args, "defcreds", False)):
                return detect_record
            return self._host_stage(ctx, run_deep_checks=False)
        return detect_record

    def _capabilities(self, ctx: AuditHookContext, record: AuditRecord) -> AuditRecord:
        if self.spec.capabilities is not None:
            return _record_to_model(self.spec.capabilities(ctx, record))
        return record

    def _data(self, ctx: AuditHookContext, record: AuditRecord) -> AuditRecord:
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
                diagnostic_fields = {
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
        if self.spec.credential_gate is not None:
            return self.spec.credential_gate(credential, record)
        return self._deep_gate(record)

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
            for field_name in self.spec.credential_attempt_detail_fields:
                if field_name in attempt.extra:
                    payload[field_name] = attempt.extra.get(field_name)
            attempts_payload.append(payload)
        if not force and len(attempts_payload) <= 1:
            return record
        import dataclasses as _dc

        return _dc.replace(
            record,
            extra={**record.extra, "attempted_credentials": attempts_payload},
        )

    def _is_detected(self, record: AuditRecord) -> bool:
        if self.spec.is_detected is not None:
            return bool(self.spec.is_detected(record))
        marker = f"is_{self.spec.module}"
        marker_value = record.extra.get(marker)
        if marker_value is True:
            return True
        if marker_value is False:
            return False
        status = str(record.status or "").strip().lower()
        if not status or status == "fail" or status.startswith(("not_", "unknown")):
            return False
        return True

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
    if cfg.debug and result.detected_count == 0 and hasattr(console, "warn"):
        console.warn(f"all {name} targets are unreachable")
    return 0


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
