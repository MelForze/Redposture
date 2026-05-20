"""Shared runtime helpers for staged audit modules."""

from __future__ import annotations

import os
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from . import audit_models as _audit_models
from .audit_models import StageTrace
from .progress import CommandProgressOwner, NoOpProgress, ProgressHandle
from .scheduler import BoundedScheduler

AuditRecord = _audit_models.AuditRecord
CapabilitySet = _audit_models.CapabilitySet
CredentialAttempt = _audit_models.CredentialAttempt


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


class LineOutputSink:
    """Buffered line sink for stages that must choose one emitted result from many attempts."""

    def __init__(self, output_path: str | None, emit_line: Callable[[str], None]) -> None:
        self.output_path = output_path
        self.emit_line = emit_line
        self.output_written = False

    def emit_many(self, lines: Iterable[str]) -> None:
        buffered = [line for line in lines if line]
        if not buffered:
            return
        if self.output_path:
            os.makedirs(os.path.dirname(self.output_path) or ".", exist_ok=True)
            with open(self.output_path, "a" if self.output_written else "w", encoding="utf-8") as out_fh:
                for line in buffered:
                    out_fh.write(line + "\n")
        else:
            for line in buffered:
                self.emit_line(line)
        self.output_written = True


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
    return owner.start(label, total, enabled=enabled, leave=leave, render_initial=initial)


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


@dataclass(frozen=True)
class TwoPassAuditResult:
    detect_records: dict[int, dict[str, Any]]
    deep_records: dict[int, dict[str, Any]]
    final_records: dict[int, dict[str, Any]]
    detected_count: int
    deep_candidates: list[tuple[int, str]]


@dataclass(frozen=True)
class TwoPassAuditRunner:
    """Shared 2-pass detect/deep executor for staged host audits.

    The runner owns ordered pass-1 emission, stage2 gate debug markers,
    pass-level debug markers, optional command progress advancing, and
    detect/deep record merging. Module code supplies protocol-specific hooks.
    """

    label: str
    workers: int
    debug_emit: Callable[[str], None] | None = None
    progress: ProgressHandle | None = None
    detected_name: str = "detected"

    def run(
        self,
        indexed_hosts: list[tuple[int, str]],
        *,
        detect_task: Callable[[str], dict[str, Any]],
        deep_task: Callable[[str], dict[str, Any]],
        is_detected: Callable[[dict[str, Any]], bool],
        deep_gate: Callable[[dict[str, Any]], tuple[bool, str]],
        emit_detect: Callable[[dict[str, Any]], None] | None = None,
        merge_records: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]] = merge_stage_records,
        not_detected_reason: str = "not_detected",
    ) -> TwoPassAuditResult:
        detect_records: dict[int, dict[str, Any]] = {}
        deep_records: dict[int, dict[str, Any]] = {}
        final_records: dict[int, dict[str, Any]] = {}

        if self.debug_emit is not None:
            self.debug_emit(format_pass_marker(1, "detect", "start", total=len(indexed_hosts)))

        scheduler: BoundedScheduler[tuple[int, str], dict[str, Any]] = BoundedScheduler(
            max_workers=max(1, int(self.workers))
        )
        buffered_records: dict[int, dict[str, Any]] = {}
        gate_decisions: dict[int, tuple[bool, str]] = {}
        detected_flags: dict[int, bool] = {}
        next_emit_idx = 0
        for (record_idx, _host), detect_record in scheduler.iter_completed(
            indexed_hosts,
            lambda item: detect_task(item[1]),
        ):
            record_idx = int(record_idx)
            buffered_records[record_idx] = detect_record
            detected = is_detected(detect_record)
            detected_flags[record_idx] = detected
            if detected:
                should_run, reason = deep_gate(detect_record)
                gate_decisions[record_idx] = (should_run, reason)
                if should_run and self.progress is not None:
                    self.progress.add_total(1)
            if self.progress is not None:
                self.progress.advance()
            while next_emit_idx in buffered_records:
                ready_record = buffered_records.pop(next_emit_idx)
                detect_records[next_emit_idx] = ready_record
                if emit_detect is not None:
                    emit_detect(ready_record)
                next_emit_idx += 1

        detected_count = 0
        deep_candidates: list[tuple[int, str]] = []
        for idx, host in indexed_hosts:
            detect_record = detect_records[idx]
            if not detected_flags.get(idx, False):
                if self.debug_emit is not None:
                    self.debug_emit(
                        format_stage2_gate(
                            host,
                            int(detect_record.get("port") or 0),
                            "skip",
                            not_detected_reason,
                        )
                    )
                continue
            detected_count += 1
            should_run, reason = gate_decisions.get(idx, (False, "gate_not_evaluated"))
            if should_run:
                deep_candidates.append((idx, host))
                if self.debug_emit is not None:
                    self.debug_emit(format_stage2_gate(host, int(detect_record.get("port") or 0), "run", reason))
            elif self.debug_emit is not None:
                self.debug_emit(format_stage2_gate(host, int(detect_record.get("port") or 0), "skip", reason))

        if self.debug_emit is not None:
            self.debug_emit(
                format_pass_marker(
                    1,
                    "detect",
                    "complete",
                    **{self.detected_name: detected_count, "deep_candidates": len(deep_candidates)},
                )
            )
            self.debug_emit(format_pass_marker(2, "deep", "start", total=len(deep_candidates)))

        if deep_candidates:
            for (record_idx, _host), deep_record in scheduler.iter_completed(
                deep_candidates,
                lambda item: deep_task(item[1]),
            ):
                deep_records[int(record_idx)] = deep_record
                if self.progress is not None:
                    self.progress.advance()

        if self.debug_emit is not None:
            self.debug_emit(format_pass_marker(2, "deep", "complete", processed=len(deep_records)))

        for idx, _host in indexed_hosts:
            detect_record = detect_records[idx]
            deep_record = deep_records.get(idx)
            final_records[idx] = merge_records(detect_record, deep_record) if deep_record else detect_record

        return TwoPassAuditResult(
            detect_records=detect_records,
            deep_records=deep_records,
            final_records=final_records,
            detected_count=detected_count,
            deep_candidates=deep_candidates,
        )


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
        record["stage_timing_total_ms"] = int(max(0, total_ms))
        return record
