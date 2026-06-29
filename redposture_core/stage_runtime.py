"""Shared runtime helpers for staged audit modules."""

from __future__ import annotations

import functools
import inspect
import json
import os
import sys
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

from . import audit_models as _audit_models
from .audit_config import AuditConfig
from .audit_models import StageTrace
from .progress import CommandProgressOwner, NoOpProgress, ProgressHandle
from .scheduler import BoundedScheduler
from .show_limits import dump_flag_enabled, dump_flag_limit, show_flag_enabled, show_flag_limit
from .targeting import (
    DEFAULT_MAX_NETWORK_HOSTS,
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
)

AuditRecord = _audit_models.AuditRecord
CapabilitySet = _audit_models.CapabilitySet
CredentialAttempt = _audit_models.CredentialAttempt
_RUNTIME_COMPAT_EXPORTS = (collect_scan_targets, collect_scan_target_specs)
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
    """Buffered line sink for stages that must choose one emitted result from many attempts."""

    def __init__(self, output_path: str | None, emit_line: Callable[[str], None], *, append: bool = False) -> None:
        self.output_path = output_path
        self.emit_line = emit_line
        self.output_written = bool(append)
        self._handle: Any = None

    def emit_many(self, lines: Iterable[str]) -> None:
        buffered = [line for line in lines if line]
        if not buffered:
            return
        if self.output_path:
            if self._handle is None:
                # Open once and keep the handle: render emits per record, so a
                # per-call open/close would re-open the file for every finding.
                os.makedirs(os.path.dirname(self.output_path) or ".", exist_ok=True)
                self._handle = open(self.output_path, "a" if self.output_written else "w", encoding="utf-8")
            for line in buffered:
                self._handle.write(line + "\n")
            self._handle.flush()
        # Always echo to the console as well: `-o`/`--save` now tees (file + console)
        # instead of suppressing stdout. The colorizer in `emit_line` applies to the
        # console copy; the file copy stays plain (written directly above).
        for line in buffered:
            self.emit_line(line)
        self.output_written = True

    def close(self) -> None:
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
    # Modules normally supply only `host_stage` (their real host audit function);
    # the runner drives the detect/auth/data lifecycle generically. The per-phase
    # callables below are optional overrides for custom modules and tests.
    host_stage: Callable[..., AuditRecord | dict[str, Any]] | None = None
    detect: Callable[[AuditHookContext], AuditRecord] | None = None
    auth: Callable[[AuditHookContext, AuditRecord], AuditRecord] | None = None
    capabilities: Callable[[AuditHookContext, AuditRecord], AuditRecord] | None = None
    data: Callable[[AuditHookContext, AuditRecord], AuditRecord] | None = None
    # Output: either an explicit `render` callable, or a `render_module` whose
    # `_format_*` functions the runner introspects (via `render_record_with_module`).
    # `colorize` is the module's explicit `_render_colored_*_line` hook; the runner
    # applies it to stdout (no `__all__` name-magic in the call site).
    render: Callable[[AuditRecord], Iterable[str]] | None = None
    render_module: Any = None
    colorize: Callable[[Any, str], bool] | None = None
    is_detected: Callable[[AuditRecord], bool] | None = None
    deep_gate: Callable[[AuditRecord], tuple[bool, str]] | None = None


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

    @property
    def target_count(self) -> int:
        if self.target_plan is not None:
            return self.target_plan.count_for_ports(self.ports)
        if self.target_specs_by_port:
            return sum(len(specs) for specs in self.target_specs_by_port.values())
        return sum(len(hosts) for hosts in self.targets_by_port.values())

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
    try:
        ports = collect_scan_ports(getattr(args, "ports", None))
    except ValueError as exc:
        raise ValueError(f"failed to parse --port: {exc}") from exc
    if not ports:
        port_value = getattr(args, "port", None)
        if port_value is None and default_ports is not None:
            ports = [int(port) for port in default_ports]
        else:
            ports = [int(port_value if port_value is not None else default_port)]

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

    credential_runs = build_basic_credential_runs(args)
    port_tuple = tuple(int(port) for port in ports)

    if any(run.source == "file" for run in credential_runs) and target_plan.target_count <= DEFAULT_MAX_NETWORK_HOSTS:
        target_specs = list(target_plan.iter_specs())
        groups = build_scan_execution_groups(target_specs, ports)
        targets_by_port: dict[int, tuple[str, ...]] = {}
        target_specs_by_port: dict[int, tuple[ScanTargetSpec, ...]] = {}
        for group in groups:
            port = int(group.port)
            group_hosts = [str(host) for host in group.hosts]
            group_hosts = filter_open_tcp_hosts_for_credential_file(
                group_hosts,
                port,
                timeout=cfg.timeout,
                workers=cfg.workers,
                enabled=not cfg.proxy,
            )
            targets_by_port[port] = (*targets_by_port.get(port, ()), *group_hosts)
            group_specs = tuple(getattr(group, "target_specs", ()) or ())
            if group_specs:
                group_host_set = set(group_hosts)
                filtered_specs = tuple(spec for spec in group_specs if str(spec.host) in group_host_set)
                target_specs_by_port[port] = (*target_specs_by_port.get(port, ()), *filtered_specs)

        return AuditCommandPlan(
            targets_by_port=targets_by_port,
            target_specs_by_port=target_specs_by_port,
            ports=port_tuple,
            credential_runs=credential_runs,
            output_path=cfg.output,
            output_format=cfg.output_format,
            workers=cfg.workers,
        )

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


def _invoke_host_stage(
    func: Callable[..., Any],
    *,
    module: str,
    ctx: AuditHookContext,
    run_deep_checks: bool | None = None,
) -> AuditRecord:
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
        )
    cfg = AuditConfig.from_namespace(ctx.args)
    positional: list[Any] = []
    keyword: dict[str, Any] = {}
    for name, parameter in signature.parameters.items():
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
    for name in getattr(render_module, "__all__", ()):
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
        lines.append(str(plan.summary(record_payload, output_format)))
    for func, takes_debug in plan.details:
        try:
            rendered = (
                func(record_payload, output_format, debug=debug) if takes_debug else func(record_payload, output_format)
            )
        except TypeError:
            continue
        if rendered:
            lines.extend(str(line) for line in rendered if line)
    return [line for line in lines if line]


def render_record_with_module(
    render_module: Any, record: AuditRecord, output_format: str, *, debug: bool = False
) -> list[str]:
    return render_with_plan(build_render_plan(render_module), record.to_dict(), output_format, debug=debug)


def _record_looks_detected(record: dict[str, Any]) -> bool:
    if any(bool(value) for key, value in record.items() if key.startswith("is_")):
        return True
    status = str(record.get("status") or "")
    return status not in {"fail", "not_detected", "not_found", "not_service"}


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
    if name in {"target_path", "url_path", "path"} and ctx.target is not None and ctx.target.path:
        return ctx.target.path
    if name in {"target_query", "url_query", "query_string"} and ctx.target is not None and ctx.target.query:
        return ctx.target.query
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
        return credential.username if credential.username is not None else cfg.username
    if name == "password":
        return credential.password if credential.username is not None else cfg.password
    if name in {"token", "api_token"}:
        return credential.token or getattr(args, name, None) or getattr(args, "token", None)
    if name == "defcreds":
        return cfg.defcreds and credential.source != "file"
    if name == "run_deep_checks":
        return bool(ctx.run_deep_checks)
    if name == "debug":
        return cfg.debug
    if name == "debug_emit":
        return ctx.debug_emit
    if name == "proxy":
        # `cli.py` parses --proxy once into `args._proxy_config` (a ProxyConfig).
        # Hand that parsed object through so clients reuse it instead of
        # re-parsing the raw string. Bare test args fall back to the raw value.
        if hasattr(args, "_proxy_config"):
            return args._proxy_config
        return getattr(args, "proxy", None)
    if name == "max_messages":
        raw_max_messages = getattr(args, "max_messages", None)
        if raw_max_messages is not None:
            return int(raw_max_messages)
        dump_limit = dump_flag_limit(getattr(args, "dump", None))
        if dump_limit is not None:
            return int(dump_limit)
        return 10
    if name == "credential_candidates":
        if credential.username is not None:
            return [
                {"username": credential.username, "password": credential.password or "", "source": credential.source}
            ]
        builder = getattr(args, "_credential_candidates", None)
        if builder is not None:
            return builder
        public_candidates = getattr(args, "credential_candidates", None)
        if public_candidates is not None:
            return public_candidates
        username = getattr(args, "username", None)
        password = getattr(args, "password", None)
        if username:
            return [{"username": username, "password": password or "", "source": "provided"}]
        return []
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

    def run_plan(self, plan: AuditCommandPlan) -> AuditCommandResult:
        target_count = plan.target_count
        retain_records = target_count <= DEFAULT_RECORD_RETENTION_LIMIT
        progress = start_command_progress(
            self.args,
            self.spec.label,
            target_count,
            enabled=should_use_global_progress(plan.output_format, target_count),
            leave=False,
        )
        sink = LineOutputSink(plan.output_path, self.emit_line, append=plan.append)
        worker_count = max(1, int(plan.workers or getattr(self.args, "workers", 1) or 1))
        scheduler: BoundedScheduler[tuple[int, str, int, ScanTargetSpec | None], AuditRecord] = BoundedScheduler(
            max_workers=worker_count
        )
        deep_scheduler: BoundedScheduler[tuple[int, str, int, ScanTargetSpec | None, AuditRecord], AuditRecord] = (
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
        debug_emit = getattr(self.args, "debug_emit", None) if bool(getattr(self.args, "debug", False)) else None
        if debug_emit is not None:
            debug_emit(format_pass_marker(1, "detect", "start", total=target_count))

        def _emit_record(record: AuditRecord) -> None:
            nonlocal emitted_lines, suppressed_records
            if plan.output_format == "json":
                emitted_lines += 1
                sink.emit_many((json.dumps(record.to_dict(), ensure_ascii=False),))
                return
            if self.spec.render is None and self.spec.render_module is None:
                return
            if not debug and is_pre_detect_network_noise(record):
                suppressed_records += 1
                return
            lines = self._render_record(record, render_plan, plan.output_format, debug)
            emitted_lines += len(lines)
            sink.emit_many(lines)

        def _finalize_record(record: AuditRecord) -> None:
            nonlocal record_count, detected_count
            record_count += 1
            status = str(record.status or "")
            status_counts[status] = status_counts.get(status, 0) + 1
            if self._is_detected(record):
                detected_count += 1
            if retain_records:
                retained_records.append(record)
            if record_callbacks:
                payload = record.to_dict()
                for record_callback in record_callbacks:
                    record_callback(dict(payload))
            _emit_record(record)

        total_detected = 0
        total_deep_candidates = 0
        processed_deep = 0
        window_index = 0
        try:
            for window in plan.iter_target_windows():
                window_index += 1
                pending_emit_records: dict[int, AuditRecord] = {}
                next_emit_idx = int(window[0][0]) if window else 0
                detected_targets: list[tuple[int, str, int, ScanTargetSpec | None, AuditRecord]] = []

                def _queue_final_record(
                    idx: int,
                    record: AuditRecord,
                    pending_emit_records=pending_emit_records,
                ) -> None:
                    nonlocal next_emit_idx
                    pending_emit_records[int(idx)] = record
                    while next_emit_idx in pending_emit_records:
                        ready_record = pending_emit_records.pop(next_emit_idx)
                        _finalize_record(ready_record)
                        next_emit_idx += 1

                for (idx, host, port, target), detect_record in scheduler.iter_completed(
                    window,
                    lambda item: self._safe_record(
                        item[1], item[2], lambda: self._run_detect(item[1], item[2], item[3], debug_emit)
                    ),
                ):
                    if self._is_detected(detect_record):
                        detected_targets.append((idx, host, port, target, detect_record))
                    else:
                        if debug_emit is not None:
                            debug_emit(
                                format_stage2_gate(host, int(port), "skip", self._not_detected_reason(detect_record))
                            )
                        _queue_final_record(int(idx), detect_record)
                    progress.advance(1)

                initial_deep_candidates = [
                    (idx, host, port, target, detect_record)
                    for idx, host, port, target, detect_record in detected_targets
                    if self._deep_gate(detect_record)[0]
                ]
                total_detected += len(detected_targets)
                total_deep_candidates += len(initial_deep_candidates)
                if debug_emit is not None:
                    if target_count <= len(window):
                        debug_emit(
                            format_pass_marker(
                                1,
                                "detect",
                                "complete",
                                detected=len(detected_targets),
                                deep_candidates=len(initial_deep_candidates),
                            )
                        )
                        debug_emit(format_pass_marker(2, "deep", "start", total=len(initial_deep_candidates)))
                    else:
                        debug_emit(
                            format_pass_marker(
                                1,
                                "detect",
                                "window_complete",
                                window=window_index,
                                detected=len(detected_targets),
                                deep_candidates=len(initial_deep_candidates),
                            )
                        )
                        debug_emit(
                            format_pass_marker(
                                2,
                                "deep",
                                "window_start",
                                window=window_index,
                                total=len(initial_deep_candidates),
                            )
                        )

                if detected_targets:
                    progress.add_total(len(detected_targets))
                for (idx, _host, _port, _target, _detect_record), final_record in deep_scheduler.iter_completed(
                    detected_targets,
                    lambda item: self._safe_record(
                        item[1],
                        item[2],
                        lambda: self._run_deep_lifecycle(
                            item[1], item[2], item[3], item[4], plan.credential_runs, debug_emit
                        ),
                    ),
                ):
                    _queue_final_record(int(idx), final_record)
                    processed_deep += int(self._deep_gate(final_record)[0])
                    progress.advance(1)

                if pending_emit_records:
                    for idx, _host, _port, _target in window:
                        if idx in pending_emit_records:
                            _finalize_record(pending_emit_records.pop(idx))
        finally:
            progress.close()
        if debug_emit is not None:
            if window_index > 1:
                debug_emit(
                    format_pass_marker(
                        1,
                        "detect",
                        "complete",
                        detected=total_detected,
                        deep_candidates=total_deep_candidates,
                    )
                )
            debug_emit(format_pass_marker(2, "deep", "complete", processed=processed_deep))

        try:
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
        finally:
            sink.close()

    def _ctx(
        self,
        host: str,
        port: int,
        target: ScanTargetSpec | None,
        credential: AuditCredentialRun,
        *,
        run_deep_checks: bool,
        debug_emit: Callable[[str], None] | None,
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
        )

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
            run_deep_checks=False,
            debug_emit=debug_emit,
        )
        return self._detect(ctx)

    def _run_deep_lifecycle(
        self,
        host: str,
        port: int,
        target: ScanTargetSpec | None,
        detect_record: AuditRecord,
        credential_runs: tuple[AuditCredentialRun, ...],
        debug_emit: Callable[[str], None] | None,
    ) -> AuditRecord:
        auth_records: list[tuple[AuditCredentialRun, AuditRecord]] = []
        candidates = credential_runs or (AuditCredentialRun(source="anonymous"),)
        if self._should_keep_anonymous_detect_record(detect_record):
            selected_credential = AuditCredentialRun(source="anonymous")
            selected_record = detect_record
            gate_reason = "status=open_no_auth"
        else:
            for credential in candidates:
                ctx = self._ctx(host, port, target, credential, run_deep_checks=False, debug_emit=debug_emit)
                auth_records.append((credential, self._auth(ctx, detect_record)))
            selected_credential, selected_record, gate_reason = self._select_deep_record(detect_record, auth_records)
        gate = self._deep_gate(selected_record)
        if not gate[0]:
            # No credential gated (all attempts failed). Record every attempted credential
            # so renderers can surface all of them instead of only the last-tried one.
            # Generic + harmless: modules whose renderers ignore this key are unaffected.
            if len(auth_records) > 1:
                selected_record.extra["attempted_credentials"] = [
                    {
                        "username": cred.username,
                        "password": cred.password,
                        "source": cred.source,
                        "status": str(rec.status),
                    }
                    for cred, rec in auth_records
                ]
            if debug_emit is not None:
                debug_emit(format_stage2_gate(host, int(port), "skip", gate[1] or gate_reason))
            return selected_record
        if debug_emit is not None:
            debug_emit(format_stage2_gate(host, int(port), "run", gate[1] or gate_reason))

        deep_ctx = self._ctx(host, port, target, selected_credential, run_deep_checks=True, debug_emit=debug_emit)
        record = self._capabilities(deep_ctx, selected_record)
        record = self._data(deep_ctx, record)
        return record

    def _should_keep_anonymous_detect_record(self, detect_record: AuditRecord) -> bool:
        return (
            self.spec.module == "kafka"
            and bool(getattr(self.args, "defcreds", False))
            and str(detect_record.status or "") == "open_no_auth"
        )

    def _safe_record(self, host: str, port: int, task: Callable[[], AuditRecord]) -> AuditRecord:
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
            return AuditRecord(
                host=str(host),
                port=int(port),
                module=self.spec.module,
                service=self.spec.module,
                status="fail",
                extra={"error": message},
            )

    def _host_stage(self, ctx: AuditHookContext, *, run_deep_checks: bool) -> AuditRecord:
        if self.spec.host_stage is None:
            raise TypeError(f"{self.spec.module} spec exposes neither hook overrides nor host_stage")
        return _invoke_host_stage(
            self.spec.host_stage, module=self.spec.module, ctx=ctx, run_deep_checks=run_deep_checks
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
            gate = self._deep_gate(record)
            if gate[0]:
                return credential, record, gate[1]
        if auth_records:
            return auth_records[-1][0], auth_records[-1][1], "no accepted credentials"
        return AuditCredentialRun(source="anonymous"), detect_record, "no credentials"

    def _is_detected(self, record: AuditRecord) -> bool:
        if self.spec.is_detected is not None:
            return bool(self.spec.is_detected(record))
        marker = f"is_{self.spec.module}"
        if record.extra.get(marker) is False:
            return False
        status = str(record.status or "")
        return status not in {"not_detected", "not_found", "not_service", f"not_{self.spec.module}"}

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
            "weak_default_creds",
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
    runner = AuditCommandRunner(args=args, spec=build_spec(args), logger=logger, console=console)
    try:
        result = runner.run_plan(plan)
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
