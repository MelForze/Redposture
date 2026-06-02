"""Shared runtime helpers for staged audit modules."""

from __future__ import annotations

import inspect
import json
import os
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from . import audit_models as _audit_models
from .audit_models import StageTrace
from .progress import CommandProgressOwner, NoOpProgress, ProgressHandle
from .scheduler import BoundedScheduler
from .show_limits import dump_flag_enabled, dump_flag_limit, show_flag_enabled, show_flag_limit
from .targeting import (
    ScanTargetSpec,
    TargetParsePolicy,
    build_scan_execution_groups,
    collect_scan_target_specs,
    parse_scan_target_specs,
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

    def __init__(self, output_path: str | None, emit_line: Callable[[str], None], *, append: bool = False) -> None:
        self.output_path = output_path
        self.emit_line = emit_line
        self.output_written = bool(append)

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
    detect: Callable[[str, int], AuditRecord]
    detect_context: Callable[[AuditHookContext], AuditRecord] | None = None
    auth: Callable[[AuditRecord], AuditRecord] | None = None
    capabilities: Callable[[AuditRecord], AuditRecord] | None = None
    data: Callable[[AuditRecord], AuditRecord] | None = None
    render: Callable[[dict[str, Any]], Iterable[str]] | None = None
    is_detected: Callable[[dict[str, Any]], bool] | None = None
    deep_gate: Callable[[dict[str, Any]], tuple[bool, str]] | None = None


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

    targets_by_port: dict[int, tuple[str, ...]]
    target_specs_by_port: dict[int, tuple[ScanTargetSpec, ...]] = field(default_factory=dict)
    credential_runs: tuple[AuditCredentialRun, ...] = (AuditCredentialRun(),)
    output_path: str | None = None
    output_format: str = "txt"
    workers: int = 1
    append: bool = False

    @property
    def target_count(self) -> int:
        if self.target_specs_by_port:
            return sum(len(specs) for specs in self.target_specs_by_port.values())
        return sum(len(hosts) for hosts in self.targets_by_port.values())

    @property
    def credential_run_count(self) -> int:
        return max(1, len(self.credential_runs))

    @property
    def total_work_units(self) -> int:
        return self.target_count * self.credential_run_count

    def iter_targets(self) -> list[tuple[int, str, int]]:
        return [(idx, host, port) for idx, host, port, _target in self.iter_target_specs()]

    def iter_target_specs(self) -> list[tuple[int, str, int, ScanTargetSpec | None]]:
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

    def iter_work_items(self) -> list[tuple[int, str, int, AuditCredentialRun, ScanTargetSpec | None]]:
        items: list[tuple[int, str, int, AuditCredentialRun, ScanTargetSpec | None]] = []
        idx = 0
        credential_runs = self.credential_runs or (AuditCredentialRun(),)
        for _target_idx, host, port, target in self.iter_target_specs():
            for credential in credential_runs:
                items.append((idx, str(host), int(port), credential, target))
                idx += 1
        return items


@dataclass(frozen=True)
class AuditCommandResult:
    records: list[dict[str, Any]]
    detected_count: int
    emitted_lines: int
    typed_records: list[AuditRecord]


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
        target_specs = parse_scan_target_specs(
            targets,
            policy=TargetParsePolicy(url_mode="preserve", path_policy="preserve"),
        )
    except (OSError, ValueError) as exc:
        raise ValueError(f"failed to parse targets: {exc}") from exc
    if not target_specs:
        raise ValueError("targets are required")

    groups = build_scan_execution_groups(target_specs, ports)
    credential_runs = build_basic_credential_runs(args)
    targets_by_port: dict[int, tuple[str, ...]] = {}
    target_specs_by_port: dict[int, tuple[ScanTargetSpec, ...]] = {}
    for group in groups:
        port = int(group.port)
        group_hosts = [str(host) for host in group.hosts]
        if any(run.source == "file" for run in credential_runs):
            group_hosts = filter_open_tcp_hosts_for_credential_file(
                group_hosts,
                port,
                timeout=float(getattr(args, "timeout", 5.0) or 5.0),
                workers=int(getattr(args, "workers", 1) or 1),
                enabled=not bool(getattr(args, "proxy", None)),
            )
        targets_by_port[port] = (*targets_by_port.get(port, ()), *group_hosts)
        group_specs = tuple(getattr(group, "target_specs", ()) or ())
        if group_specs:
            filtered_specs = tuple(spec for spec in group_specs if str(spec.host) in set(group_hosts))
            target_specs_by_port[port] = (*target_specs_by_port.get(port, ()), *filtered_specs)

    return AuditCommandPlan(
        targets_by_port=targets_by_port,
        target_specs_by_port=target_specs_by_port,
        credential_runs=credential_runs,
        output_path=getattr(args, "output", None),
        output_format=str(getattr(args, "output_format", "txt") or "txt"),
        workers=max(1, int(getattr(args, "workers", 1) or 1)),
    )


def build_basic_credential_runs(args: Any) -> tuple[AuditCredentialRun, ...]:
    custom_runs = getattr(args, "_audit_credential_runs", None)
    if custom_runs is not None:
        return tuple(custom_runs)
    username = getattr(args, "username", None)
    password = getattr(args, "password", None)
    token = getattr(args, "token", None) or getattr(args, "api_token", None)
    try:
        credential_file_entries = parse_username_password_credential_file(username, password)
    except ValueError as exc:
        raise ValueError(str(exc)) from exc
    if credential_file_entries is not None:
        return (
            AuditCredentialRun(source="anonymous"),
            *tuple(
                AuditCredentialRun(username=entry.username, password=entry.password, source="file")
                for entry in credential_file_entries
            ),
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
    if dump_value not in (None, False, True):
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
            specs = parse_scan_target_specs(
                str(targets),
                policy=TargetParsePolicy(url_mode="preserve", path_policy="preserve"),
            )
        except ValueError as exc:
            console.error(f"failed to parse targets: {exc}")
            return 2
        if any(str(spec.scheme or "").lower() == "https" for spec in specs):
            console.error(f"{module} accepts only http:// URL targets for -t/--targets")
            return 2

    return None


def invoke_action_hook_from_args(
    actions_module: Any,
    *,
    module: str,
    ctx: AuditHookContext,
) -> AuditRecord:
    func = _select_host_action(actions_module, module)
    signature = inspect.signature(func)
    positional: list[Any] = []
    keyword: dict[str, Any] = {}
    for name, parameter in signature.parameters.items():
        value = _argument_value_for_hook(name, ctx)
        if parameter.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD):
            positional.append(value)
        elif parameter.kind is inspect.Parameter.KEYWORD_ONLY:
            keyword[name] = value
        elif parameter.kind is inspect.Parameter.VAR_POSITIONAL:
            positional.extend(
                [
                    ctx.host,
                    int(ctx.port),
                    float(getattr(ctx.args, "timeout", 5.0) or 5.0),
                    int(getattr(ctx.args, "retries", 0) or 0),
                ]
            )
        elif parameter.kind is inspect.Parameter.VAR_KEYWORD:
            continue
    payload = func(*positional, **keyword)
    if isinstance(payload, AuditRecord):
        return payload
    if isinstance(payload, dict):
        return AuditRecord.from_mapping(payload, module=module, service=module)
    raise TypeError(f"{module} host hook must return AuditRecord or dict payload")


def _select_host_action(actions_module: Any, module: str) -> Callable[..., Any]:
    candidates = (
        f"_call_audit_{module}_host_with_stage_debug",
        f"_call_audit_{module}_host_with_thread_debug",
        f"_audit_{module}_host_stage",
        "_call_audit_host_with_thread_debug",
        f"_audit_{module}_host",
    )
    for name in candidates:
        func = getattr(actions_module, name, None)
        if callable(func):
            return func
    raise AttributeError(f"{module} actions module does not expose a host audit hook")


def render_record_with_module(
    render_module: Any, record: dict[str, Any], output_format: str, *, debug: bool = False
) -> list[str]:
    lines: list[str] = []
    detect = getattr(render_module, "_format_detect_record", None) or getattr(render_module, "_detect_line", None)
    if callable(detect) and _record_looks_detected(record):
        try:
            lines.append(str(detect(record, output_format)))
        except TypeError:
            pass
    summary = getattr(render_module, "_format_record", None)
    if callable(summary):
        lines.append(str(summary(record, output_format)))
    for name in getattr(render_module, "__all__", ()):
        if name in {"_format_detect_record", "_format_record", "_detect_line"}:
            continue
        if not (name.startswith("_format") and (name.endswith("_records") or name.endswith("_lines"))):
            continue
        func = getattr(render_module, name, None)
        if not callable(func) or not _can_call_detail_renderer(func):
            continue
        try:
            if "debug" in inspect.signature(func).parameters:
                rendered = func(record, output_format, debug=debug)
            else:
                rendered = func(record, output_format)
        except TypeError:
            continue
        if rendered:
            lines.extend(str(line) for line in rendered if line)
    return [line for line in lines if line]


def _record_looks_detected(record: dict[str, Any]) -> bool:
    if any(bool(value) for key, value in record.items() if key.startswith("is_")):
        return True
    status = str(record.get("status") or "")
    return status not in {"fail", "not_detected", "not_found", "not_service"}


def _can_call_detail_renderer(func: Callable[..., Any]) -> bool:
    signature = inspect.signature(func)
    required = [
        name
        for name, parameter in signature.parameters.items()
        if parameter.default is inspect.Parameter.empty
        and parameter.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]
    return len(required) <= 2


def _argument_value_for_hook(name: str, ctx: AuditHookContext) -> Any:
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
        return float(getattr(args, "timeout", 5.0) or 5.0)
    if name == "retries":
        return int(getattr(args, "retries", 0) or 0)
    if name == "workers":
        return int(getattr(args, "workers", 1) or 1)
    if name == "username":
        return credential.username if credential.username is not None else getattr(args, "username", None)
    if name == "password":
        return credential.password if credential.username is not None else getattr(args, "password", None)
    if name in {"token", "api_token"}:
        return credential.token or getattr(args, name, None) or getattr(args, "token", None)
    if name == "defcreds":
        return bool(getattr(args, "defcreds", False)) and credential.source != "file"
    if name == "run_deep_checks":
        return bool(ctx.run_deep_checks)
    if name == "debug":
        return bool(getattr(args, "debug", False))
    if name == "debug_emit":
        return ctx.debug_emit
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
        "proxy": "proxy",
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
    return None


class AuditCommandRunner:
    """Command-level runner for staged modules.

    The runner owns the parts that previously drifted across stage modules:
    ordered target execution, command progress, output sink and record counting.
    Main hooks return `AuditRecord`; dict conversion is kept outside this runner
    path in explicit compatibility wrappers.
    """

    def __init__(
        self,
        *,
        args: Any,
        spec: ModuleAuditSpec,
        logger: Any = None,
        emit_line: Callable[[str], None] | None = None,
    ) -> None:
        self.args = args
        self.spec = spec
        self.logger = logger
        self.emit_line = emit_line or print

    def run_hosts(
        self,
        hosts: list[str],
        *,
        port: int | None = None,
        workers: int | None = None,
        output_path: str | None = None,
        output_format: str = "txt",
    ) -> AuditCommandResult:
        active_port = int(port if port is not None else self.spec.default_port)
        indexed_hosts = list(enumerate(hosts))
        progress = start_command_progress(
            self.args,
            self.spec.label,
            len(indexed_hosts),
            enabled=should_use_global_progress(output_format, len(indexed_hosts)),
        )
        sink = LineOutputSink(output_path, self.emit_line)
        records_by_idx: dict[int, AuditRecord] = {}
        scheduler: BoundedScheduler[tuple[int, str], AuditRecord] = BoundedScheduler(
            max_workers=max(1, int(workers or getattr(self.args, "workers", 1) or 1))
        )
        emitted_lines = 0
        try:
            for (idx, _host), raw_record in scheduler.iter_completed(
                indexed_hosts,
                lambda item: self._run_one(item[1], active_port),
            ):
                records_by_idx[int(idx)] = raw_record
                progress.advance()
        finally:
            progress.close()

        typed_records = [records_by_idx[idx] for idx, _host in indexed_hosts if idx in records_by_idx]
        records = [record.to_dict() for record in typed_records]
        if output_format == "txt" and self.spec.render is not None:
            for record in records:
                lines = list(self.spec.render(record))
                emitted_lines += len(lines)
                sink.emit_many(lines)
        return AuditCommandResult(
            records=records,
            detected_count=sum(1 for record in records if self._is_detected(record)),
            emitted_lines=emitted_lines,
            typed_records=typed_records,
        )

    def run_plan(self, plan: AuditCommandPlan) -> AuditCommandResult:
        indexed_targets = plan.iter_work_items()
        progress = start_command_progress(
            self.args,
            self.spec.label,
            len(indexed_targets),
            enabled=should_use_global_progress(plan.output_format, len(indexed_targets)),
        )
        sink = LineOutputSink(plan.output_path, self.emit_line, append=plan.append)
        records_by_idx: dict[int, AuditRecord] = {}
        scheduler: BoundedScheduler[
            tuple[int, str, int, AuditCredentialRun, ScanTargetSpec | None],
            AuditRecord,
        ] = BoundedScheduler(max_workers=max(1, int(plan.workers or getattr(self.args, "workers", 1) or 1)))
        emitted_lines = 0
        debug_emit = getattr(self.args, "debug_emit", None) if bool(getattr(self.args, "debug", False)) else None
        if debug_emit is not None:
            debug_emit(format_pass_marker(1, "detect", "start", total=len(indexed_targets)))
        detected_count = 0
        deep_candidates: list[tuple[int, str, int, AuditCredentialRun, ScanTargetSpec | None]] = []
        try:
            for (idx, host, port, credential, target), detect_record in scheduler.iter_completed(
                indexed_targets,
                lambda item: self._run_detect_context(item[1], item[2], item[3], item[4], debug_emit),
            ):
                records_by_idx[int(idx)] = detect_record
                payload = detect_record.to_dict()
                detected = self._is_detected(payload)
                detected_count += int(bool(detected))
                gate = (
                    self.spec.deep_gate(payload)
                    if self.spec.deep_gate is not None
                    else self._default_deep_gate(payload)
                )
                if detected and gate[0] and self.spec.detect_context is not None:
                    deep_candidates.append((idx, host, port, credential, target))
                    if debug_emit is not None:
                        debug_emit(format_stage2_gate(host, int(port), "run", gate[1]))
                elif debug_emit is not None:
                    reason = gate[1] if detected else self._not_detected_reason(payload)
                    debug_emit(format_stage2_gate(host, int(port), "skip", reason))
                progress.advance(1)

            if debug_emit is not None:
                debug_emit(
                    format_pass_marker(
                        1,
                        "detect",
                        "complete",
                        detected=detected_count,
                        deep_candidates=len(deep_candidates),
                    )
                )
                debug_emit(format_pass_marker(2, "deep", "start", total=len(deep_candidates)))
            if deep_candidates:
                progress.add_total(len(deep_candidates))
            for (idx, _host, _port, _credential, _target), deep_record in scheduler.iter_completed(
                deep_candidates,
                lambda item: self._run_deep_context(item[1], item[2], item[3], item[4], debug_emit),
            ):
                records_by_idx[int(idx)] = deep_record
                progress.advance(1)
        finally:
            progress.close()
        if debug_emit is not None:
            debug_emit(format_pass_marker(2, "deep", "complete", processed=len(deep_candidates)))

        typed_records = [
            records_by_idx[idx] for idx, _host, _port, _credential, _target in indexed_targets if idx in records_by_idx
        ]
        records = [record.to_dict() for record in typed_records]
        if plan.output_format == "json":
            json_lines = [json.dumps(record, ensure_ascii=False) for record in records]
            emitted_lines += len(json_lines)
            sink.emit_many(json_lines)
        elif self.spec.render is not None:
            for record in records:
                lines = list(self.spec.render(record))
                emitted_lines += len(lines)
                sink.emit_many(lines)
        return AuditCommandResult(
            records=records,
            detected_count=sum(1 for record in records if self._is_detected(record)),
            emitted_lines=emitted_lines,
            typed_records=typed_records,
        )

    def _is_detected(self, record: dict[str, Any]) -> bool:
        if self.spec.is_detected is not None:
            return bool(self.spec.is_detected(record))
        marker = f"is_{self.spec.module}"
        if marker in record and record.get(marker) is False:
            return False
        status = str(record.get("status") or "")
        return status not in {"not_detected", "not_found", "not_service", f"not_{self.spec.module}"}

    def _not_detected_reason(self, record: dict[str, Any]) -> str:
        status = str(record.get("status") or "")
        if status.startswith("not_"):
            return status
        marker = f"is_{self.spec.module}"
        if marker in record and record.get(marker) is False:
            return f"not_{self.spec.module}"
        return "not_detected"

    def _default_deep_gate(self, record: dict[str, Any]) -> tuple[bool, str]:
        status = str(record.get("status") or "unknown")
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
        }
        if status in allowed:
            return True, f"status={status}"
        if status.startswith("not_"):
            return False, status
        return False, f"status={status}"

    def _run_one(self, host: str, port: int) -> AuditRecord:
        record_model = _record_to_model(self.spec.detect(host, port))
        record = record_model.to_dict()
        if self.spec.auth is not None:
            record_model = _record_to_model(self.spec.auth(AuditRecord.from_mapping(record, module=self.spec.module)))
            record = record_model.to_dict()
        gate = self.spec.deep_gate(record) if self.spec.deep_gate is not None else self._default_deep_gate(record)
        if gate[0] and self.spec.capabilities is not None:
            record_model = _record_to_model(
                self.spec.capabilities(AuditRecord.from_mapping(record, module=self.spec.module))
            )
            record = record_model.to_dict()
        if gate[0] and self.spec.data is not None:
            record_model = _record_to_model(self.spec.data(AuditRecord.from_mapping(record, module=self.spec.module)))
            record = record_model.to_dict()
        return record_model

    def _run_one_with_context(
        self,
        host: str,
        port: int,
        credential: AuditCredentialRun,
        target: ScanTargetSpec | None = None,
    ) -> AuditRecord:
        record, _detected, _deep_ran = self._run_two_pass_with_context(host, port, credential, target, None)
        return record

    def _run_detect_context(
        self,
        host: str,
        port: int,
        credential: AuditCredentialRun,
        target: ScanTargetSpec | None,
        debug_emit: Callable[[str], None] | None,
    ) -> AuditRecord:
        if self.spec.detect_context is None:
            return self._run_one(host, port)
        detect_ctx = AuditHookContext(
            args=self.args,
            logger=self.logger,
            host=host,
            port=int(port),
            credential=credential,
            target=target,
            run_deep_checks=False,
            debug_emit=debug_emit,
        )
        return _record_to_model(self.spec.detect_context(detect_ctx))

    def _run_deep_context(
        self,
        host: str,
        port: int,
        credential: AuditCredentialRun,
        target: ScanTargetSpec | None,
        debug_emit: Callable[[str], None] | None,
    ) -> AuditRecord:
        if self.spec.detect_context is None:
            return self._run_one(host, port)
        deep_ctx = AuditHookContext(
            args=self.args,
            logger=self.logger,
            host=host,
            port=int(port),
            credential=credential,
            target=target,
            run_deep_checks=True,
            debug_emit=debug_emit,
        )
        return _record_to_model(self.spec.detect_context(deep_ctx))

    def _run_two_pass_with_context(
        self,
        host: str,
        port: int,
        credential: AuditCredentialRun,
        target: ScanTargetSpec | None,
        debug_emit: Callable[[str], None] | None,
    ) -> tuple[AuditRecord, bool, bool]:
        if self.spec.detect_context is None:
            record = self._run_one(host, port)
            payload = record.to_dict()
            return record, self._is_detected(payload), False
        detect_ctx = AuditHookContext(
            args=self.args,
            logger=self.logger,
            host=host,
            port=int(port),
            credential=credential,
            target=target,
            run_deep_checks=False,
            debug_emit=debug_emit,
        )
        detect_record = _record_to_model(self.spec.detect_context(detect_ctx))
        detect_payload = detect_record.to_dict()
        detected = self._is_detected(detect_payload)
        gate = (
            self.spec.deep_gate(detect_payload)
            if self.spec.deep_gate is not None
            else self._default_deep_gate(detect_payload)
        )
        if not detected or not gate[0]:
            if debug_emit is not None:
                reason = "not_detected" if not detected else gate[1]
                debug_emit(format_stage2_gate(host, int(port), "skip", reason))
            return detect_record, detected, False
        if debug_emit is not None:
            debug_emit(format_stage2_gate(host, int(port), "run", gate[1]))
            debug_emit(format_pass_marker(2, "deep", "start", total=1))
        deep_ctx = AuditHookContext(
            args=self.args,
            logger=self.logger,
            host=host,
            port=int(port),
            credential=credential,
            target=target,
            run_deep_checks=True,
            debug_emit=debug_emit,
        )
        return _record_to_model(self.spec.detect_context(deep_ctx)), detected, True


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
