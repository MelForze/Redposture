"""Collect stage."""

from __future__ import annotations

import argparse
import json
import os
import re
import ssl
import sys
import time
from collections.abc import Iterable, Iterator
from typing import Any, TextIO, cast

from .console import Console
from .constants import COLLECT_DEEP_ENDPOINT_TEMPLATES
from .exporters.collect import collect_exporter_debug_data
from .exporters.discover import scan_exporter_presence
from .exporters.http_client import build_exporter_tls_context
from .exporters.output import emit_line as emit_output_line
from .exporters.output import format_collect_record
from .logger import AttemptLogger
from .profiles import default_exporter_ports, load_profiles
from .stage_runtime import progress_total_from_groups, should_use_global_progress, start_command_progress
from .stage_validate import VALIDATION_PRECISION_COLLECT_STRICT, ValidationRecordAccumulator
from .utils import (
    DEFAULT_MAX_NETWORK_HOSTS,
    TargetParsePolicy,
    build_scan_execution_groups,
    collect_scan_ports,
    collect_scan_target_specs,
    stream_scan_target_specs,
    utc_now_iso,
)
from .validate.artifacts import write_vulnerable_targets_files

COLLECT_VALIDATE_INPUT_FORMAT = "auto"
COLLECT_VALIDATE_PRECISION_PROFILE = VALIDATION_PRECISION_COLLECT_STRICT
COLLECT_VALIDATE_SHOW = True
COLLECT_VALIDATE_MAX_LINES = 0
COLLECT_VALIDATE_FAIL_ON_CREDS = False
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _chunk_collect_specs_by_scheme(
    specs: Iterable[Any],
    *,
    size: int = 4096,
) -> Iterator[tuple[str, list[str]]]:
    buckets: dict[str, list[str]] = {}
    seen: dict[str, set[str]] = {}
    for spec in specs:
        scheme = str(getattr(spec, "scheme", None) or "http").lower()
        host = str(spec.host)
        if host in seen.setdefault(scheme, set()):
            continue
        seen[scheme].add(host)
        bucket = buckets.setdefault(scheme, [])
        bucket.append(host)
        if len(bucket) >= size:
            yield scheme, bucket
            buckets[scheme] = []
    for scheme, bucket in buckets.items():
        if bucket:
            yield scheme, bucket


def _collect_transport_kwargs(scheme: str, tls_context: ssl.SSLContext | None) -> dict[str, Any]:
    kwargs: dict[str, Any] = {}
    if scheme != "http":
        kwargs["scheme"] = scheme
    if tls_context is not None:
        kwargs["tls_context"] = tls_context
    return kwargs


def _collect_output_base_dir(args: argparse.Namespace) -> str:
    output_path = str(getattr(args, "output", "") or "").strip()
    if output_path:
        return os.path.dirname(os.path.abspath(output_path)) or "."
    return os.getcwd()


def _write_vulnerable_targets_files(
    *,
    args: argparse.Namespace,
    validator: ValidationRecordAccumulator,
    console: Console,
) -> None:
    if not str(getattr(args, "output", "") or "").strip():
        return
    write_vulnerable_targets_files(
        base_dir=_collect_output_base_dir(args),
        validator=validator,
        debug=console.debug if bool(getattr(args, "debug", False)) else None,
    )


def _resolve_collect_checkpoint_path(args: argparse.Namespace) -> str:
    explicit = str(getattr(args, "checkpoint_file", "") or "").strip()
    if explicit:
        return explicit
    output_path = str(getattr(args, "output", "") or "").strip()
    if output_path:
        return f"{output_path}.checkpoint.jsonl"
    save_dir = str(getattr(args, "save_responses_dir", "") or "").strip()
    if save_dir:
        return os.path.join(save_dir, "collect.checkpoint.jsonl")
    return ".redposture_collect.checkpoint.jsonl"


def _load_collect_checkpoint_state(
    path: str,
    *,
    console: Console | None = None,
) -> dict[tuple[str, str, int, str], dict[str, Any]]:
    """Load the latest durable state for each collect job.

    JSONL can contain several attempts for a job.  Last-write-wins is
    intentional here: a later successful retry supersedes an earlier failure,
    while a failed/latest attempt must remain retryable.
    """

    state: dict[tuple[str, str, int, str], dict[str, Any]] = {}
    if not path or not os.path.exists(path):
        return state
    try:
        with open(path, encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(payload, dict):
                    continue
                host = str(payload.get("host") or "").strip()
                exporter = str(payload.get("exporter") or "").strip()
                endpoint = str(payload.get("endpoint") or "").strip()
                try:
                    port = int(payload.get("port", ""))
                except (TypeError, ValueError):
                    continue
                if not host or not exporter or not endpoint or port <= 0:
                    continue
                state[(host, exporter, port, endpoint)] = payload
    except OSError as exc:
        if console is not None:
            console.warn(f"failed to load collect checkpoint '{path}': {exc}")
    return state


def _load_collect_completed_jobs(path: str, *, console: Console | None = None) -> set[tuple[str, str, int, str]]:
    state = _load_collect_checkpoint_state(path, console=console)
    # Only an explicitly successful terminal result is safe to skip.  Legacy
    # rows without `ok` and all failed/transport-error rows are retried.
    return {key for key, payload in state.items() if payload.get("ok") is True}


def _materialize_collect_endpoint(template: str, pprof_seconds: int, trace_seconds: int) -> str:
    return (
        str(template)
        .replace("{pprof_seconds}", str(pprof_seconds))
        .replace("{trace_seconds}", str(trace_seconds))
        .strip()
    )


def _build_collect_endpoints(
    base_endpoints: list[str] | tuple[str, ...],
    *,
    deep: bool,
    pprof_seconds: int,
    trace_seconds: int,
) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = set()

    for endpoint in base_endpoints:
        rendered = _materialize_collect_endpoint(endpoint, pprof_seconds, trace_seconds)
        if not rendered or not rendered.startswith("/") or rendered in seen:
            continue
        seen.add(rendered)
        result.append(rendered)

    if deep:
        for template in COLLECT_DEEP_ENDPOINT_TEMPLATES:
            rendered = _materialize_collect_endpoint(template, pprof_seconds, trace_seconds)
            if not rendered or rendered in seen:
                continue
            seen.add(rendered)
            result.append(rendered)

    return tuple(result)


def _normalize_collect_exporter_token(value: str) -> str:
    return str(value).strip().lower().replace("-", "_")


def _collect_exporter_alias_map(
    collect_exporters: list[dict[str, Any]] | tuple[dict[str, Any], ...],
) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for exporter in collect_exporters:
        canonical = _normalize_collect_exporter_token(str(exporter.get("name") or ""))
        if not canonical:
            continue
        aliases[canonical] = canonical
        if canonical.endswith("_exporter"):
            short = canonical[: -len("_exporter")]
            if short:
                aliases.setdefault(short, canonical)
    return aliases


def _parse_collect_exporter_filter(
    raw: str | None,
    collect_exporters: list[dict[str, Any]] | tuple[dict[str, Any], ...],
) -> set[str]:
    if raw is None:
        return set()
    alias_map = _collect_exporter_alias_map(collect_exporters)
    selected: set[str] = set()
    unknown: set[str] = set()
    for part in str(raw).split(","):
        token = _normalize_collect_exporter_token(part)
        if not token:
            continue
        mapped = alias_map.get(token)
        if mapped is None:
            unknown.add(token)
            continue
        selected.add(mapped)
    if unknown:
        supported_short = sorted(
            {name[: -len("_exporter")] if name.endswith("_exporter") else name for name in alias_map.values()}
        )
        raise ValueError(
            "unsupported collect exporters: "
            + ", ".join(sorted(unknown))
            + " (supported: "
            + ",".join(supported_short)
            + ")"
        )
    return selected


def _filter_collect_exporter_profiles(
    *,
    discovery_exporters: list[dict[str, Any]] | tuple[dict[str, Any], ...],
    collect_exporters: list[dict[str, Any]] | tuple[dict[str, Any], ...],
    selected_exporter_names: set[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not selected_exporter_names:
        return list(discovery_exporters), list(collect_exporters)

    filtered_discovery = [
        item
        for item in discovery_exporters
        if _normalize_collect_exporter_token(str(item.get("name") or "")) in selected_exporter_names
    ]
    filtered_collect = [
        item
        for item in collect_exporters
        if _normalize_collect_exporter_token(str(item.get("name") or "")) in selected_exporter_names
    ]
    return filtered_discovery, filtered_collect


def run_collect_stage(args: argparse.Namespace, logger: AttemptLogger) -> int:
    console = Console(debug=args.debug)
    pipeline_started_at = time.monotonic()

    if args.timeout <= 0:
        console.error("--timeout must be > 0")
        return 2
    if args.retries < 0:
        console.error("--retries must be >= 0")
        return 2

    targets = getattr(args, "targets", None) or getattr(args, "hosts", None)
    hosts_file = getattr(args, "hosts_file", None)
    if hosts_file:
        targets = f"{targets},{hosts_file}" if targets else hosts_file

    try:
        target_plan = stream_scan_target_specs(
            targets,
            policy=TargetParsePolicy(url_mode="preserve", path_policy="preserve"),
            exclude_targets=getattr(args, "out_targets", None),
        )
    except (OSError, ValueError) as exc:
        console.error(f"failed to parse targets: {exc}")
        return 2
    try:
        target_specs = (
            []
            if target_plan.target_count > DEFAULT_MAX_NETWORK_HOSTS
            else collect_scan_target_specs(targets, exclude_targets=getattr(args, "out_targets", None))
        )
    except (OSError, ValueError) as exc:
        console.error(f"failed to parse targets: {exc}")
        return 2

    try:
        profiles = load_profiles(args.profiles_file)
    except (OSError, ValueError) as exc:
        console.error(f"failed to load profiles: {exc}")
        return 2
    try:
        custom_ports = collect_scan_ports(getattr(args, "ports", None))
    except ValueError as exc:
        console.error(f"failed to parse --ports: {exc}")
        return 2
    try:
        tls_context = build_exporter_tls_context(
            insecure=bool(getattr(args, "insecure", False)),
            ca_file=getattr(args, "tls_ca", None),
            cert_file=getattr(args, "tls_cert", None),
            key_file=getattr(args, "tls_key", None),
        )
    except (OSError, ValueError, ssl.SSLError) as exc:
        console.error(f"invalid exporter TLS configuration: {exc}")
        return 2
    target_plan = target_plan.with_additional_ports_for_bare_explicit_targets(bool(custom_ports))
    try:
        selected_collect_exporters = _parse_collect_exporter_filter(
            getattr(args, "collect_exporters_filter", None),
            profiles["collect_exporters"],
        )
    except ValueError as exc:
        console.error(str(exc))
        return 2
    discovery_exporters, collect_exporters = _filter_collect_exporter_profiles(
        discovery_exporters=profiles["discovery_exporters"],
        collect_exporters=profiles["collect_exporters"],
        selected_exporter_names=selected_collect_exporters,
    )

    if not target_plan or (target_plan.target_count <= DEFAULT_MAX_NETWORK_HOSTS and not target_specs):
        if targets and getattr(args, "out_targets", None):
            console.error("all targets were excluded by --out-target")
            return 2
        console.error("collect requires -t/--targets")
        return 2
    hosts = list(dict.fromkeys(spec.host for spec in target_specs))

    stream_to_stdout = not bool(args.output)
    save_responses_dir = getattr(args, "save_responses_dir", None)
    deep = bool(getattr(args, "deep", False))
    resume_enabled = bool(getattr(args, "resume", False))
    checkpoint_requested = bool(getattr(args, "checkpoint_file", None))
    checkpoint_path: str | None = None
    completed_jobs: set[tuple[str, str, int, str]] = set()
    checkpoint_state: dict[tuple[str, str, int, str], dict[str, Any]] = {}
    if resume_enabled or checkpoint_requested:
        checkpoint_path = _resolve_collect_checkpoint_path(args)
    if resume_enabled and checkpoint_path:
        checkpoint_state = _load_collect_checkpoint_state(checkpoint_path, console=console)
        completed_jobs = {key for key, payload in checkpoint_state.items() if payload.get("ok") is True}
    pprof_seconds = int(getattr(args, "pprof_seconds", 5))
    trace_seconds = int(getattr(args, "trace_seconds", 2))
    adaptive_collect = bool(getattr(args, "adaptive_collect", True))
    max_inflight_raw = getattr(args, "max_inflight", None)
    max_inflight: int | None = int(max_inflight_raw) if max_inflight_raw is not None else None
    validator = ValidationRecordAccumulator(
        input_format=COLLECT_VALIDATE_INPUT_FORMAT,
        max_lines=COLLECT_VALIDATE_MAX_LINES,
        precision_profile=COLLECT_VALIDATE_PRECISION_PROFILE,
    )
    collect_endpoints = _build_collect_endpoints(
        profiles["collect_debug_endpoints"],
        deep=deep,
        pprof_seconds=pprof_seconds,
        trace_seconds=trace_seconds,
    )
    selected_profile_names = {
        str(item.get("name") or "") for item in collect_exporters if str(item.get("name") or "").strip()
    }
    scoped_completed_jobs = {
        key
        for key in completed_jobs
        if (key[0] in hosts if hosts else target_plan.contains_host(key[0]))
        and (not selected_profile_names or key[1] in selected_profile_names)
        and key[3] in collect_endpoints
    }
    if resume_enabled:
        for job_key in sorted(scoped_completed_jobs):
            payload = checkpoint_state.get(job_key, {})
            prior_record = payload.get("record")
            if isinstance(prior_record, dict):
                validator.feed(dict(prior_record))
    completed_jobs = scoped_completed_jobs
    resumed_success = len(completed_jobs)
    if args.debug:
        mode = "deep" if deep else "default"
        console.debug(f"collect endpoints mode={mode} count={len(collect_endpoints)}")
        if selected_collect_exporters:
            selected_sorted = ",".join(sorted(selected_collect_exporters))
            console.debug(f"collect exporters filter={selected_sorted}")

    def _split_tabbed_tag(left: str) -> tuple[str, str]:
        parts = left.split("\t", 1)
        if len(parts) != 2:
            return left.strip(), ""
        tag = parts[0].strip()
        rest = "\t" + parts[1]
        return tag, rest

    def emit_line(line: str) -> None:
        if args.output_format != "txt":
            print(line, flush=True)
            return
        is_discovery_line = line.startswith("SCAN")
        if is_discovery_line:
            line = f"{'DISCOVER':<8}" + line[8:]
        if is_discovery_line and not args.debug and " [+] " not in line and " [!] " not in line:
            return
        if " [*] " in line:
            if args.debug:
                console.plain(line, color="cyan")
            return
        if " [+] " in line:
            left, right = line.split(" [+] ", 1)
            tag, rest = _split_tabbed_tag(left)
            if tag in {"DISCOVER", "COLLECT"}:
                tag_text = f"{tag:<8}"
                rest_text = rest
            else:
                tag_text = tag
                rest_text = ""
            colored = (
                f"{console._paint(tag_text, 'blue', sys.stdout)}"
                f"{console._paint(rest_text, 'white', sys.stdout)} "
                f"{console._paint('[+]', 'green', sys.stdout)} "
                f"{console._paint(right, 'white', sys.stdout)}"
            )
            console.plain(colored)
            return
        if not args.debug:
            return
        if " [!] " in line:
            console.plain(line, color="red")
            return
        if " [-] " in line:
            console.plain(line, color="yellow")
            return
        console.plain(line)

    if args.debug and stream_to_stdout and args.output_format == "txt":
        save_suffix = f" save_responses={save_responses_dir}" if save_responses_dir else ""
        ports_hint = f" ports={len(custom_ports)}(custom)" if custom_ports else ""
        checkpoint_hint = f" checkpoint={checkpoint_path}" if checkpoint_path else ""
        resume_hint = f" resume={resume_enabled}" if checkpoint_path else ""
        console.info(
            f"collect started: hosts={target_plan.target_count} timeout={args.timeout}s "
            f"workers={args.workers} retries={args.retries} format=txt"
            f"{ports_hint}{save_suffix}{resume_hint}{checkpoint_hint}"
        )
    if args.debug and not stream_to_stdout:
        save_suffix = f" save_responses={save_responses_dir}" if save_responses_dir else ""
        ports_hint = f" ports={len(custom_ports)}(custom)" if custom_ports else ""
        checkpoint_hint = f" checkpoint={checkpoint_path}" if checkpoint_path else ""
        resume_hint = f" resume={resume_enabled}" if checkpoint_path else ""
        console.info(
            f"collect started: hosts={target_plan.target_count} timeout={args.timeout}s "
            f"workers={args.workers} retries={args.retries} "
            f"format={args.output_format} output={args.output}"
            f"{ports_hint}{save_suffix}{resume_hint}{checkpoint_hint}"
        )

    class _ValidationConsoleProxy:
        def __init__(self, base: Console, *, suppress_summary: bool, output_path: str | None = None) -> None:
            self._base = base
            self._suppress_summary = suppress_summary
            self.debug_enabled = base.debug_enabled
            self._output_fh: TextIO | None = None
            if output_path:
                os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
                self._output_fh = open(output_path, "a", encoding="utf-8")

        def _paint(self, text: str, color: str, stream: TextIO) -> str:
            return self._base._paint(text, color, stream)

        def _write_output_line(self, message: str) -> None:
            if self._output_fh is None:
                return
            self._output_fh.write(message + "\n")
            self._output_fh.flush()

        def plain(self, message: str, color: str | None = None, stream: TextIO | None = None) -> None:
            cleaned = _ANSI_RE.sub("", str(message))
            is_summary = "validate complete: lines=" in cleaned
            if self._suppress_summary and is_summary:
                # Keep validation summary in -o output but hide noisy console row.
                self._write_output_line(cleaned)
                return
            self._base.plain(message, color=color, stream=stream)
            self._write_output_line(cleaned)

        def info(self, message: str) -> None:
            self._base.info(message)
            self._write_output_line(f"[*] {message}")

        def warn(self, message: str) -> None:
            self._base.warn(message)
            self._write_output_line(f"[-] {message}")

        def error(self, message: str) -> None:
            self._base.error(message)
            self._write_output_line(f"[!] {message}")

        def debug(self, message: str) -> None:
            self._base.debug(message)
            if self.debug_enabled:
                self._write_output_line(f"[d] {message}")

        def close(self) -> None:
            if self._output_fh is None:
                return
            self._output_fh.close()
            self._output_fh = None

    def _finish_validation() -> int:
        validate_console = _ValidationConsoleProxy(
            console,
            suppress_summary=True,
            output_path=args.output if args.output_format == "txt" else None,
        )
        try:
            return validator.finish(
                show=COLLECT_VALIDATE_SHOW,
                fail_on_creds=COLLECT_VALIDATE_FAIL_ON_CREDS,
                debug=bool(args.debug),
                console=cast("Console", validate_console),
                source="stream",
            )
        finally:
            validate_console.close()

    def _emit_collect_summary(
        hosts_count: int,
        requests_count: int,
        success_count: int,
        *,
        errors_count: int = 0,
        mode: str = "a",
    ) -> None:
        summary = {
            "timestamp": utc_now_iso(),
            "type": "summary",
            "hosts": hosts_count,
            "requests": requests_count,
            "success": success_count,
            "errors": errors_count,
            "resumed": resumed_success,
            "output_path": args.output,
        }
        line = format_collect_record(summary, args.output_format)
        if args.output:
            os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
            with open(args.output, mode, encoding="utf-8") as out_fh:
                emit_output_line(out_fh, emit_line, line)
        else:
            emit_output_line(None, emit_line, line)

    if target_plan.target_count > DEFAULT_MAX_NETWORK_HOSTS:
        if args.debug:
            console.debug(f"pass=1 detect start total={target_plan.target_count}")
        default_ports = default_exporter_ports(discovery_exporters)
        scan_checks = 0
        scan_found = 0
        scan_errors = 0
        requests = 0
        success = 0
        collect_errors = 0
        collect_stats: dict[str, int] = {}
        skipped_jobs_total = 0
        collect_chunk_index = 0
        data_started_at = time.monotonic()

        def _process_host_chunk(
            host_chunk: list[str],
            ports_for_scan: list[int] | None,
            scheme: str,
        ) -> int:
            nonlocal scan_checks, scan_found, scan_errors, requests, success, collect_errors
            nonlocal collect_chunk_index, skipped_jobs_total
            part_scan_stats: dict[str, int] = {}
            part_checks, part_found, part_found_by_host = scan_exporter_presence(
                hosts=host_chunk,
                timeout=args.timeout,
                output_path=None,
                output_format="txt",
                logger=logger if args.debug else None,
                emit_line=emit_line if args.output_format == "txt" else None,
                workers=args.workers,
                retries=args.retries,
                discovery_exporters=discovery_exporters,
                custom_ports=ports_for_scan,
                emit_summary=False,
                show_progress=False,
                progress_leave=False,
                progress_owner=getattr(args, "_progress_owner", None),
                stats_sink=part_scan_stats,
                **_collect_transport_kwargs(scheme, tls_context),
            )
            scan_checks += part_checks
            scan_found += part_found
            scan_errors += int(part_scan_stats.get("errors", 0))
            if part_found <= 0:
                return 0
            part_requests, part_success = collect_exporter_debug_data(
                logger=logger if args.debug else None,
                hosts=host_chunk,
                timeout=args.timeout,
                output_path=args.output,
                output_format=args.output_format,
                emit_line=emit_line,
                workers=args.workers,
                retries=args.retries,
                collect_exporters=collect_exporters,
                collect_debug_endpoints=collect_endpoints,
                found_by_host=part_found_by_host,
                save_responses_dir=save_responses_dir,
                record_callback=validator.feed,
                output_mode="a" if (resume_enabled or collect_chunk_index > 0) else "w",
                index_mode="a" if (resume_enabled or collect_chunk_index > 0) else "w",
                emit_summary=False,
                adaptive_collect=adaptive_collect,
                max_inflight_requests=max_inflight,
                resume_completed_jobs=completed_jobs if resume_enabled else None,
                checkpoint_path=checkpoint_path,
                checkpoint_mode="a" if (resume_enabled or collect_chunk_index > 0) else "w",
                stats_sink=collect_stats,
                # The chunked path owns a single command-level bar across all chunks
                # (see `chunk_progress`); the owner allows only one active bar, so the
                # per-chunk collect must not start its own (it would close ours).
                progress_owner=None,
                **_collect_transport_kwargs(scheme, tls_context),
            )
            collect_chunk_index += 1
            requests += part_requests
            success += part_success
            collect_errors += int(collect_stats.get("errors", 0))
            skipped_jobs_total += int(collect_stats.get("skipped_jobs", 0))
            return part_found

        # A huge target list is chunked; per-chunk scan progress is off, so a single
        # command-level bar owns the run (counted by hosts). advance() clamps at the
        # total, so re-visited hosts in the explicit-port matrix never overshoot.
        chunk_progress = None
        if should_use_global_progress(args.output_format, target_plan.target_count):
            chunk_progress = start_command_progress(args, "COLLECT", target_plan.target_count, enabled=True, leave=True)
        try:
            if not target_plan.has_explicit_port_targets:
                for scheme, host_chunk in _chunk_collect_specs_by_scheme(target_plan.iter_specs()):
                    _process_host_chunk(host_chunk, custom_ports or None, scheme)
                    if chunk_progress is not None:
                        chunk_progress.advance(len(host_chunk))
            else:
                matrix_ports = tuple(custom_ports or default_ports)
                for port in target_plan.execution_ports(matrix_ports):
                    for scheme, host_chunk in _chunk_collect_specs_by_scheme(
                        target_plan.iter_specs_for_port(int(port), matrix_ports)
                    ):
                        _process_host_chunk(host_chunk, [int(port)], scheme)
                        if chunk_progress is not None:
                            chunk_progress.advance(len(host_chunk))
        except OSError as exc:
            console.error(f"failed to process collect output: {exc}")
            return 2
        finally:
            if chunk_progress is not None:
                chunk_progress.close()

        data_ms = int((time.monotonic() - data_started_at) * 1000)
        if args.debug:
            console.debug(f"pass=1 detect complete checks={scan_checks} detected={scan_found}")
            console.debug(f"pass=2 deep complete processed={scan_found}")
            console.debug(f"stage_trace stage_name=data attempt=1 duration_ms={data_ms} result=ok error=-")
            total_ms = int((time.monotonic() - pipeline_started_at) * 1000)
            console.debug(
                f"stage_timing_summary status=ok attempts=1/1 detect_ms=0 data_ms={data_ms} total_ms={total_ms}"
            )
        save_suffix = f" saved={save_responses_dir}" if save_responses_dir else ""
        resume_suffix = f" resumed={skipped_jobs_total}" if (resume_enabled and checkpoint_path) else ""
        if stream_to_stdout and args.output_format == "txt":
            console.info(
                f"collect complete: hosts={target_plan.target_count} checks={scan_checks} "
                f"detected={scan_found} requests={requests} success={success}{save_suffix}{resume_suffix}"
            )
        elif not stream_to_stdout:
            console.info(
                f"collect complete: hosts={target_plan.target_count} checks={scan_checks} detected={scan_found} "
                f"requests={requests} success={success} format={args.output_format} output={args.output}"
                f"{save_suffix}{resume_suffix}"
            )
        validate_rc = _finish_validation()
        summary_mode = "a" if (resume_enabled or collect_chunk_index > 0) else "w"
        _emit_collect_summary(
            target_plan.target_count,
            resumed_success + requests,
            resumed_success + success,
            errors_count=collect_errors,
            mode=summary_mode,
        )
        _write_vulnerable_targets_files(args=args, validator=validator, console=console)
        if validate_rc == 2:
            return 2
        if validate_rc == 1:
            return 1
        if scan_found == 0 and scan_errors > 0:
            console.error(
                f"collect inconclusive: no exporter confirmed; {scan_errors}/{scan_checks} discovery requests failed"
            )
            return 1
        if requests > 0 and collect_errors == requests:
            console.error("collect inconclusive: every data request failed")
            return 1
        return 0

    if args.debug:
        console.debug(f"pass=1 detect start total={len(hosts)}")
    detect_started_at = time.monotonic()

    has_target_overrides = any(spec.explicit_port is not None or spec.scheme is not None for spec in target_specs)
    scan_errors = 0
    found_by_scheme: dict[str, dict[str, list[dict[str, Any]]]] = {}
    if not has_target_overrides:
        scan_stats: dict[str, int] = {}
        try:
            scan_checks, scan_found, found_by_host = scan_exporter_presence(
                hosts=hosts,
                timeout=args.timeout,
                output_path=None,
                output_format="txt",
                logger=logger if args.debug else None,
                emit_line=emit_line if args.output_format == "txt" else None,
                workers=args.workers,
                retries=args.retries,
                discovery_exporters=discovery_exporters,
                custom_ports=custom_ports or None,
                emit_summary=False,
                show_progress=True,
                progress_leave=False,
                progress_owner=getattr(args, "_progress_owner", None),
                stats_sink=scan_stats,
                **_collect_transport_kwargs("http", tls_context),
            )
            scan_errors = int(scan_stats.get("errors", 0))
            found_by_scheme["http"] = found_by_host
        except OSError as exc:
            console.error(f"failed to process collect discovery scan: {exc}")
            return 2
    else:
        default_ports = default_exporter_ports(discovery_exporters)
        execution_groups = build_scan_execution_groups(
            target_specs,
            custom_ports or default_ports,
            include_scheme_in_key=True,
            include_matrix_ports_for_bare_explicit_targets=bool(custom_ports),
        )
        scan_checks = 0
        scan_found = 0
        found_by_host = {host: [] for host in hosts}
        seen_hits: dict[str, set[tuple[str, int, str]]] = {host: set() for host in hosts}
        # Mirror `scan`: with explicit-port/URL targets the discovery scan is split
        # into per-port execution groups, so per-group progress bars would flicker.
        # A single command-level bar owns the whole discovery instead (per-group
        # progress stays off). Without this, URL lists showed no progress at all.
        use_single_global_progress = should_use_global_progress(args.output_format, len(execution_groups))
        outer_progress = None
        if use_single_global_progress:
            global_total = progress_total_from_groups(group.hosts for group in execution_groups)
            outer_progress = start_command_progress(args, "COLLECT", global_total, enabled=True, leave=True)
        try:
            for group in execution_groups:
                part_scan_stats: dict[str, int] = {}
                part_checks, part_found, part_found_by_host = scan_exporter_presence(
                    hosts=group.hosts,
                    timeout=args.timeout,
                    output_path=None,
                    output_format="txt",
                    logger=logger if args.debug else None,
                    emit_line=emit_line if args.output_format == "txt" else None,
                    workers=args.workers,
                    retries=args.retries,
                    discovery_exporters=discovery_exporters,
                    custom_ports=[group.port],
                    emit_summary=False,
                    show_progress=not use_single_global_progress,
                    progress_leave=False,
                    progress_owner=getattr(args, "_progress_owner", None),
                    stats_sink=part_scan_stats,
                    **_collect_transport_kwargs(group.scheme_hint or "http", tls_context),
                )
                scan_checks += part_checks
                scan_found += part_found
                scan_errors += int(part_scan_stats.get("errors", 0))
                if outer_progress is not None:
                    outer_progress.advance(part_checks)
                for host, hits in part_found_by_host.items():
                    for hit in hits:
                        exporter = str(hit.get("exporter") or "")
                        try:
                            hit_port = int(hit.get("port", ""))
                        except (TypeError, ValueError):
                            continue
                        hit_key = (exporter, hit_port, str(hit.get("url") or ""))
                        if hit_key in seen_hits.setdefault(host, set()):
                            continue
                        seen_hits[host].add(hit_key)
                        found_by_host.setdefault(host, []).append(hit)
                        scheme_key = group.scheme_hint or "http"
                        found_by_scheme.setdefault(scheme_key, {}).setdefault(host, []).append(hit)
        except OSError as exc:
            console.error(f"failed to process collect discovery scan: {exc}")
            return 2
        finally:
            if outer_progress is not None:
                outer_progress.close()

    detect_ms = int((time.monotonic() - detect_started_at) * 1000)
    deep_candidates = sum(1 for host in hosts if found_by_host.get(host))
    if args.debug:
        console.debug(f"pass=1 detect complete checks={scan_checks} detected={scan_found}")
        console.debug(f"stage_trace stage_name=detect_protocol attempt=1 duration_ms={detect_ms} result=ok error=-")
        console.debug(f"pass=2 deep start total={deep_candidates}")
        for host in hosts:
            host_hits = list(found_by_host.get(host, []))
            if host_hits:
                console.debug(f"{host} stage2_gate=run reason=detected={len(host_hits)}")
            else:
                console.debug(f"{host} stage2_gate=skip reason=detected=0")
        for host in hosts:
            host_hits = list(found_by_host.get(host, []))
            console.debug(f"collect discovery host={host}: detected={len(host_hits)}")
        console.debug(f"collect discovery: checks={scan_checks} detected={scan_found}")

    requests = 0
    success = 0
    data_ms = 0
    # The large-CIDR branch (above) and this normal branch both maintain their own
    # collect_stats dict because they live in mutually exclusive code paths; mypy
    # otherwise complains about a redefinition.
    collect_stats: dict[str, int] = {}  # type: ignore[no-redef]
    if scan_found > 0:
        data_started_at = time.monotonic()
        try:
            aggregate_collect_stats = {"errors": 0, "skipped_jobs": 0}
            collect_call_index = 0
            for scheme, scheme_found_by_host in found_by_scheme.items():
                if not any(scheme_found_by_host.values()):
                    continue
                part_collect_stats: dict[str, int] = {}
                part_requests, part_success = collect_exporter_debug_data(
                    logger=logger if args.debug else None,
                    hosts=hosts,
                    timeout=args.timeout,
                    output_path=args.output,
                    output_format=args.output_format,
                    emit_line=emit_line,
                    workers=args.workers,
                    retries=args.retries,
                    collect_exporters=collect_exporters,
                    collect_debug_endpoints=collect_endpoints,
                    found_by_host=scheme_found_by_host,
                    save_responses_dir=save_responses_dir,
                    record_callback=validator.feed,
                    output_mode="a" if (resume_enabled or collect_call_index > 0) else "w",
                    index_mode="a" if (resume_enabled or collect_call_index > 0) else "w",
                    emit_summary=False,
                    adaptive_collect=adaptive_collect,
                    max_inflight_requests=max_inflight,
                    resume_completed_jobs=completed_jobs if resume_enabled else None,
                    checkpoint_path=checkpoint_path,
                    checkpoint_mode="a" if (resume_enabled or collect_call_index > 0) else "w",
                    stats_sink=part_collect_stats,
                    progress_owner=getattr(args, "_progress_owner", None),
                    **_collect_transport_kwargs(scheme, tls_context),
                )
                collect_call_index += 1
                requests += part_requests
                success += part_success
                aggregate_collect_stats["errors"] += int(part_collect_stats.get("errors", 0))
                aggregate_collect_stats["skipped_jobs"] += int(part_collect_stats.get("skipped_jobs", 0))
            collect_stats.update(aggregate_collect_stats)
        except OSError as exc:
            console.error(f"failed to process collect output: {exc}")
            return 2
        data_ms = int((time.monotonic() - data_started_at) * 1000)

    if scan_found <= 0:
        if args.debug:
            console.debug("pass=2 deep complete processed=0")
            console.debug("stage_trace stage_name=data attempt=1 duration_ms=0 result=skip error=no_detected_exporters")
            total_ms = int((time.monotonic() - pipeline_started_at) * 1000)
            console.debug(
                f"stage_timing_summary status=ok attempts=1/1 detect_ms={detect_ms} data_ms=0 total_ms={total_ms}"
            )
        summary_mode = "a" if resume_enabled else "w"
        _emit_collect_summary(
            len(hosts),
            resumed_success,
            resumed_success,
            errors_count=0,
            mode=summary_mode,
        )
        if save_responses_dir:
            os.makedirs(save_responses_dir, exist_ok=True)
            index_path = os.path.join(save_responses_dir, "index.jsonl")
            with open(index_path, "a" if resume_enabled else "w", encoding="utf-8"):
                pass
        if stream_to_stdout and args.output_format == "txt":
            save_suffix = f" saved={save_responses_dir}" if save_responses_dir else ""
            resume_suffix = (
                f" resumed={collect_stats.get('skipped_jobs', 0)}" if (resume_enabled and checkpoint_path) else ""
            )
            console.info(
                f"collect complete: hosts={len(hosts)} checks={scan_checks} "
                f"detected=0 requests=0 success=0{save_suffix}{resume_suffix}"
            )
        if not stream_to_stdout:
            save_suffix = f" saved={save_responses_dir}" if save_responses_dir else ""
            resume_suffix = (
                f" resumed={collect_stats.get('skipped_jobs', 0)}" if (resume_enabled and checkpoint_path) else ""
            )
            console.info(
                f"collect complete: hosts={len(hosts)} checks={scan_checks} detected=0 requests=0 success=0 "
                f"format={args.output_format} output={args.output}{save_suffix}{resume_suffix}"
            )
            if args.debug:
                console.debug("debug mode enabled; detailed collect events emitted in text logs")
        validate_rc = _finish_validation()
        _write_vulnerable_targets_files(args=args, validator=validator, console=console)
        if validate_rc == 2:
            return 2
        if validate_rc == 1:
            return 1
        if scan_errors > 0:
            console.error(
                f"collect inconclusive: no exporter confirmed; {scan_errors}/{scan_checks} discovery requests failed"
            )
            return 1
        return 0

    if stream_to_stdout:
        if args.output_format == "txt":
            save_suffix = f" saved={save_responses_dir}" if save_responses_dir else ""
            resume_suffix = (
                f" resumed={collect_stats.get('skipped_jobs', 0)}" if (resume_enabled and checkpoint_path) else ""
            )
            console.info(
                f"collect complete: hosts={len(hosts)} checks={scan_checks} "
                f"detected={scan_found} requests={requests} success={success}{save_suffix}{resume_suffix}"
            )
    else:
        save_suffix = f" saved={save_responses_dir}" if save_responses_dir else ""
        resume_suffix = (
            f" resumed={collect_stats.get('skipped_jobs', 0)}" if (resume_enabled and checkpoint_path) else ""
        )
        console.info(
            f"collect complete: hosts={len(hosts)} checks={scan_checks} detected={scan_found} "
            f"requests={requests} success={success} "
            f"format={args.output_format} output={args.output}{save_suffix}{resume_suffix}"
        )
        if args.debug:
            console.debug("debug mode enabled; detailed collect events emitted in text logs")
    if args.debug:
        console.debug(f"pass=2 deep complete processed={scan_found}")
        console.debug(f"stage_trace stage_name=data attempt=1 duration_ms={data_ms} result=ok error=-")
        total_ms = int((time.monotonic() - pipeline_started_at) * 1000)
        console.debug(
            f"stage_timing_summary status=ok attempts=1/1 detect_ms={detect_ms} data_ms={data_ms} total_ms={total_ms}"
        )
    validate_rc = _finish_validation()
    _emit_collect_summary(
        len(hosts),
        resumed_success + requests,
        resumed_success + success,
        errors_count=int(collect_stats.get("errors", 0)),
        mode="a" if resume_enabled or requests > 0 else "w",
    )
    _write_vulnerable_targets_files(args=args, validator=validator, console=console)
    if validate_rc == 2:
        return 2
    if validate_rc == 1:
        return 1
    if requests > 0 and int(collect_stats.get("errors", 0)) == requests:
        console.error("collect inconclusive: every data request failed")
        return 1
    return 0
