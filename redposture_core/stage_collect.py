"""Collect stage."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import TextIO

from .console import Console
from .constants import COLLECT_DEEP_ENDPOINT_TEMPLATES
from .logger import AttemptLogger
from .profiles import load_profiles
from .scanner import collect_exporter_debug_data, scan_exporter_presence
from .stage_validate import ValidationRecordAccumulator
from .utils import collect_scan_ports, collect_scan_targets, utc_now_iso

COLLECT_VALIDATE_INPUT_FORMAT = "auto"
COLLECT_VALIDATE_SHOW = True
COLLECT_VALIDATE_MAX_LINES = 0
COLLECT_VALIDATE_FAIL_ON_CREDS = False
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


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


def _load_collect_completed_jobs(path: str, *, console: Console | None = None) -> set[tuple[str, str, int, str]]:
    completed: set[tuple[str, str, int, str]] = set()
    if not path or not os.path.exists(path):
        return completed
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
                    port = int(payload.get("port"))
                except (TypeError, ValueError):
                    continue
                if not host or not exporter or not endpoint or port <= 0:
                    continue
                completed.add((host, exporter, port, endpoint))
    except OSError as exc:
        if console is not None:
            console.warn(f"failed to load collect checkpoint '{path}': {exc}")
    return completed


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


def run_collect_stage(args: argparse.Namespace, logger: AttemptLogger) -> int:
    console = Console(debug=args.debug)

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
        hosts = collect_scan_targets(targets)
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

    if not hosts:
        console.error("collect requires -t/--targets")
        return 2

    stream_to_stdout = not bool(args.output)
    save_responses_dir = getattr(args, "save_responses_dir", None)
    deep = bool(getattr(args, "deep", False))
    resume_enabled = bool(getattr(args, "resume", False))
    checkpoint_requested = bool(getattr(args, "checkpoint_file", None))
    checkpoint_path: str | None = None
    completed_jobs: set[tuple[str, str, int, str]] = set()
    if resume_enabled or checkpoint_requested:
        checkpoint_path = _resolve_collect_checkpoint_path(args)
    if resume_enabled and checkpoint_path:
        completed_jobs = _load_collect_completed_jobs(checkpoint_path, console=console)
    pprof_seconds = int(getattr(args, "pprof_seconds", 5))
    trace_seconds = int(getattr(args, "trace_seconds", 2))
    adaptive_collect = bool(getattr(args, "adaptive_collect", True))
    max_inflight_raw = getattr(args, "max_inflight", None)
    max_inflight: int | None = int(max_inflight_raw) if max_inflight_raw is not None else None
    validator = ValidationRecordAccumulator(
        input_format=COLLECT_VALIDATE_INPUT_FORMAT,
        max_lines=COLLECT_VALIDATE_MAX_LINES,
    )
    collect_endpoints = _build_collect_endpoints(
        profiles["collect_debug_endpoints"],
        deep=deep,
        pprof_seconds=pprof_seconds,
        trace_seconds=trace_seconds,
    )
    if args.debug:
        mode = "deep" if deep else "default"
        console.debug(f"collect endpoints mode={mode} count={len(collect_endpoints)}")

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
        if is_discovery_line and not args.debug and " [+] " not in line:
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
            f"collect started: hosts={len(hosts)} timeout={args.timeout}s "
            f"workers={args.workers} retries={args.retries} format=txt"
            f"{ports_hint}{save_suffix}{resume_hint}{checkpoint_hint}"
        )
    if args.debug and not stream_to_stdout:
        save_suffix = f" save_responses={save_responses_dir}" if save_responses_dir else ""
        ports_hint = f" ports={len(custom_ports)}(custom)" if custom_ports else ""
        checkpoint_hint = f" checkpoint={checkpoint_path}" if checkpoint_path else ""
        resume_hint = f" resume={resume_enabled}" if checkpoint_path else ""
        console.info(
            f"collect started: hosts={len(hosts)} timeout={args.timeout}s "
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
            discovery_exporters=profiles["discovery_exporters"],
            custom_ports=custom_ports or None,
            emit_summary=False,
            show_progress=True,
            progress_leave=False,
        )
    except OSError as exc:
        console.error(f"failed to process collect discovery scan: {exc}")
        return 2

    if args.debug:
        for host in hosts:
            host_hits = list(found_by_host.get(host, []))
            console.debug(f"collect discovery host={host}: detected={len(host_hits)}")
        console.debug(f"collect discovery: checks={scan_checks} detected={scan_found}")

    requests = 0
    success = 0
    collect_stats: dict[str, int] = {}
    if scan_found > 0:
        try:
            requests, success = collect_exporter_debug_data(
                logger=logger if args.debug else None,
                hosts=hosts,
                timeout=args.timeout,
                output_path=args.output,
                output_format=args.output_format,
                emit_line=emit_line,
                workers=args.workers,
                retries=args.retries,
                collect_exporters=profiles["collect_exporters"],
                collect_debug_endpoints=collect_endpoints,
                found_by_host=found_by_host,
                save_responses_dir=save_responses_dir,
                record_callback=validator.feed,
                output_mode="a" if resume_enabled else "w",
                index_mode="a" if resume_enabled else "w",
                emit_summary=False,
                adaptive_collect=adaptive_collect,
                max_inflight_requests=max_inflight,
                resume_completed_jobs=completed_jobs if resume_enabled else None,
                checkpoint_path=checkpoint_path,
                checkpoint_mode="a" if resume_enabled else "w",
                stats_sink=collect_stats,
            )
        except OSError as exc:
            console.error(f"failed to process collect output: {exc}")
            return 2

    if scan_found <= 0:
        if args.output and args.output_format == "json":
            os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
            with open(args.output, "w", encoding="utf-8") as out_fh:
                out_fh.write(
                    json.dumps(
                        {
                            "timestamp": utc_now_iso(),
                            "type": "summary",
                            "hosts": len(hosts),
                            "requests": 0,
                            "success": 0,
                            "output_path": args.output,
                        },
                        ensure_ascii=False,
                    )
                    + "\n"
                )
        if save_responses_dir:
            os.makedirs(save_responses_dir, exist_ok=True)
            index_path = os.path.join(save_responses_dir, "index.jsonl")
            with open(index_path, "w", encoding="utf-8"):
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
        validate_console = _ValidationConsoleProxy(
            console,
            suppress_summary=True,
            output_path=args.output if args.output_format == "txt" else None,
        )
        try:
            validate_rc = validator.finish(
                show=COLLECT_VALIDATE_SHOW,
                fail_on_creds=COLLECT_VALIDATE_FAIL_ON_CREDS,
                debug=bool(args.debug),
                console=validate_console,
                source="stream",
            )
        finally:
            validate_console.close()
        if validate_rc == 2:
            return 2
        if validate_rc == 1:
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
    validate_console = _ValidationConsoleProxy(
        console,
        suppress_summary=True,
        output_path=args.output if args.output_format == "txt" else None,
    )
    try:
        validate_rc = validator.finish(
            show=COLLECT_VALIDATE_SHOW,
            fail_on_creds=COLLECT_VALIDATE_FAIL_ON_CREDS,
            debug=bool(args.debug),
            console=validate_console,
            source="stream",
        )
    finally:
        validate_console.close()
    if validate_rc == 2:
        return 2
    if validate_rc == 1:
        return 1
    return 0
