#!/usr/bin/env python3
"""Real spray/collect/trigger CLI on isolated logical loopback HTTP targets.

These are protocol fixtures. Trigger does not cause a real backend connection;
the peer returns a known probe result. Listener integration is a separate gate.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import ipaddress
import json
import resource
import socket
import sys
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

from scripts.performance_container import container_sample  # noqa: E402
from scripts.performance_contracts import HttpRouteStats, SchedulerAdmissionProbe  # noqa: E402
from scripts.performance_http_fixtures import grafana_reply, jenkins_reply, response  # noqa: E402
from scripts.performance_http_server import AsyncHttpFixture  # noqa: E402
from scripts.profile_module_performance import (  # noqa: E402
    BASE_IP,
    PROFILE_FILES,
    activate_source,
    case_roles,
    environment_evidence,
    fd_count,
    profile_output_files,
    source_hash,
)

WORKFLOW_FILES = (
    *PROFILE_FILES,
    "scripts/performance_container.py",
    "scripts/performance_http_server.py",
    "scripts/profile_workflow_performance.py",
)
PAIR = ("profile-user", "profile-password")
BAD_PAIR = ("profile-user", "wrong-password")
ENDPOINTS = ("/metrics", "/debug/vars", "/config")
GRAFANA_HEALTH = {"database": "ok", "version": "13.3.0", "commit": "qa-profile"}


def fixture_body(path: str) -> str:
    return {
        "/metrics": '# HELP mysql_exporter_build_info Build information\nmysql_exporter_build_info{version="0.15.1"} 1\n',
        "/debug/vars": '{"service":"billing","region":"qa-eu","workers":4}',
        "/config": '{"application":"billing","region":"qa-eu","replicas":3}',
    }[path]


def workflow_hash(parent: Path) -> str:
    contents = {name: (ROOT / name).read_bytes() for name in WORKFLOW_FILES}
    digest = hashlib.sha256()
    for name, payload in contents.items():
        digest.update(name.encode())
        digest.update(payload)
    fingerprint = digest.hexdigest()
    folder = parent / ("instrument-" + fingerprint)
    for name, payload in contents.items():
        target = folder / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and target.read_bytes() != payload:
            raise ValueError("instrument snapshot changed")
        if not target.exists():
            target.write_bytes(payload)
    expected = {
        "profile_sha256": fingerprint,
        "files": {name: hashlib.sha256(data).hexdigest() for name, data in contents.items()},
    }
    manifest = folder / "MANIFEST.json"
    if manifest.exists():
        try:
            actual = json.loads(manifest.read_text())
        except (OSError, ValueError) as exc:
            raise ValueError("instrument manifest changed") from exc
        if actual != expected:
            raise ValueError("instrument manifest changed")
    else:
        with manifest.open("x") as handle:
            handle.write(json.dumps(expected, indent=2) + "\n")
    return fingerprint


def verify_records(rows: list[dict[str, Any]], workflow: str, module: str, expected: set[str]) -> dict[str, Any]:
    actual: Counter[tuple[Any, ...]] = Counter()
    errors: Counter[str] = Counter()
    wanted_keys: set[tuple[str, ...]]
    if workflow == "spray":
        confirmed = {
            r.get("host")
            for r in rows
            if r.get("status") == "confirmed" and r.get("module") == module and r.get("surface") != "ui"
        }
        for row in rows:
            if row.get("surface") == "ui":
                errors["unexpected UI surface"] += 1
                continue
            if "credential_type" not in row:
                continue
            if row.get("credential_type") != "pair" or row.get("module") != module:
                errors["unexpected credential type or module"] += 1
                continue
            if not all(isinstance(row.get(field), str) for field in ("host", "username", "password")):
                errors["malformed credential identity"] += 1
                continue
            pair = (row.get("username"), row.get("password"))
            actual[(row.get("host"), *pair)] += 1
            wanted = "valid" if pair == PAIR else "invalid" if pair == BAD_PAIR else "UNDEFINED"
            if row.get("status") != wanted:
                errors["credential verdict " + str(row.get("status"))] += 1
        wanted_keys = {(host, *pair) for host in expected for pair in (PAIR, BAD_PAIR)}
        if confirmed != expected:
            errors["confirmed target set differs"] += 1
    elif workflow == "collect":
        for row in rows:
            if "endpoint" not in row:
                continue
            if not isinstance(row.get("host"), str) or not isinstance(row.get("endpoint"), str):
                errors["malformed collect identity"] += 1
                continue
            actual[(row.get("host"), row.get("endpoint"))] += 1
            endpoint = row.get("endpoint")
            if endpoint not in ENDPOINTS or row.get("ok") is not True or row.get("body") != fixture_body(endpoint):
                errors["incorrect or incomplete collected body"] += 1
        wanted_keys = {(host, endpoint) for host in expected for endpoint in ENDPOINTS}
    else:
        for row in rows:
            if row.get("source_type", row.get("type")) != "trigger":
                continue
            if not isinstance(row.get("host"), str):
                errors["malformed trigger identity"] += 1
                continue
            actual[(row.get("host"),)] += 1
            if (
                row.get("confirmed") is not True
                or row.get("success") is not True
                or row.get("probe_success") is not True
            ):
                errors["unconfirmed trigger"] += 1
        wanted_keys = {(host,) for host in expected}
    missing = wanted_keys - set(actual)
    extra = set(actual) - wanted_keys
    duplicates = sum(max(0, count - 1) for count in actual.values())
    return {
        "missing": sorted(missing),
        "extra": sorted(extra),
        "duplicates": duplicates,
        "errors": dict(errors),
        "records_checked": sum(actual.values()),
        "result_sha256": hashlib.sha256(json.dumps(sorted(actual), sort_keys=True).encode()).hexdigest(),
        "quality": "PASS" if not (missing or extra or duplicates or errors) else "FAIL",
    }


class FirstFinding:
    """Observe complete, known-positive JSONL records, never just a nonempty file."""

    def __init__(self, workflow: str, module: str, expected: set[str]) -> None:
        self.workflow, self.module, self.expected = workflow, module, expected
        self.offset = 0
        self.pending = b""
        self.seconds: float | None = None
        self.error: str | None = None
        self.lock = threading.Lock()

    def positive(self, row: Any) -> bool:
        if not isinstance(row, dict) or row.get("host") not in self.expected:
            return False
        if self.workflow == "collect":
            endpoint = row.get("endpoint")
            return (
                isinstance(endpoint, str)
                and endpoint in ENDPOINTS
                and row.get("ok") is True
                and row.get("body") == fixture_body(endpoint)
            )
        if self.workflow == "spray":
            return (
                row.get("module") == self.module
                and row.get("credential_type") == "pair"
                and row.get("status") == "valid"
                and (row.get("username"), row.get("password")) == PAIR
            )
        return row.get("source_type", row.get("type")) == "trigger" and all(
            row.get(key) is True for key in ("success", "confirmed", "probe_success")
        )

    def observe(self, path: Path, started: float) -> None:
        with self.lock:
            if self.seconds is not None or self.error:
                return
            try:
                with path.open("rb") as source:
                    source.seek(self.offset)
                    while chunk := source.read(16_384):
                        self.offset += len(chunk)
                        self.pending += chunk
                        while b"\n" in self.pending:
                            line, self.pending = self.pending.split(b"\n", 1)
                            if line.strip() and self.positive(json.loads(line)):
                                self.seconds = time.monotonic() - started
                                return
                        if len(self.pending) > 65_536:
                            self.error = "fixture JSONL record exceeds observer bound"
                            return
            except FileNotFoundError:
                return
            except (OSError, ValueError, TypeError) as exc:
                self.error = type(exc).__name__


def measure(args: argparse.Namespace) -> dict[str, Any]:
    activate_source(args.source)
    from redposture_core import cli
    from redposture_core.async_detection import AsyncDetectScheduler

    roles = case_roles(args.targets, args.model, args.seed)
    hosts = {index: str(ipaddress.IPv4Address(BASE_IP + index)) for index in roles}
    expected = {hosts[index] for index, role in roles.items() if role == "positive"}
    env = environment_evidence()
    fingerprint = workflow_hash(args.output.parent)
    start_fd, start_threads = fd_count(), threading.active_count()
    routes = HttpRouteStats()

    def router(method, path, headers, body, host):
        routes.record(method, path, headers, body)
        index = int(ipaddress.IPv4Address(host)) - BASE_IP
        if roles.get(index) != "positive":
            return response(200, "ordinary unrelated service", headers={"Content-Type": "text/plain"})
        if args.workflow == "spray":
            if args.module == "grafana":
                result = grafana_reply(method, path, headers, body, valid_pair=PAIR)
                if result is not None:
                    return result
                if urlsplit(path).path == "/api/health":
                    return response(200, GRAFANA_HEALTH)
                return response(
                    200,
                    '<title>Grafana</title><div class="grafana-app"><form><input name="user"><input name="password"></form></div>',
                    headers={"Content-Type": "text/html"},
                )
            return jenkins_reply(method, path, headers, body, valid_pair=PAIR, origin=f"http://{host}:{fixture.port}")
        parsed = urlsplit(path)
        if parsed.path in ENDPOINTS:
            return response(200, fixture_body(parsed.path), headers={"Content-Type": "text/plain"})
        if parsed.path == "/probe":
            query = parse_qs(parsed.query)
            if query.get("target") != ["127.0.0.1:3306"] or query.get("auth_module") != ["profile"]:
                raise ValueError("unexpected trigger target or profile")
            return response(200, "probe_success 1\n", headers={"Content-Type": "text/plain"})
        return response(404, {"message": "Not found"})

    def delay(host, path):
        index = int(ipaddress.IPv4Address(host)) - BASE_IP
        return 0.05 if args.model == "slow" and index % 20 == 0 else args.delay_ms / 1000

    fixture = AsyncHttpFixture(router, host="0.0.0.0", delay=delay)
    fixture.start()
    refused = socket.socket()
    refused.bind(("0.0.0.0", 0))
    closed_port = refused.getsockname()[1]
    target_file = args.output.with_suffix(".targets.txt")
    target_file.write_text(
        "".join(f"http://{hosts[i]}:{closed_port if role == 'closed' else fixture.port}\n" for i, role in roles.items())
    )
    output = args.output.with_suffix(".results.jsonl")
    flags = [
        "--timeout",
        str(args.timeout),
        "--retries",
        "0",
        "--workers",
        str(args.workers),
        "--no-color",
        "--format",
        "json",
        "-o",
        str(output),
    ]
    if args.workflow == "spray":
        pairs = args.output.with_suffix(".pairs.txt")
        pairs.write_text(":".join(BAD_PAIR) + "\n" + ":".join(PAIR) + "\n")
        argv = [
            "spray",
            "-t",
            str(target_file),
            "--modules",
            args.module,
            "--pairs",
            str(pairs),
            "--origin-rate",
            "100000",
            "--account-interval",
            "0.0001",
            *flags,
        ]
    else:
        profiles = args.output.with_suffix(".profiles.json")
        exporter = {
            "name": "mysqld_exporter",
            "port": fixture.port,
            "markers": ["mysql_exporter_build_info"],
            "detect_path": "/metrics",
            "trigger_path": "/probe",
            "target_fmt": "{our_host}:3306",
            "trigger_query": "auth_module=profile",
        }
        profiles.write_text(
            json.dumps(
                {
                    "trigger_exporters": [exporter],
                    "discovery_exporters": [exporter],
                    "collect_exporters": [exporter],
                    "collect_debug_endpoints": ENDPOINTS,
                }
            )
        )
        argv = [
            "exporters",
            args.workflow,
            "-t",
            str(target_file),
            "--profiles-file",
            str(profiles),
            "--ports",
            str(fixture.port),
            *flags,
        ]
        if args.workflow == "trigger":
            argv += ["--callback-ip", "127.0.0.1", "--no-with-listen", "--mysql-auth-module", "profile"]
    if args.debug:
        argv.append("--debug")
    peak = {"fd": fd_count(), "threads": threading.active_count()}
    stopping = threading.Event()
    first: list[float] = []
    confirmed_first = FirstFinding(args.workflow, args.module, expected)
    started = time.monotonic()
    cpu = time.process_time()

    def sample():
        while not stopping.wait(0.02):
            peak["fd"] = max(peak["fd"], fd_count())
            peak["threads"] = max(peak["threads"], threading.active_count())
            if not first and output.exists() and output.stat().st_size:
                first.append(time.monotonic() - started)
            confirmed_first.observe(output, started)

    sampler = threading.Thread(target=sample, name="workflow-resource-sampler", daemon=True)
    sampler.start()
    admission = SchedulerAdmissionProbe(AsyncDetectScheduler)
    try:
        with (
            admission,
            args.output.with_suffix(".stdout.log").open("w") as out,
            args.output.with_suffix(".stderr.log").open("w") as err,
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
        ):
            code = cli.main(argv)
        confirmed_first.observe(output, started)
        wall = time.monotonic() - started
        cpu = time.process_time() - cpu
    finally:
        stopping.set()
        sampler.join(2)
        fixture.close()
        refused.close()
    deadline = time.monotonic() + 3
    while (fd_count() != start_fd or threading.active_count() != start_threads) and time.monotonic() < deadline:
        time.sleep(0.02)
    payload = output.read_text() if output.exists() else ""
    rows = [json.loads(line) for line in payload.splitlines() if line.strip()]
    quality = verify_records(rows, args.workflow, args.module, expected)
    wrong_acceptances = (
        sum(
            row.get("status") == "valid"
            and (
                row.get("host") not in expected
                or row.get("module") != args.module
                or row.get("credential_type") != "pair"
                or (row.get("username"), row.get("password")) != PAIR
            )
            for row in rows
        )
        if args.workflow == "spray"
        else 0
    )
    cleanup = fd_count() == start_fd and threading.active_count() == start_threads
    if (
        code != 0
        or fixture.errors
        or not cleanup
        or "\x1b" in payload
        or admission.snapshot()["restore_conflict"]
        or admission.snapshot()["overflow"]
        or not routes.snapshot()["complete"]
        or confirmed_first.error is not None
        or (bool(expected) and confirmed_first.seconds is None)
    ):
        quality["quality"] = "FAIL"
    return {
        "module": args.module if args.workflow == "spray" else "exporters",
        "workflow": args.workflow,
        "mode": args.workflow,
        "engine": "workflow_auto",
        "target_style": "http",
        "auth_case": "valid_and_invalid" if args.workflow == "spray" else "not_applicable",
        "auth_surface": "default",
        "read_wire_storage_policy": "not_applicable_workflow_jsonl_observation",
        "actions": list(ENDPOINTS)
        if args.workflow == "collect"
        else ["probe:profile"]
        if args.workflow == "trigger"
        else ["two-seeded-pairs"],
        "detect_concurrency": admission.selected_detect_workers(),
        "detect_policy": "automatic",
        "http_peer": "async",
        "detect_concurrency_source": "actual_scheduler_constructor",
        "scheduler_admission": admission.snapshot(),
        "debug_io_policy": "public CLI owns stdout/stderr",
        "measured_output_files": profile_output_files(
            [args.output.with_suffix(".stdout.log"), args.output.with_suffix(".stderr.log"), output]
        ),
        "format": "json",
        "save": True,
        "invalid_credentials_accepted": wrong_acceptances,
        "first_finding_seconds": confirmed_first.seconds,
        "first_finding_note": "20 ms sampled upper bound: first complete saved JSONL record matching a known positive fixture; includes output flush latency",
        "first_finding_observer_error": confirmed_first.error,
        "model": args.model,
        "targets": args.targets,
        "seed": args.seed,
        "timeout": args.timeout,
        "retries": 0,
        "workers": args.workers,
        "deep_workers": args.workers,
        "debug": args.debug,
        "delay_ms": args.delay_ms,
        "source_sha256": source_hash(args.source),
        "profile_sha256": fingerprint,
        "environment": env["details"],
        "environment_sha256": env["sha256"],
        "container_image_id": None,
        "fixture": "protocol emulation, not a real product; real public CLI and HTTP clients",
        "fixture_process_included_in_metrics": True,
        "command": argv,
        "public_exit": code,
        "wall_seconds": wall,
        "cpu_seconds": cpu,
        "throughput": args.targets / wall,
        "peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
        "fd_peak": peak["fd"],
        "threads_peak": peak["threads"],
        "fd_before": start_fd,
        "fd_after": fd_count(),
        "threads_before": start_threads,
        "threads_after": threading.active_count(),
        "cleanup": "PASS" if cleanup else "FAIL",
        "first_saved_record_upper_seconds": first[0] if first else None,
        "first_saved_record_note": "20 ms sampled first nonempty output, may be a negative record; not claimed as first confirmed finding",
        "requests": dict(fixture.stats),
        "http_routes": routes.snapshot(),
        "fixture_errors": fixture.errors,
        **quality,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workflow", required=True, choices=("spray", "collect", "trigger"))
    parser.add_argument("--module", default="grafana", choices=("grafana", "jenkins"))
    parser.add_argument("--source", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--model", choices=("positive", "mixed", "closed", "foreign", "slow"), default="mixed")
    parser.add_argument("--targets", type=int, default=1000)
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--timeout", type=float, default=0.5)
    parser.add_argument("--delay-ms", type=float, default=2)
    parser.add_argument("--seed", type=int, default=20261107)
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--container-image")
    args = parser.parse_args()
    if not 1 <= args.targets <= 10000 or min(args.workers, args.timeout) <= 0 or args.delay_ms < 0:
        parser.error("1..10000 logical targets, positive workers/timeout and nonnegative delay required")
    if args.output.exists():
        parser.error("output already exists")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.container_image:
        flags = [
            "--workflow",
            args.workflow,
            "--module",
            args.module,
            "--targets",
            str(args.targets),
            "--model",
            args.model,
            "--workers",
            str(args.workers),
            "--timeout",
            str(args.timeout),
            "--delay-ms",
            str(args.delay_ms),
            "--seed",
            str(args.seed),
        ]
        if args.debug:
            flags.append("--debug")
        return container_sample(ROOT, Path(__file__).resolve(), args.source, args.output, args.container_image, flags)
    if sys.platform != "linux":
        parser.error("run in the isolated Linux container for loopback aliases and resource metrics")
    result = measure(args)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: result[key] for key in ("workflow", "quality", "public_exit", "wall_seconds", "requests")}))
    return 0 if result["quality"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
