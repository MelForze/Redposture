#!/usr/bin/env python3
"""Deterministic loopback detection profile; logical routes, not physical hosts.

Each measurement runs the actual Grafana detector and audit scheduler in a fresh
process. Auth/data are explicitly disabled in both sources to isolate detection.
The fixture server runs in that process, so CPU/RSS include its cost. No external
network, Docker, credentials or command execution is used.
"""

from __future__ import annotations

import argparse
import asyncio
import collections
import hashlib
import json
import os
import random
import resource
import statistics
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import replace
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MODELS = ("numeric", "hostname", "interim", "mixed")


def expected_ids(targets: int, seed: int) -> set[int]:
    return set(random.Random(seed).sample(range(targets), max(1, targets // 20)))


def compare_runs(before: list[dict[str, Any]], after: list[dict[str, Any]]) -> dict[str, Any]:
    """Quality is mandatory; timings use repeated medians and a noise allowance.

    A timing regression requires >25%, >0.25s and more than three times the
    observed full range in either sample. No claim is made for one-off timings.
    """
    if not before or len(before) != len(after):
        raise ValueError("equal nonempty measurement sets are required")
    keys = ("model", "targets", "seed", "detect_concurrency", "deep_workers", "timeout", "retries", "delay_ms")
    if any(tuple(row[k] for k in keys) != tuple(before[0][k] for k in keys) for row in before + after):
        raise ValueError("measurement parameters differ")
    quality = all(row["quality"] == "PASS" for row in before + after)
    quality = quality and len({row["result_sha256"] for row in before + after}) == 1
    if any(len({row.get("source_sha256") for row in group}) != 1 for group in (before, after)):
        raise ValueError("source changed between measurements")

    def median_metric(group: list[dict[str, Any]], key: str) -> float | None:
        values = [row[key] for row in group]
        # Missing first finding is evidence of a failed run, never a zero time.
        return None if any(value is None for value in values) else statistics.median(values)

    times = [[row["wall_seconds"] for row in group] for group in (before, after)]
    medians = [statistics.median(group) for group in times]
    spread = max(max(group) - min(group) for group in times)
    repeated = len(before) >= 3
    regression = repeated and medians[1] - medians[0] > max(medians[0] * 0.25, 0.25, 3 * spread)
    return {
        "status": "FAIL" if not quality or regression else "PASS",
        "quality": "PASS" if quality else "FAIL",
        "timing_status": "REGRESSION" if regression else "NO_REGRESSION" if repeated else "INSUFFICIENT_REPEATS",
        "repeats": len(before),
        "before_median_seconds": medians[0],
        "after_median_seconds": medians[1],
        "speedup": medians[0] / medians[1] if medians[1] else None,
        "observed_range_seconds": spread,
        "metrics": {
            key: {"before": median_metric(before, key), "after": median_metric(after, key)}
            for key in (
                "http_requests",
                "cpu_seconds",
                "peak_rss_bytes",
                "first_finding_seconds",
                "fd_peak",
                "threads_peak",
            )
        },
    }


def fd_count() -> int:
    for directory in ("/proc/self/fd", "/dev/fd"):
        try:
            return len(os.listdir(directory))
        except OSError:
            pass
    return 0


class Fixture:
    def __init__(self, model: str, positives: set[int], delay_ms: float):
        self.model, self.positives, self.delay_ms = model, positives, delay_ms
        self.requests = 0
        self.writers: set[asyncio.StreamWriter] = set()
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, name="profile-http", daemon=True)
        self.thread.start()
        self.port = asyncio.run_coroutine_threadsafe(self.start(), self.loop).result(5)

    async def start(self) -> int:
        self.server = await asyncio.start_server(self.serve, "127.0.0.1", 0)
        return int(self.server.sockets[0].getsockname()[1])

    async def serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.writers.add(writer)
        try:
            while True:
                try:
                    head = await reader.readuntil(b"\r\n\r\n")
                except (asyncio.IncompleteReadError, ConnectionError):
                    break
                path = head.split(b" ", 2)[1].decode("ascii").split("?", 1)[0]
                parts = path.strip("/").split("/")
                index = int(parts[1]) if len(parts) > 1 and parts[0] == "target" else -1
                self.requests += 1
                delay = self.delay_ms * (10 if self.model == "mixed" and index % 20 == 0 else 1)
                await asyncio.sleep(delay / 1000)
                positive = index in self.positives
                status, body = 404, b"ordinary unrelated endpoint"
                if positive and path.endswith("/api/health"):
                    status = 200
                    body = json.dumps({"database": "ok", "version": f"13.0.{index}", "commit": "abcdef"}).encode()
                elif positive and "/api/" in path:
                    status, body = 401, b'{"message":"Unauthorized"}'
                elif positive and path.endswith("/login"):
                    # API proof identifies this service; the app DOM is an
                    # independent positive control for both source revisions.
                    status = 200
                    body = b'<html><title>Grafana</title><link rel="stylesheet" href="/public/build/grafana.dark.123.css"><body class="app-grafana"><div id="reactRoot"></div><script src="/public/build/app.123.js"></script></body></html>'
                if self.model == "interim" or self.model == "mixed" and index % 3 == 0:
                    writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")
                writer.write(
                    f"HTTP/1.1 {status} Result\r\nContent-Length: {len(body)}\r\nConnection: keep-alive\r\n\r\n".encode()
                    + body
                )
                await writer.drain()
        except (ConnectionError, OSError, ValueError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
            self.writers.discard(writer)

    def close(self) -> int:
        async def stop() -> int:
            self.server.close()
            await self.server.wait_closed()
            writers = list(self.writers)
            for writer in writers:
                writer.close()
            await asyncio.gather(*(writer.wait_closed() for writer in writers), return_exceptions=True)
            for _ in range(100):
                if not self.writers:
                    break
                await asyncio.sleep(0.01)
            return len(self.writers)

        remaining = asyncio.run_coroutine_threadsafe(stop(), self.loop).result(5)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)
        self.loop.close()
        return remaining + int(self.thread.is_alive())


def one_run(args: argparse.Namespace) -> dict[str, Any]:
    source = Path(args.source).resolve()
    source_hash = hashlib.sha256()
    for path in sorted((source / "redposture_core").rglob("*.py")):
        source_hash.update(str(path.relative_to(source)).encode())
        source_hash.update(path.read_bytes())
    sys.path.insert(0, str(source))
    from redposture_core.cli_args import parse_args
    from redposture_core.modules.grafana.stage import build_grafana_spec
    from redposture_core.stage_runtime import AuditCommandPlan, AuditCommandRunner
    from redposture_core.targeting import ScanTargetSpec

    positives = expected_ids(args.targets, args.seed)
    initial_fd = fd_count()
    initial_threads = threading.active_count()
    fixture = Fixture(args.model, positives, args.delay_ms)
    options = parse_args(["grafana", "-t", "127.0.0.1", "--timeout", "2", "-r", "0", "--no-color"])
    options._async_detect_concurrency = args.concurrency
    spec = replace(
        build_grafana_spec(options),
        auth=None,
        capabilities=None,
        data=None,
        render=lambda _: (),
        render_module=None,
        record_retention_limit=0,
    )
    seen: collections.Counter[int] = collections.Counter()
    errors: collections.Counter[str] = collections.Counter()
    records = 0
    first = None
    start = time.monotonic()

    def record(row: dict[str, Any]) -> None:
        nonlocal first, records
        records += 1
        if row.get("error"):
            errors[str(row["error"])] += 1
        if row.get("is_grafana") is True:
            if first is None:
                first = time.monotonic() - start
            seen[int(str(row["server_version"]).rsplit(".", 1)[1])] += 1

    options._record_callback = record
    targets = tuple(
        ScanTargetSpec(
            "localhost" if args.model == "hostname" or args.model == "mixed" and i % 2 else "127.0.0.1",
            scheme="http",
            explicit_port=fixture.port,
            path=f"/target/{i}",
        )
        for i in range(args.targets)
    )
    plan = AuditCommandPlan(
        target_specs_by_port={fixture.port: targets}, ports=(fixture.port,), workers=args.workers, output_format="txt"
    )
    runner = AuditCommandRunner(args=options, spec=spec, emit_line=lambda _: None)
    peak_fd, peak_threads = [fd_count()], [threading.active_count()]
    stopping = threading.Event()

    def sample() -> None:
        while not stopping.wait(0.02):
            peak_fd[0] = max(peak_fd[0], fd_count())
            peak_threads[0] = max(peak_threads[0], threading.active_count())

    sampler = threading.Thread(target=sample, name="profile-sampler", daemon=True)
    sampler.start()
    start_cpu = time.process_time()
    start = time.monotonic()
    try:
        result = runner.run_plan(plan)
        wall = time.monotonic() - start
        cpu = time.process_time() - start_cpu
    finally:
        runner._close_all_lifecycle_states()
        stopping.set()
        sampler.join(2)
        remaining = fixture.close()
    # Bounded resolver workers retire after their idle timeout. This wait is
    # outside measured wall time, and cleanup itself has an explicit deadline.
    until = time.monotonic() + 2
    while threading.active_count() > initial_threads and time.monotonic() < until:
        time.sleep(0.02)
    missing, extra = sorted(positives - set(seen)), sorted(set(seen) - positives)
    duplicates = sum(count - 1 for count in seen.values())
    operational_errors = {message: count for message, count in errors.items() if message != "service is not grafana"}
    fd_after, threads_after = fd_count(), threading.active_count()
    cleanup = remaining == 0 and threads_after <= initial_threads and fd_after <= initial_fd + 2
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * (1 if sys.platform == "darwin" else 1024)
    return {
        "source": str(source),
        "source_sha256": source_hash.hexdigest(),
        "python": sys.version,
        "model": args.model,
        "targets": args.targets,
        "seed": args.seed,
        "detect_concurrency": args.concurrency,
        "deep_workers": args.workers,
        "timeout": 2,
        "retries": 0,
        "delay_ms": args.delay_ms,
        "physical_fixture_servers": 1,
        "wall_seconds": wall,
        "cpu_seconds": cpu,
        "peak_rss_bytes": rss,
        "http_requests": fixture.requests,
        "first_finding_seconds": first,
        "fd_peak": peak_fd[0],
        "threads_peak": peak_threads[0],
        "fd_before": initial_fd,
        "fd_after": fd_after,
        "threads_after": threads_after,
        "cleanup": "PASS" if cleanup else "FAIL",
        "records": records,
        "errors": dict(errors),
        "operational_errors": operational_errors,
        "missing": missing,
        "extra": extra,
        "duplicates": duplicates,
        "result_sha256": hashlib.sha256(json.dumps(sorted(seen)).encode()).hexdigest(),
        "quality": "PASS"
        if not missing
        and not extra
        and not duplicates
        and not operational_errors
        and records == result.record_count == args.targets
        and cleanup
        else "FAIL",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source", default=str(ROOT))
    parser.add_argument("--baseline", help="Optional source tree for paired before/after runs")
    parser.add_argument("--targets", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=20261106)
    parser.add_argument("--concurrency", type=int, default=128)
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--delay-ms", type=float, default=2)
    parser.add_argument("--model", choices=MODELS, default="mixed")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--one-run", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument(
        "--container-image",
        default=os.environ.get("REDPOSTURE_PROFILE_CONTAINER_IMAGE"),
        help="Run each measurement in a fresh, network-isolated Linux container (e.g. python:3.12.14-slim)",
    )
    args = parser.parse_args()
    if args.targets < 32 or args.concurrency < 1 or args.workers < 1 or args.repeats < 1 or args.delay_ms < 0:
        parser.error("targets >=32, positive workers/concurrency/repeats and delay >=0 required")
    if args.output.exists():
        parser.error("output already exists; use a fresh artifact path")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.one_run:
        row = one_run(args)
        args.output.write_text(json.dumps(row, indent=2) + "\n")
        return 0 if row["quality"] == "PASS" else 1
    phases = {"after": args.source}
    if args.baseline:
        phases = {"before": args.baseline, **phases}
    samples: dict[str, list[dict[str, Any]]] = {phase: [] for phase in phases}
    warmups: dict[str, dict[str, Any]] = {}
    # One warm-up for each source, then alternate order to reduce order bias.
    for repeat in range(args.repeats + 1):
        order = list(phases) if repeat % 2 == 0 else list(reversed(phases))
        for phase in order:
            path = args.output.with_name(f"{args.output.stem}-{phase}-{repeat}.json")
            command = [
                sys.executable,
                str(Path(__file__).resolve()),
                "--one-run",
                "--source",
                phases[phase],
                "--output",
                str(path),
                "--model",
                args.model,
                "--targets",
                str(args.targets),
                "--seed",
                str(args.seed),
                "--concurrency",
                str(args.concurrency),
                "--workers",
                str(args.workers),
                "--delay-ms",
                str(args.delay_ms),
            ]
            container_name = None
            if args.container_image:
                container_name = "redposture-detect-profile-" + uuid.uuid4().hex
                script = str(Path(__file__).resolve())
                command = [
                    "docker",
                    "run",
                    "--pull",
                    "never",
                    "--rm",
                    "--name",
                    container_name,
                    "--network",
                    "none",
                    "--cpus",
                    "2",
                    "--memory",
                    "768m",
                    "--pids-limit",
                    "256",
                    "--mount",
                    f"type=bind,src={Path(phases[phase]).resolve()},dst=/profile-source,readonly",
                    "--mount",
                    f"type=bind,src={script},dst=/profile-tools/profile.py,readonly",
                    "--mount",
                    f"type=bind,src={path.parent.resolve()},dst=/profile-output",
                    args.container_image,
                    "python",
                    "/profile-tools/profile.py",
                    *command[2:],
                ]
                command[command.index("--source") + 1] = "/profile-source"
                command[command.index("--output") + 1] = "/profile-output/" + path.name
            try:
                run = subprocess.run(command, check=False, timeout=600)
            finally:
                if container_name is not None:
                    subprocess.run(
                        ["docker", "rm", "-f", "-v", container_name], capture_output=True, timeout=30, check=False
                    )
            if not path.exists():
                raise RuntimeError(f"measurement failed without result: exit={run.returncode}")
            row = json.loads(path.read_text())
            row["container_image"] = args.container_image
            if repeat:
                samples[phase].append(row)
            else:
                warmups[phase] = row
            print(
                json.dumps(
                    {"phase": phase, "repeat": repeat, "quality": row["quality"], "wall_seconds": row["wall_seconds"]}
                ),
                flush=True,
            )
    comparison = (
        compare_runs(samples["before"], samples["after"])
        if args.baseline
        else {
            "status": "PASS" if all(row["quality"] == "PASS" for row in samples["after"]) else "FAIL",
            "timing_status": "NO_BASELINE",
        }
    )
    if any(row["quality"] != "PASS" for row in warmups.values()):
        comparison["status"] = "FAIL"
    payload = {
        "schema": 1,
        "scope": "Grafana detect only; logical loopback routes; fixture CPU/RSS included",
        "warmups_per_source": 1,
        "warmups": warmups,
        "samples": samples,
        "comparison": comparison,
    }
    args.output.write_text(json.dumps(payload, indent=2) + "\n")
    print(json.dumps(comparison, indent=2))
    return 0 if comparison["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
