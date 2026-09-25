#!/usr/bin/env python3
"""Long-running worker/resource soak for large audit plans."""

from __future__ import annotations

import argparse
import gc
import ipaddress
import json
import threading
import time
import tracemalloc
from pathlib import Path
from types import SimpleNamespace

from redposture_core.audit_models import AuditRecord
from redposture_core.stage_runtime import AuditCommandPlan, AuditCommandRunner, AuditHookContext, ModuleAuditSpec


def _fd_count() -> int | None:
    for directory in (Path("/proc/self/fd"), Path("/dev/fd")):
        try:
            return len(list(directory.iterdir()))
        except OSError:
            continue
    return None


def _targets(count: int) -> tuple[str, ...]:
    start = int(ipaddress.ip_address("10.0.0.1"))
    return tuple(str(ipaddress.ip_address(start + offset)) for offset in range(count))


def run_round(targets: tuple[str, ...], workers: int) -> int:
    def detect(ctx: AuditHookContext) -> AuditRecord:
        return AuditRecord(host=str(ctx.host), port=1, module="soak", service="soak", status="not_soak")

    result = AuditCommandRunner(
        args=SimpleNamespace(debug=False),
        spec=ModuleAuditSpec(
            module="soak",
            label="SOAK",
            default_port=1,
            detect=detect,
            is_detected=lambda _record: False,
            record_retention_limit=0,
        ),
        emit_line=lambda _line: None,
    ).run_plan(AuditCommandPlan(targets_by_port={1: targets}, workers=workers))
    return result.record_count


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--targets", type=int, default=100_000)
    parser.add_argument("--workers", type=int, default=128)
    parser.add_argument("--duration", type=float, default=300.0, help="Minimum run time in seconds.")
    parser.add_argument("--rounds", type=int, default=1, help="Minimum number of complete target rounds.")
    parser.add_argument("--max-growth-mib", type=float, default=24.0)
    args = parser.parse_args()
    if args.targets < 1 or args.workers < 1 or args.duration < 0 or args.rounds < 1:
        parser.error("targets/workers/rounds must be positive and duration must be non-negative")

    targets = _targets(args.targets)
    baseline_threads = threading.active_count()
    baseline_fds = _fd_count()
    tracemalloc.start()
    gc.collect()
    baseline_memory = tracemalloc.get_traced_memory()[0]
    deadline = time.monotonic() + args.duration
    rounds = 0
    processed = 0
    while rounds < args.rounds or time.monotonic() < deadline:
        processed += run_round(targets, args.workers)
        rounds += 1
        gc.collect()

    current_memory, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    final_fds = _fd_count()
    final_threads = threading.active_count()
    growth = max(0, current_memory - baseline_memory)
    allowed = int(args.max_growth_mib * 1024 * 1024)
    report = {
        "targets_per_round": len(targets),
        "rounds": rounds,
        "processed": processed,
        "threads_before": baseline_threads,
        "threads_after": final_threads,
        "fds_before": baseline_fds,
        "fds_after": final_fds,
        "memory_growth_bytes": growth,
        "peak_traced_bytes": peak_memory,
    }
    print(json.dumps(report, sort_keys=True))
    if final_threads > baseline_threads:
        raise SystemExit("thread leak detected")
    if baseline_fds is not None and final_fds is not None and final_fds > baseline_fds + 2:
        raise SystemExit("file descriptor leak detected")
    if growth > allowed:
        raise SystemExit(f"memory growth exceeded {args.max_growth_mib:g} MiB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
