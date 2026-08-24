#!/usr/bin/env python3
"""Run a local scan benchmark and print machine-readable transport/CPU metrics."""

from __future__ import annotations

import argparse
import json
import re
import resource
import subprocess
import time
from pathlib import Path

_SUMMARY_RE = re.compile(
    r"transport summary: requests=(?P<requests>\d+) connections=(?P<connections>\d+) "
    r"reused=(?P<reused>\d+) retries=(?P<retries>\d+) "
    r"tls_contexts=(?P<tls_contexts>\d+) tls_cache_hits=(?P<tls_cache_hits>\d+)"
)


def _target_count(path: str | None) -> int:
    if not path:
        return 0
    return sum(1 for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip())


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Benchmark Kafka/Grafana/Proxmox or another RedPosture scan without enforcing a CI threshold."
    )
    parser.add_argument("--targets-file", help="Optional target file used to calculate targets/sec.")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="Command after --, normally redposture ... --debug")
    args = parser.parse_args()
    command = list(args.command)
    if command and command[0] == "--":
        command.pop(0)
    if not command:
        parser.error("a command is required after --")

    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started = time.monotonic()
    completed = subprocess.run(command, text=True, capture_output=True, check=False)  # noqa: S603
    wall_seconds = max(0.0, time.monotonic() - started)
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    combined = f"{completed.stdout}\n{completed.stderr}"
    summaries = list(_SUMMARY_RE.finditer(combined))
    transport = {name: 0 for name in _SUMMARY_RE.groupindex}
    for match in summaries:
        for name in transport:
            transport[name] += int(match.group(name))
    targets = _target_count(args.targets_file)
    result = {
        "exit_code": int(completed.returncode),
        "wall_seconds": round(wall_seconds, 6),
        "user_cpu_seconds": round(after.ru_utime - before.ru_utime, 6),
        "sys_cpu_seconds": round(after.ru_stime - before.ru_stime, 6),
        "targets": targets,
        "targets_per_second": round(targets / wall_seconds, 3) if targets and wall_seconds else None,
        **transport,
    }
    print(json.dumps(result, sort_keys=True))
    return int(completed.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
