#!/usr/bin/env python3
"""Run the existing per-version CI test job concurrently with resource telemetry."""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class Job:
    tag: str
    argv: tuple[str, ...]
    env: dict[str, str] | None = None
    cwd: Path | None = None


@dataclass
class JobResult:
    exit_code: int
    wall_seconds: float
    sampled_peak_rss_mib: float
    sampled_peak_cpu_percent: float
    sampled_peak_fd: int | None
    pytest_summary: str | None = None
    coverage_percent: float | None = None


def _process_stats(root_pids: set[int]) -> tuple[dict[int, tuple[int, float]], dict[int, set[int]]]:
    """Return RSS KiB/CPU percent and process trees for the three CI jobs."""
    try:
        output = subprocess.check_output(
            ["ps", "-axo", "pid=,ppid=,rss=,%cpu="], text=True, stderr=subprocess.DEVNULL, timeout=5
        )
    except (OSError, subprocess.SubprocessError):
        return {}, {pid: {pid} for pid in root_pids}
    rows: dict[int, tuple[int, int, float]] = {}
    children: dict[int, list[int]] = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) != 4:
            continue
        try:
            pid, parent, rss, cpu = int(fields[0]), int(fields[1]), int(fields[2]), float(fields[3])
        except ValueError:
            continue
        rows[pid] = (parent, rss, cpu)
        children.setdefault(parent, []).append(pid)
    trees: dict[int, set[int]] = {}
    stats: dict[int, tuple[int, float]] = {}
    for root in root_pids:
        pending = [root]
        tree: set[int] = set()
        while pending:
            pid = pending.pop()
            if pid in tree:
                continue
            tree.add(pid)
            pending.extend(children.get(pid, []))
        trees[root] = tree
        stats[root] = (
            sum(rows[pid][1] for pid in tree if pid in rows),
            sum(rows[pid][2] for pid in tree if pid in rows),
        )
    return stats, trees


def _fd_counts(trees: dict[int, set[int]]) -> dict[int, int | None]:
    all_pids = set().union(*trees.values()) if trees else set()
    if not all_pids:
        return {pid: 0 for pid in trees}
    try:
        output = subprocess.check_output(
            ["lsof", "-nP", "-p", ",".join(map(str, sorted(all_pids))), "-F", "pf"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return {pid: None for pid in trees}
    per_pid: dict[int, int] = {}
    current: int | None = None
    for line in output.splitlines():
        if line.startswith("p") and line[1:].isdigit():
            current = int(line[1:])
        elif line.startswith("f") and current is not None:
            per_pid[current] = per_pid.get(current, 0) + 1
    return {root: sum(per_pid.get(pid, 0) for pid in tree) for root, tree in trees.items()}


def _stop_processes(processes: dict[str, subprocess.Popen[bytes]]) -> None:
    for process in processes.values():
        if process.poll() is not None:
            continue
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 5
    for process in processes.values():
        if process.poll() is None:
            try:
                process.wait(timeout=max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass


def run_jobs(
    jobs: list[Job],
    out_dir: Path,
    *,
    sample_interval: float = 5.0,
    max_rss_bytes: int = 10 * 1024**3,
) -> dict[str, JobResult]:
    if not jobs or len({job.tag for job in jobs}) != len(jobs):
        raise ValueError("jobs must be nonempty with unique tags")
    if out_dir.exists() and (
        (out_dir / "results.json").exists() or any((out_dir / f"{job.tag}.log").exists() for job in jobs)
    ):
        raise FileExistsError(f"parallel CI artifacts already exist: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    processes: dict[str, subprocess.Popen[bytes]] = {}
    streams = []
    started: dict[str, float] = {}
    finished: dict[str, float] = {}
    peak_rss: dict[str, int] = {job.tag: 0 for job in jobs}
    peak_cpu: dict[str, float] = {job.tag: 0 for job in jobs}
    peak_fd: dict[str, int | None] = {job.tag: None for job in jobs}
    resource_exceeded = False
    samples_over_limit = 0
    last_progress = time.monotonic()
    try:
        for job in jobs:
            stream = (out_dir / f"{job.tag}.log").open("wb")
            streams.append(stream)
            started[job.tag] = time.monotonic()
            processes[job.tag] = subprocess.Popen(
                job.argv,
                cwd=job.cwd,
                env=job.env,
                stdout=stream,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            print(f"== parallel start {job.tag}: log={out_dir / (job.tag + '.log')} ==", flush=True)
        sample_number = 0
        while any(process.poll() is None for process in processes.values()):
            time.sleep(sample_interval)
            sample_number += 1
            stats, trees = _process_stats({process.pid for process in processes.values() if process.poll() is None})
            fds = _fd_counts(trees) if sample_number % max(1, round(10 / sample_interval)) == 0 else {}
            combined_rss = 0
            for tag, process in processes.items():
                if process.poll() is not None:
                    finished.setdefault(tag, time.monotonic())
                rss_kib, cpu = stats.get(process.pid, (0, 0.0))
                combined_rss += rss_kib * 1024
                peak_rss[tag] = max(peak_rss[tag], rss_kib)
                peak_cpu[tag] = max(peak_cpu[tag], cpu)
                fd = fds.get(process.pid)
                if fd is not None:
                    peak_fd[tag] = max(peak_fd[tag] or 0, fd)
            samples_over_limit = samples_over_limit + 1 if combined_rss > max_rss_bytes else 0
            if samples_over_limit >= 2:
                resource_exceeded = True
                print(f"== parallel resource limit exceeded: RSS > {max_rss_bytes // 1024**2} MiB ==", flush=True)
                _stop_processes(processes)
                break
            if time.monotonic() - last_progress >= 30:
                active = ", ".join(tag for tag, process in processes.items() if process.poll() is None)
                print(f"== parallel running: {active}; sampled RSS={combined_rss // 1024**2} MiB ==", flush=True)
                last_progress = time.monotonic()
        for tag, process in processes.items():
            process.wait()
            finished.setdefault(tag, time.monotonic())
    except BaseException:
        _stop_processes(processes)
        raise
    finally:
        for stream in streams:
            stream.close()

    results: dict[str, JobResult] = {}
    for tag, process in processes.items():
        log = (out_dir / f"{tag}.log").read_text(errors="replace")
        summary_matches = re.findall(r"^=+ .* (?:passed|failed|error|skipped).* in [\d.]+s .* =+$", log, re.MULTILINE)
        coverage_matches = re.findall(r"Total coverage:\s*([\d.]+)%", log)
        results[tag] = JobResult(
            exit_code=process.returncode,
            wall_seconds=round(finished[tag] - started[tag], 2),
            sampled_peak_rss_mib=round(peak_rss[tag] / 1024, 1),
            sampled_peak_cpu_percent=round(peak_cpu[tag], 1),
            sampled_peak_fd=peak_fd[tag],
            pytest_summary=summary_matches[-1] if summary_matches else None,
            coverage_percent=float(coverage_matches[-1]) if coverage_matches else None,
        )
        print(f"== parallel result {tag}: exit={process.returncode} wall={results[tag].wall_seconds}s ==", flush=True)
    status = (
        "resource_limit"
        if resource_exceeded
        else "passed"
        if all(r.exit_code == 0 for r in results.values())
        else "failed"
    )
    (out_dir / "results.json").write_text(
        json.dumps(
            {"overall_status": status, "jobs": {tag: asdict(result) for tag, result in results.items()}}, indent=2
        )
        + "\n"
    )
    print(f"== parallel CI {status}: {out_dir / 'results.json'} ==", flush=True)
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--venv-root", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--versions", nargs="+", required=True)
    parser.add_argument("--probe", nargs="*", metavar="TEST_PATH")
    parser.add_argument("--max-rss-mib", type=int, default=10240)
    args = parser.parse_args()
    jobs = []
    for version in args.versions:
        tag = "py" + version.removeprefix("python")
        venv = args.venv_root.resolve() / tag
        env = os.environ.copy()
        env["PATH"] = f"{venv / 'bin'}{os.pathsep}{env.get('PATH', '')}"
        env["REDPOSTURE_COVERAGE_DIR"] = str(args.out.resolve() / tag / "coverage")
        env["PYTEST_ADDOPTS"] = (
            f"{env.get('PYTEST_ADDOPTS', '')} -o cache_dir={args.out.resolve() / tag / '.pytest_cache'}"
        )
        if args.probe is None:
            argv = ("bash", "scripts/run_ci_job.sh", "test")
        else:
            argv = (
                str(venv / "bin" / "python"),
                "-u",
                "-m",
                "pytest",
                "-vv",
                "-o",
                "faulthandler_timeout=180",
                "-o",
                "faulthandler_exit_on_timeout=true",
                "--cov=redposture_core",
                "--cov-report=term-missing",
                f"--cov-report=json:{args.out.resolve() / tag / 'coverage' / 'coverage.json'}",
                "--cov-fail-under=0",
                *args.probe,
            )
            (args.out / tag / "coverage").mkdir(parents=True, exist_ok=True)
        jobs.append(Job(tag, argv, env, args.source_root.resolve()))
    results = run_jobs(jobs, args.out, max_rss_bytes=args.max_rss_mib * 1024**2)
    return 0 if all(result.exit_code == 0 for result in results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
