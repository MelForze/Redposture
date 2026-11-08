#!/usr/bin/env python3
"""Opt-in sequential before/after matrix; protocol fixtures, not physical hosts.

Run a fresh limited Linux container for each sample. All modules stay in the
report even when a sample fails; a missing result never becomes a PASS.
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.performance_contracts import compare_profiles  # noqa: E402
from scripts.profile_module_performance import AUTH_SURFACE_CHOICES, source_hash  # noqa: E402


def sample_order(repeats: int) -> list[tuple[int, str]]:
    if repeats < 3 or repeats > 20:
        raise ValueError("3..20 measured repeats required, plus one warmup")
    return [
        (repeat, side)
        for repeat in range(repeats + 1)
        for side in (("before", "after") if repeat % 2 == 0 else ("after", "before"))
    ]


def summarize_samples(rows: list[dict[str, Any]], repeats: int) -> dict[str, Any]:
    measured = [row for row in rows if row["repeat"] > 0]
    groups = {side: [row for row in measured if row["side"] == side] for side in ("before", "after")}
    if any(len(values) != repeats for values in groups.values()):
        return {"gate": "FAIL", "reason": "missing measured samples"}
    if any(not isinstance(row.get("result"), dict) for row in measured):
        return {"gate": "FAIL", "reason": "a sample did not produce a result; inspect its log"}
    before = [row["result"] for row in groups["before"]]
    after = [row["result"] for row in groups["after"]]
    for side in ("before", "after"):
        warmups = [row for row in rows if row["repeat"] == 0 and row["side"] == side]
        if len(warmups) != 1 or not isinstance(warmups[0].get("result"), dict):
            return {"gate": "FAIL", "reason": "missing warmup result"}
    if any(row.get("exit") != 0 and row["result"].get("quality") == "PASS" for row in rows):
        return {"gate": "FAIL", "reason": "process failure contradicts a passing result artifact"}
    if all(result.get("quality") == "NOT_APPLICABLE" for result in before + after):
        if any(row.get("exit") != 0 for row in rows):
            return {"gate": "FAIL", "reason": "non-applicable sample returned a failure"}
        reasons = {result.get("reason") for result in before + after}
        return {"gate": "NOT_APPLICABLE", "reasons": sorted(str(reason) for reason in reasons)}
    try:
        comparison = compare_profiles(before, after)
    except ValueError as exc:
        return {"gate": "FAIL", "reason": str(exc)}
    if any(row.get("exit") != 0 for row in groups["after"]):
        comparison.update(gate="FAIL", reason="candidate process returned nonzero exit")
    warmups = [row for row in rows if row["repeat"] == 0 and row["side"] == "after"]
    if len(warmups) != 1 or any(
        row.get("exit") != 0 or not isinstance(row.get("result"), dict) or row["result"].get("quality") != "PASS"
        for row in warmups
    ):
        comparison.update(gate="FAIL", reason="candidate warmup did not pass")
    metrics = {}
    for key in ("cpu_seconds", "peak_rss_bytes", "fd_peak", "threads_peak", "first_finding_seconds", "throughput"):
        metrics[key] = {
            side: statistics.median(values) if values else None
            for side, results in (("before", before), ("after", after))
            for values in [[result[key] for result in results if isinstance(result.get(key), (int, float))]]
        }
    comparison["medians"] = metrics
    comparison["request_samples"] = {
        "before": [row.get("requests") for row in before],
        "after": [row.get("requests") for row in after],
    }
    comparison["warmups_excluded"] = True
    return comparison


def run_sample(command: list[str], destination: Path) -> dict[str, Any]:
    unsafe_to_continue = False
    try:
        process = subprocess.run(command, capture_output=True, text=True, timeout=720)
        log = process.stdout + process.stderr
        code = process.returncode
    except subprocess.TimeoutExpired as exc:
        log = str(exc)
        code = 124
        unsafe_to_continue = True
    except OSError as exc:
        log = str(exc)
        code = 127
    destination.with_suffix(".log").write_text(log)
    try:
        result = json.loads(destination.read_text()) if destination.exists() else None
    except (OSError, ValueError):
        result = None
    lease = destination.with_suffix(".container.json")
    if lease.exists():
        try:
            unsafe_to_continue |= json.loads(lease.read_text()).get("cleanup") != "PASS"
        except (OSError, ValueError):
            unsafe_to_continue = True
    return {
        "exit": code,
        "command": command,
        "artifact": destination.name,
        "result": result,
        "unsafe_to_continue": unsafe_to_continue,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--after", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--modules", nargs="+", default=["all"])
    parser.add_argument(
        "--models", nargs="+", choices=("positive", "mixed", "closed", "foreign", "slow"), default=["mixed"]
    )
    parser.add_argument("--mode", choices=("detect", "credentials", "defcreds", "actions"), default="detect")
    parser.add_argument("--auth-case", choices=("invalid", "valid", "limited"), default="invalid")
    parser.add_argument("--auth-surface", choices=AUTH_SURFACE_CHOICES, default="default")
    parser.add_argument("--http-peer", choices=("threaded", "async", "process"), default="async")
    parser.add_argument("--native-peer", choices=("threaded", "async", "process"), default="threaded")
    parser.add_argument("--target-style", choices=("auto", "http"), default="auto")
    parser.add_argument("--format", choices=("txt", "json"), default="txt")
    parser.add_argument("--save", action="store_true")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--auto-concurrency", action="store_true")
    parser.add_argument("--action", action="append", default=[])
    parser.add_argument("--targets", type=int, default=1000)
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--concurrency", type=int, default=64)
    parser.add_argument("--timeout", type=float, default=0.5)
    parser.add_argument("--delay-ms", type=float, default=2)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--seed", type=int, default=20261107)
    parser.add_argument("--container-image", required=True)
    args = parser.parse_args()
    try:
        schedule = sample_order(args.repeats)
    except ValueError as exc:
        parser.error(str(exc))
    if (
        not 1 <= args.targets <= 1_000_000
        or min(args.workers, args.concurrency) < 1
        or args.timeout <= 0
        or args.delay_ms < 0
    ):
        parser.error("positive bounded targets/workers/concurrency/timeout and nonnegative delay required")
    if args.output.exists():
        parser.error("output must be new; old samples must not be silently reused")
    if args.mode == "detect" and args.auth_case != "invalid":
        parser.error("detect-only mode cannot verify valid/limited credentials")
    if args.mode == "actions" and not args.action:
        parser.error("actions mode requires explicit --action arguments")
    sources = {side: getattr(args, side).resolve() for side in ("before", "after")}
    for source in sources.values():
        if not (source / "redposture_core/module_registry.py").is_file():
            parser.error("source snapshot is missing the module registry")
    from redposture_core.module_registry import AUDIT_MODULE_NAMES

    modules = list(AUDIT_MODULE_NAMES) if args.modules == ["all"] else args.modules
    if len(modules) != len(set(modules)) or set(modules) - set(AUDIT_MODULE_NAMES):
        parser.error("unknown or duplicate module")
    if len(set(args.models)) != len(args.models):
        parser.error("duplicate model")
    args.output.mkdir(parents=True)
    expected_sources = {side: source_hash(path) for side, path in sources.items()}
    report: dict[str, Any] = {
        "status": "RUNNING",
        "source_sha256": expected_sources,
        "fixture": "protocol emulation, not real products or physical hosts",
        "samples_per_group": len(schedule),
        "groups": [
            {"module": module, "model": model, "mode": args.mode, "samples": [], "status": "PENDING"}
            for module in modules
            for model in args.models
        ],
    }
    (args.output / "comparison-runner.py").write_bytes(Path(__file__).read_bytes())
    failed = False
    for group in report["groups"]:
        module, model = group["module"], group["model"]
        label = f"{module}-{model}-{args.mode}"
        group["status"] = "RUNNING"
        for repeat, side in schedule:
            destination = args.output / f"{label}-{repeat}-{side}.json"
            command = [
                sys.executable,
                str(ROOT / "scripts/profile_module_performance.py"),
                "--source",
                str(sources[side]),
                "--module",
                module,
                "--model",
                model,
                "--mode",
                args.mode,
                "--auth-case",
                args.auth_case,
                "--auth-surface",
                args.auth_surface,
                "--http-peer",
                args.http_peer,
                "--native-peer",
                args.native_peer,
                "--target-style",
                args.target_style,
                "--format",
                args.format,
                "--targets",
                str(args.targets),
                "--workers",
                str(args.workers),
                "--concurrency",
                str(args.concurrency),
                "--timeout",
                str(args.timeout),
                "--delay-ms",
                str(args.delay_ms),
                "--seed",
                str(args.seed),
                "--container-image",
                args.container_image,
                "--output",
                str(destination),
            ]
            for flag in ("save", "debug", "auto_concurrency"):
                if getattr(args, flag):
                    command.append("--" + flag.replace("_", "-"))
            command.extend("--action=" + value for value in args.action)
            row = run_sample(command, destination)
            row.update(repeat=repeat, side=side)
            result = row.get("result")
            if isinstance(result, dict) and result.get("quality") != "NOT_APPLICABLE":
                if result.get("source_sha256") != expected_sources[side]:
                    row.update(exit=1, error="source changed since matrix start")
                    result.update(quality="FAIL", source_changed=True)
            group["samples"].append(row)
            if row["unsafe_to_continue"]:
                group.update(
                    status="FAIL",
                    comparison={"gate": "FAIL", "reason": "sample timeout or unverified container cleanup"},
                )
                report["status"] = "STOPPED_CLEANUP"
                (args.output / "results.json").write_text(json.dumps(report, indent=2) + "\n")
                return 1
            (args.output / "results.json").write_text(json.dumps(report, indent=2) + "\n")
            print(
                json.dumps(
                    {
                        "case": label,
                        "repeat": repeat,
                        "side": side,
                        "exit": row["exit"],
                        "quality": result.get("quality") if isinstance(result, dict) else "NO_RESULT",
                    }
                ),
                flush=True,
            )
        group["comparison"] = summarize_samples(group["samples"], args.repeats)
        group["status"] = group["comparison"]["gate"]
        failed |= group["comparison"]["gate"] not in {"PASS", "NOT_APPLICABLE"}
        print(json.dumps({"case": label, "comparison": group["comparison"]}), flush=True)
    report["status"] = "FAIL" if failed else "PASS"
    (args.output / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
