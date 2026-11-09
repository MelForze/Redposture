#!/usr/bin/env python3
"""Short sequential shared-reader gate; offline inputs, never service throughput."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import statistics
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.compare_module_performance import run_sample, sample_order  # noqa: E402
from scripts.profile_processing_performance import CASES, expected_findings, payload_parts  # noqa: E402

# Absolute floors avoid declaring tiny sampling/import changes regressions.
# Relative tolerance and three times the observed range come from each pair's
# repeated samples, never from one successful candidate run.
METRICS = {
    "wall_seconds": (0.25, 0.25),
    "first_finding_seconds": (0.05, 0.25),
    "peak_rss_bytes": (32 * 1024 * 1024, 0.25),
    "sampled_peak_fd": (8, 0.25),
    "sampled_peak_temp_file_bytes": (1024 * 1024, 0.25),
}
IDENTITY = (
    "case",
    "megabytes",
    "input_bytes",
    "input_sha256",
    "profile_sha256",
    "environment",
    "container_image_id",
    "container_limits",
    "discover_time",
)


def summarize(rows: list[dict[str, Any]], repeats: int) -> dict[str, Any]:
    expected = {(repeat, side) for repeat, side in sample_order(repeats)}
    actual = [(r.get("repeat"), r.get("side")) for r in rows]
    if len(actual) != len(expected) or set(actual) != expected:
        return {"gate": "FAIL", "reason": "missing or duplicated sample, including warmups"}
    if any(r.get("exit") != 0 or not isinstance(r.get("result"), dict) for r in rows):
        return {"gate": "FAIL", "reason": "sample failed or result missing"}
    results = [r["result"] for r in rows]
    if any(any(key not in r or r[key] != results[0].get(key) for key in IDENTITY) for r in results):
        return {"gate": "FAIL", "reason": "instrument, input, environment or settings changed"}
    if results[0].get("case") not in CASES:
        return {"gate": "FAIL", "reason": "unknown input case"}
    known_findings = expected_findings(results[0]["case"], payload_parts(results[0]["case"])[3])
    for side in ("before", "after"):
        hashes = {r["result"].get("source_sha256") for r in rows if r["side"] == side}
        if len(hashes) != 1 or None in hashes:
            return {"gate": "FAIL", "reason": "source missing or changed during samples"}
    for r in results:
        if (
            r.get("quality") != "PASS"
            or r.get("source_status") != "complete"
            or r.get("no_ansi") is not True
            or r.get("temporary_directory_removed") is not True
            or r.get("fd_before") != r.get("fd_after")
            or r.get("threads_before") != r.get("threads_after")
            or any(key not in r for key in ("fd_before", "threads_before", "findings"))
            or any(type(r.get(key)) is not int or r[key] < 0 for key in ("fd_before", "threads_before"))
            or r["findings"] != known_findings
        ):
            return {"gate": "FAIL", "reason": "exact quality, completed coverage, clean output or cleanup failed"}
    measured = {
        side: [r["result"] for r in rows if r["side"] == side and r["repeat"] > 0] for side in ("before", "after")
    }
    metrics = {}
    for key, (floor, ratio) in METRICS.items():
        values = {side: [r.get(key) for r in group] for side, group in measured.items()}
        if any(
            type(v) not in (int, float) or not math.isfinite(v) or v < 0 for group in values.values() for v in group
        ):
            return {"gate": "FAIL", "reason": "resource/latency measurement missing or invalid: " + key}
        before, after = (statistics.median(values[s]) for s in ("before", "after"))
        spread = max(max(v) - min(v) for v in values.values())
        tolerance = max(floor, before * ratio, 3 * spread)
        metrics[key] = {
            "before_median": before,
            "after_median": after,
            "tolerance": tolerance,
            "sample_ranges": {s: max(v) - min(v) for s, v in values.items()},
            "status": "REGRESSION" if after - before > tolerance else "WITHIN_BUDGET",
        }
    return {
        "gate": "FAIL" if any(m["status"] == "REGRESSION" for m in metrics.values()) else "PASS",
        "metrics": metrics,
        "repeats": repeats,
        "warmups_excluded": True,
        "scope": "shared reader, exact known findings, not network/product or production recall",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--after", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--case", choices=CASES, default="json-stream")
    parser.add_argument("--megabytes", type=int, choices=(1, 10, 100), default=10)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--container-image", required=True)
    args = parser.parse_args()
    try:
        schedule = sample_order(args.repeats)
    except ValueError as exc:
        parser.error(str(exc))
    if args.output.exists():
        parser.error("output must be new; never reuse samples silently")
    sources = {s: getattr(args, s).resolve() for s in ("before", "after")}
    if any(not (s / "redposture_core/__init__.py").is_file() for s in sources.values()):
        parser.error("source snapshot missing")
    args.output.mkdir(parents=True)
    instrument = args.output / "instrument"
    instrument.mkdir()
    checksums = {}
    for path in (
        Path(__file__).resolve(),
        ROOT / "scripts/profile_processing_performance.py",
        ROOT / "scripts/performance_container.py",
        ROOT / "scripts/compare_module_performance.py",
    ):
        content = path.read_bytes()
        (instrument / path.name).write_bytes(content)
        checksums[path.name] = hashlib.sha256(content).hexdigest()
    (instrument / "MANIFEST.json").write_text(json.dumps(checksums, indent=2) + "\n")
    report: dict[str, Any] = {"status": "RUNNING", "samples": [], "case": args.case, "megabytes": args.megabytes}
    for repeat, side in schedule:
        destination = args.output / f"{repeat}-{side}.json"
        command = [
            sys.executable,
            str(ROOT / "scripts/profile_processing_performance.py"),
            "--source",
            str(sources[side]),
            "--output",
            str(destination),
            "--case",
            args.case,
            "--megabytes",
            str(args.megabytes),
            "--container-image",
            args.container_image,
        ]
        sample = run_sample(command, destination)
        sample.update(repeat=repeat, side=side)
        report["samples"].append(sample)
        if sample["unsafe_to_continue"]:
            report.update(status="STOPPED_CLEANUP")
        (args.output / "results.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"repeat": repeat, "side": side, "exit": sample["exit"]}), flush=True)
        if sample["unsafe_to_continue"]:
            return 1
    report["comparison"] = summarize(report["samples"], args.repeats)
    report["status"] = report["comparison"]["gate"]
    (args.output / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["comparison"]), flush=True)
    return int(report["status"] != "PASS")


if __name__ == "__main__":
    raise SystemExit(main())
