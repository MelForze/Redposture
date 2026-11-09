#!/usr/bin/env python3
"""Sequential short performance gate over changed paths and protocol representatives.

Wire samples use real CLI/clients against authored loopback protocol peers in
fresh offline containers. DTO accuracy and shared-reader cost are separate
checks; neither is presented as full product enumeration or production recall.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import statistics
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.compare_module_performance import run_sample, sample_order, summarize_samples  # noqa: E402
from scripts.performance_selection import ACTION_SETTINGS, ACTIONS, selection  # noqa: E402
from scripts.profile_module_performance import PROFILE_FILES, inventory, source_hash  # noqa: E402
from scripts.profile_native_data_performance import MODULES as NATIVE_DATA_MODULES  # noqa: E402

RESOURCE_METRICS = {"first_finding_seconds": (0.05, 0.25), "peak_rss_bytes": (32 * 1024**2, 0.25), "fd_peak": (8, 0.25)}


def retain_controls(root: Path, output: Path) -> dict[str, str]:
    """Retain the actual controller, peers and labelled corpus, not only hashes."""
    names = set(PROFILE_FILES) | {
        "scripts/check_performance_regressions.py",
        "scripts/performance_selection.py",
        "scripts/profile_native_data_performance.py",
        "scripts/profile_workflow_performance.py",
        "scripts/compare_module_performance.py",
        "scripts/compare_processing_performance.py",
        "scripts/profile_processing_performance.py",
        "scripts/performance_container.py",
        "scripts/discovery_accuracy.py",
        "scripts/discovery_ui_accuracy.py",
    }
    names.update(str(p.relative_to(root)) for p in (root / "tests/fixtures/discovery_accuracy").glob("*.json"))
    files = {}
    for name in sorted(names):
        payload = (root / name).read_bytes()
        target = output / "controls" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and target.read_bytes() != payload:
            raise ValueError("retained control changed: " + name)
        if not target.exists():
            target.write_bytes(payload)
        files[name] = hashlib.sha256(payload).hexdigest()
    (output / "controls/MANIFEST.json").write_text(json.dumps(files, indent=2) + "\n")
    return files


def resource_gate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    groups = {
        side: [r["result"] for r in rows if r["side"] == side and r["repeat"] > 0] for side in ("before", "after")
    }
    metrics = {}
    for key, (floor, ratio) in RESOURCE_METRICS.items():
        values = {s: [r.get(key) for r in group] for s, group in groups.items()}
        if any(not v for v in values.values()) or any(
            type(v) not in (int, float) or not math.isfinite(v) or v < 0 for group in values.values() for v in group
        ):
            return {"gate": "FAIL", "reason": "missing/invalid resource or first-finding evidence: " + key}
        before, after = (statistics.median(values[s]) for s in ("before", "after"))
        tolerance = max(floor, ratio * before, 3 * max(max(v) - min(v) for v in values.values()))
        metrics[key] = {
            "before_median": before,
            "after_median": after,
            "tolerance": tolerance,
            "regression": after - before > tolerance,
        }
    return {"gate": "FAIL" if any(m["regression"] for m in metrics.values()) else "PASS", "metrics": metrics}


def check_artifact(name: str, directory: Path, routes: list[str]) -> bool:
    """Exit zero without complete current evidence is a failed check."""
    path = directory / ("shared-processing/results.json" if name == "shared-processing" else name + ".json")
    try:
        record = json.loads(path.read_bytes())
        if record.get("status") != "PASS":
            return False
        if name == "shared-processing":
            return record.get("comparison", {}).get("gate") == "PASS" and bool(record.get("samples"))
        if name == "discover-quality":
            return (
                set(record.get("routes", [])) == set(routes)
                and record.get("failures") == 0
                and type(record.get("cases")) is int
                and record["cases"] > 0
                and bool(record.get("corpus_sha256"))
                and len(record.get("results", [])) == len(routes) * record["cases"]
                and len({(r["route"], r["case"]) for r in record["results"]}) == len(record["results"])
                and {r["route"] for r in record["results"]} == set(routes)
                and all(
                    r.get("status") == r.get("expected_status")
                    and all(
                        r.get("metrics", {}).get(k) == 0
                        for k in ("fn", "fp", "duplicates", "value_missing", "value_extra", "confidence_mismatch")
                    )
                    for r in record["results"]
                )
            )
        return bool(record.get("cases")) and all(
            case.get("accuracy", {}).get("status_ok") is True
            and all(case["accuracy"].get(key) == 0 for key in ("fn", "fp", "duplicates"))
            for case in record["cases"]
        )
    except (OSError, ValueError, TypeError, AttributeError, KeyError):
        return False


def summarize_native(rows: list[dict[str, Any]], repeats: int) -> dict[str, Any]:
    expected = set(sample_order(repeats))
    if len(rows) != len(expected) or {(r.get("repeat"), r.get("side")) for r in rows} != expected:
        return {"gate": "FAIL", "reason": "missing/duplicate native data samples"}
    if any(r.get("exit") != 0 or not isinstance(r.get("result"), dict) for r in rows):
        return {"gate": "FAIL", "reason": "native data process/result failed"}
    results = [r["result"] for r in rows]
    for result in results:
        if (
            result.get("quality") != "PASS"
            or result.get("cleanup") != "PASS"
            or not result.get("result_sha256")
            or not (result["result_sha256"] == result.get("expected_sha256") == result.get("input_sha256"))
        ):
            return {"gate": "FAIL", "reason": "native data known-answer or cleanup failed"}
    fields = (
        "module",
        "mode",
        "rows",
        "scope",
        "profile_sha256",
        "environment",
        "container_image_id",
        "container_limits",
        "result_sha256",
    )
    if any(any(k not in r or r[k] != results[0].get(k) for k in fields) for r in results):
        return {"gate": "FAIL", "reason": "native data identity/instrument/values changed"}
    for side in ("before", "after"):
        hashes = {r["result"].get("source_sha256") for r in rows if r["side"] == side}
        if len(hashes) != 1 or None in hashes:
            return {"gate": "FAIL", "reason": "native data source changed"}
    values = {
        s: [r["result"].get("wall_seconds") for r in rows if r["side"] == s and r["repeat"] > 0]
        for s in ("before", "after")
    }
    if any(type(v) not in (int, float) or not math.isfinite(v) or v <= 0 for vs in values.values() for v in vs):
        return {"gate": "FAIL", "reason": "invalid native data wall time"}
    before, after = (statistics.median(values[s]) for s in ("before", "after"))
    tolerance = max(0.25, 0.25 * before, 3 * max(max(v) - min(v) for v in values.values()))
    return {
        "gate": "FAIL" if after - before > tolerance else "PASS",
        "before_median_seconds": before,
        "after_median_seconds": after,
        "timing_threshold_seconds": tolerance,
        "same_results": True,
        "warmups_excluded": True,
        "scope": results[0]["scope"],
    }


def recipes(plan: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Keep unprofiled transport phases visible; never relabel them product N/A."""
    catalog = {r["module"]: r for r in plan["catalog"]}
    cases: list[dict[str, Any]] = []
    boundaries = []
    for selected in plan["modules"]:
        module = selected["module"]
        cases.append({"id": module + "-detect", "module": module, "mode": "detect"})
        if catalog[module]["auth"]["available"]:
            cases.append(
                {
                    "id": module + "-auth",
                    "module": module,
                    "mode": "credentials",
                    "auth_case": "invalid",
                    **({"auth_surface": "grpc-auth", "native_peer": "process"} if module == "grpc" else {}),
                }
            )
            if module == "redis":
                # At 64 roots a 20 ms FD sampler aliases the short startup
                # burst. A longer unchanged workload exposes the steady peak.
                cases[-1]["targets"] = 512
        if module in ACTIONS:
            cases.append(
                {
                    "id": module + "-data",
                    "module": module,
                    "mode": "actions",
                    "auth_case": "valid",
                    "actions": ACTIONS[module],
                    **ACTION_SETTINGS.get(module, {}),
                }
            )
        elif module == "docker":
            cases.append(
                {
                    "id": "docker-data",
                    "module": module,
                    "mode": "actions",
                    "access_case": "open",
                    "actions": ["--containers", "--images"],
                }
            )
        elif module == "kafka":
            cases.append(
                {
                    "id": "kafka-ui-data",
                    "module": module,
                    "mode": "actions",
                    "auth_case": "valid",
                    "auth_surface": "provectus-ui",
                    "actions": ["--show-topics"],
                }
            )
        elif module in NATIVE_DATA_MODULES:
            cases.append({"id": module + "-data-adapter", "module": module, "native_data": True})
            boundaries.append(
                {
                    "module": module,
                    "phase": "data transport",
                    "status": "NOT_PROFILED",
                    "reason": "No short positive transport recipe selected. Shared DTO/reader quality is checked separately; existing full CI/QA stays required.",
                }
            )
    for workflow in plan["workflows"]:
        cases.append({"id": "workflow-" + workflow, "workflow": workflow})
    return cases, boundaries


def command(case: dict[str, Any], source: Path, output: Path, args: Any) -> list[str]:
    if case.get("native_data"):
        return [
            sys.executable,
            str(ROOT / "scripts/profile_native_data_performance.py"),
            "--source",
            str(source),
            "--output",
            str(output),
            "--module",
            case["module"],
            "--rows",
            "128",
            "--container-image",
            args.container_image,
        ]
    workflow = case.get("workflow")
    argv = [
        sys.executable,
        str(
            ROOT / ("scripts/profile_workflow_performance.py" if workflow else "scripts/profile_module_performance.py")
        ),
        "--source",
        str(source),
        "--output",
        str(output),
        "--container-image",
        args.container_image,
        "--targets",
        str(case.get("targets", args.targets)),
        "--model",
        "mixed",
        "--workers",
        "8",
        "--timeout",
        "0.5",
        "--delay-ms",
        "2",
    ]
    if workflow:
        return argv + ["--workflow", workflow]
    argv += [
        "--module",
        case["module"],
        "--mode",
        case["mode"],
        "--concurrency",
        "32",
        "--http-peer",
        "process",
        "--native-peer",
        case.get("native_peer", "process"),
        "--format",
        "json",
        "--save",
    ]
    for key in ("auth_case", "auth_surface", "access_case"):
        if key in case:
            argv += ["--" + key.replace("_", "-"), case[key]]
    argv += ["--action=" + action for action in case.get("actions", [])]
    return argv


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--after", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--container-image", required=True)
    parser.add_argument("--changed-file", action="append")
    parser.add_argument("--all-modules", action="store_true")
    parser.add_argument("--plan", action="store_true")
    parser.add_argument(
        "--case", action="append", help="Explicit focused rerun; report keeps the full plan and selected IDs"
    )
    parser.add_argument("--targets", type=int, default=64)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    try:
        schedule = sample_order(args.repeats)
    except ValueError as exc:
        parser.error(str(exc))
    if args.output.exists() or not 20 <= args.targets <= 10000:
        parser.error("new output and 20..10000 logical targets required")
    sources = {s: getattr(args, s).resolve() for s in ("before", "after")}
    if any(not (p / "redposture_core/module_registry.py").is_file() for p in sources.values()):
        parser.error("source snapshot missing")
    changed = args.changed_file
    if changed is None:
        changed = []
        for cmd in (
            ["git", "diff", "--name-only", "-z", "HEAD", "--"],
            ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        ):
            changed += [p for p in subprocess.check_output(cmd, cwd=sources["after"]).decode().split("\0") if p]
    # inventory() activates exactly one source; other trees run in fresh child processes.
    plan = selection(inventory(sources["after"]), changed, all_modules=args.all_modules)
    cases, boundaries = recipes(plan)
    expected_case_ids = [c["id"] for c in cases]
    if args.case:
        if set(args.case) - set(expected_case_ids) or len(args.case) != len(set(args.case)):
            parser.error("unknown/duplicate case filter")
        cases = [c for c in cases if c["id"] in args.case]
    args.output.mkdir(parents=True)
    report: dict[str, Any] = {
        "status": "PLAN_ONLY" if args.plan else "RUNNING",
        "selection": plan,
        "transport_boundaries": boundaries,
        "cases": [{**c, "status": "PENDING", "samples": []} for c in cases],
        "checks": [],
        "full_plan_case_ids": expected_case_ids,
        "focused_filter": args.case,
    }
    report_path = args.output / "results.json"

    def save() -> None:
        report_path.write_text(json.dumps(report, indent=2) + "\n")

    save()
    if args.plan:
        print(json.dumps({"status": report["status"], "cases": len(cases), "transport_boundaries": boundaries}))
        return 0
    report["control_files"] = retain_controls(ROOT, args.output)
    hashes = {s: source_hash(p) for s, p in sources.items()}
    for case in report["cases"]:
        for repeat, side in schedule:
            output = args.output / f"{case['id']}-{repeat}-{side}.json"
            row = run_sample(command(case, sources[side], output, args), output)
            row.update(repeat=repeat, side=side)
            if isinstance(row.get("result"), dict) and row["result"].get("source_sha256") != hashes[side]:
                row.update(exit=1)
                row["result"]["quality"] = "FAIL"
            case["samples"].append(row)
            save()
            print(json.dumps({"case": case["id"], "repeat": repeat, "side": side, "exit": row["exit"]}), flush=True)
            if row["unsafe_to_continue"]:
                report.update(status="STOPPED_CLEANUP")
                save()
                return 1
        case["comparison"] = (
            summarize_native(case["samples"], args.repeats)
            if case.get("native_data")
            else summarize_samples(case["samples"], args.repeats)
        )
        if case["comparison"]["gate"] == "PASS":
            case["resources"] = resource_gate(case["samples"])
        case["status"] = (
            "PASS"
            if case["comparison"]["gate"] == "PASS" and case.get("resources", {}).get("gate") == "PASS"
            else "FAIL"
        )
        save()
    # Exact quality of every selected discover DTO/reader and every supported UI,
    # plus paired shared JSON cost, are distinct from the wire timings above.
    commands = []
    if plan["discover_routes"]:
        commands.append(
            (
                "discover-quality",
                [
                    sys.executable,
                    str(ROOT / "scripts/discovery_accuracy.py"),
                    "--out",
                    str(args.output / "discover-quality.json"),
                    *[v for route in plan["discover_routes"] for v in ("--route", route)],
                ],
            )
        )
        commands.append(
            (
                "ui-quality",
                [
                    sys.executable,
                    str(ROOT / "scripts/discovery_ui_accuracy.py"),
                    "--out",
                    str(args.output / "ui-quality.json"),
                ],
            )
        )
    if plan["shared_processing"]:
        commands.append(
            (
                "shared-processing",
                [
                    sys.executable,
                    str(ROOT / "scripts/compare_processing_performance.py"),
                    "--before",
                    str(sources["before"]),
                    "--after",
                    str(sources["after"]),
                    "--output",
                    str(args.output / "shared-processing"),
                    "--container-image",
                    args.container_image,
                    "--repeats",
                    str(args.repeats),
                ],
            )
        )
    for name, argv in commands:
        with (args.output / (name + ".log")).open("w") as log:
            result = subprocess.run(
                argv, stdout=log, stderr=subprocess.STDOUT, env=dict(os.environ, PYTHONPATH=str(sources["after"]))
            )
        report["checks"].append(
            {
                "name": name,
                "exit": result.returncode,
                "artifact_verified": check_artifact(name, args.output, plan["discover_routes"]),
            }
        )
        save()
    report["sources_unchanged"] = all(source_hash(sources[s]) == hashes[s] for s in sources)
    report["controls_unchanged"] = all(
        hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest
        for name, digest in report["control_files"].items()
    )
    report["status"] = (
        "PASS"
        if report["sources_unchanged"]
        and report["controls_unchanged"]
        and all(c["status"] == "PASS" for c in report["cases"])
        and all(c["exit"] == 0 and c["artifact_verified"] for c in report["checks"])
        else "FAIL"
    )
    save()
    print(json.dumps({"status": report["status"], "cases": len(cases), "report": str(report_path)}))
    return int(report["status"] != "PASS")


if __name__ == "__main__":
    raise SystemExit(main())
