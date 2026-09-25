#!/usr/bin/env python3
"""Run the opt-in output QA profile and always write machine-readable reports."""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ARTIFACT = Path("/tmp") / f"redposture_output_qa_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
AUDIT_MODULES = (
    "airflow",
    "clickhouse",
    "consul",
    "docker",
    "elastic",
    "etcd",
    "gitlab",
    "grafana",
    "grpc",
    "kafka",
    "keeper",
    "kubeapi",
    "minio",
    "mongodb",
    "oracle",
    "postgres",
    "proxmox",
    "qdrant",
    "rabbitmq",
    "redis",
    "registry",
    "zookeeper",
)


@dataclass(frozen=True)
class Stage:
    name: str
    category: str
    command: tuple[str, ...]
    pytest: bool = False
    requires_docker: bool = False
    environment: dict[str, str] = field(default_factory=dict)


@dataclass
class StageResult:
    name: str
    category: str
    command: str
    duration_seconds: float
    status: str
    returncode: int | None
    log: str
    junit: str | None = None
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    errors: int = 0
    failures: list[dict[str, str]] = field(default_factory=list)
    module_counts: dict[str, dict[str, int]] = field(default_factory=dict)
    reason: str | None = None


def _docker_available() -> tuple[bool, str | None]:
    if os.environ.get("REDPOSTURE_OUTPUT_QA_SKIP_DOCKER") == "1":
        return False, "Docker stages disabled by REDPOSTURE_OUTPUT_QA_SKIP_DOCKER=1"
    if shutil.which("docker") is None:
        return False, "docker executable is unavailable"
    try:
        completed = subprocess.run(
            ("docker", "compose", "version"),
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    if completed.returncode != 0:
        return False, (completed.stderr or completed.stdout).strip() or "docker compose is unavailable"
    return True, None


def _pytest_counts(path: Path) -> tuple[dict[str, int], list[dict[str, str]]]:
    if not path.is_file():
        return {"passed": 0, "failed": 0, "skipped": 0, "errors": 0}, []
    root = ET.parse(path).getroot()
    cases = list(root.iter("testcase"))
    counts = {"passed": 0, "failed": 0, "skipped": 0, "errors": 0}
    failures: list[dict[str, str]] = []
    for case in cases:
        skipped = case.find("skipped")
        failure = case.find("failure")
        error = case.find("error")
        file_name = str(case.get("file") or "").strip()
        owner = file_name or str(case.get("classname") or "").replace(".", "/") + ".py"
        node = f"{owner}::{case.get('name', '')}".strip(":")
        if skipped is not None:
            counts["skipped"] += 1
        elif failure is not None:
            counts["failed"] += 1
            failures.append(
                {
                    "nodeid": node,
                    "message": str(failure.get("message") or "assertion failed"),
                    "details": str(failure.text or "").strip(),
                }
            )
        elif error is not None:
            counts["errors"] += 1
            failures.append(
                {
                    "nodeid": node,
                    "message": str(error.get("message") or "test error"),
                    "details": str(error.text or "").strip(),
                }
            )
        else:
            counts["passed"] += 1
    return counts, failures


def _pytest_module_counts(path: Path) -> dict[str, dict[str, int]]:
    if not path.is_file():
        return {}
    summary: dict[str, dict[str, int]] = {}
    for case in ET.parse(path).getroot().iter("testcase"):
        file_name = str(case.get("file") or "").strip()
        owner = file_name or str(case.get("classname") or "").replace(".", "/") + ".py"
        nodeid = f"{owner}::{case.get('name', '')}".strip(":")
        module = _module_from_nodeid(nodeid)
        counts = summary.setdefault(module, {"passed": 0, "failed": 0, "skipped": 0, "errors": 0})
        if case.find("skipped") is not None:
            counts["skipped"] += 1
        elif case.find("failure") is not None:
            counts["failed"] += 1
        elif case.find("error") is not None:
            counts["errors"] += 1
        else:
            counts["passed"] += 1
    return summary


def _run_stage(stage: Stage, artifact: Path, docker_available: bool, docker_reason: str | None) -> StageResult:
    log_path = artifact / f"{stage.name}.log"
    junit_path = artifact / f"{stage.name}.xml" if stage.pytest else None
    command = list(stage.command)
    if junit_path is not None:
        command.extend(("--junitxml", str(junit_path)))
    display = shlex.join(command)
    reason: str | None
    if stage.requires_docker and not docker_available:
        reason = docker_reason or "Docker is unavailable"
        log_path.write_text(f"SKIPPED: {reason}\n", encoding="utf-8")
        return StageResult(
            name=stage.name,
            category=stage.category,
            command=display,
            duration_seconds=0.0,
            status="skipped",
            returncode=None,
            log=str(log_path),
            reason=reason,
        )

    environment = os.environ.copy()
    environment.update(stage.environment)
    started = time.monotonic()
    try:
        with log_path.open("w", encoding="utf-8") as stream:
            completed = subprocess.run(
                command,
                cwd=ROOT,
                env=environment,
                stdout=stream,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )
        returncode: int | None = completed.returncode
        status = "passed" if completed.returncode == 0 else "failed"
        reason = None
    except OSError as exc:
        returncode = None
        status = "failed"
        reason = str(exc)
        log_path.write_text(f"ERROR: {exc}\n", encoding="utf-8")
    duration = round(time.monotonic() - started, 3)
    counts, failures = _pytest_counts(junit_path) if junit_path is not None else ({}, [])
    module_counts = _pytest_module_counts(junit_path) if junit_path is not None else {}
    return StageResult(
        name=stage.name,
        category=stage.category,
        command=display,
        duration_seconds=duration,
        status=status,
        returncode=returncode,
        log=str(log_path),
        junit=str(junit_path) if junit_path is not None else None,
        passed=counts.get("passed", 0),
        failed=counts.get("failed", 0),
        skipped=counts.get("skipped", 0),
        errors=counts.get("errors", 0),
        failures=failures,
        module_counts=module_counts,
        reason=reason,
    )


def _module_from_nodeid(nodeid: str) -> str:
    match = re.search(r"\[([a-z][a-z0-9_]*)(?:-|\])", nodeid)
    if match and match.group(1) in AUDIT_MODULES:
        return match.group(1)
    lowered = nodeid.lower()
    for module in AUDIT_MODULES:
        if module in lowered:
            return module
    return "shared"


def _defects(results: list[StageResult]) -> list[dict[str, str]]:
    defects: list[dict[str, str]] = []
    for result in results:
        for failure in result.failures:
            details = failure["details"]
            assertion = "\n".join(line for line in details.splitlines() if line.startswith("E "))
            marker_args = ("-m", "local_output_audit") if result.category in {"known-defects", "load"} else ()
            reproduce = failure.get("reproduce") or shlex.join(
                (sys.executable, "-m", "pytest", "-q", *marker_args, failure["nodeid"])
            )
            defects.append(
                {
                    "module": failure.get("module") or _module_from_nodeid(failure["nodeid"]),
                    "class": result.category,
                    "test": failure["nodeid"],
                    "reproduce": reproduce,
                    "actual_and_expected": failure.get("actual_and_expected") or assertion or failure["message"],
                    "details": details[-4000:],
                    "log": result.log,
                }
            )
        if result.status == "failed" and not result.failures:
            defects.append(
                {
                    "module": "shared",
                    "class": result.category,
                    "test": result.name,
                    "reproduce": result.command,
                    "actual_and_expected": result.reason or f"command exited with {result.returncode}",
                    "details": "See the stage log for complete output.",
                    "log": result.log,
                }
            )
    return defects


def _write_reports(artifact: Path, results: list[StageResult], started_at: str) -> None:
    defects = _defects(results)
    totals = {key: sum(getattr(result, key) for result in results) for key in ("passed", "failed", "skipped", "errors")}
    skipped_stands = [
        {"stage": result.name, "reason": result.reason or "unavailable"}
        for result in results
        if result.status == "skipped"
    ]
    local_failing_tests = [
        failure["nodeid"] for result in results if result.category == "known-defects" for failure in result.failures
    ]
    summary_by_class: dict[str, dict[str, int]] = {}
    summary_by_module: dict[str, dict[str, int]] = {}
    for result in results:
        class_counts = summary_by_class.setdefault(
            result.category, {"passed": 0, "failed": 0, "skipped": 0, "errors": 0}
        )
        for key in class_counts:
            class_counts[key] += int(getattr(result, key))
        for module, counts in result.module_counts.items():
            module_summary = summary_by_module.setdefault(module, {"passed": 0, "failed": 0, "skipped": 0, "errors": 0})
            for key in module_summary:
                module_summary[key] += int(counts.get(key, 0))
    payload: dict[str, Any] = {
        "started_at": started_at,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "artifact_dir": str(artifact),
        "summary": {
            **totals,
            "stages_passed": sum(result.status == "passed" for result in results),
            "stages_failed": sum(result.status == "failed" for result in results),
            "stages_skipped": sum(result.status == "skipped" for result in results),
            "defects": len(defects),
        },
        "stages": [asdict(result) for result in results],
        "summary_by_class": summary_by_class,
        "summary_by_module": summary_by_module,
        "defects": defects,
        "skipped_stands": skipped_stands,
        "local_failing_tests": local_failing_tests,
    }
    (artifact / "report.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    lines = [
        "# Redposture output quality audit",
        "",
        f"Started: `{started_at}`  ",
        f"Finished: `{payload['finished_at']}`  ",
        f"Artifacts: `{artifact}`",
        "",
        "## Runs",
        "",
        "| Stage | Class | Status | Duration | Passed | Failed | Skipped | Command |",
        "|---|---|---:|---:|---:|---:|---:|---|",
    ]
    for result in results:
        lines.append(
            f"| {result.name} | {result.category} | {result.status} | {result.duration_seconds:.3f}s | "
            f"{result.passed} | {result.failed + result.errors} | {result.skipped} | `{result.command}` |"
        )
    lines.extend(
        (
            "",
            "## Results by check class",
            "",
            "| Class | Passed | Failed | Skipped | Errors |",
            "|---|---:|---:|---:|---:|",
        )
    )
    for category, counts in sorted(summary_by_class.items()):
        lines.append(
            f"| {category} | {counts['passed']} | {counts['failed']} | {counts['skipped']} | {counts['errors']} |"
        )
    lines.extend(
        ("", "## Results by module", "", "| Module | Passed | Failed | Skipped | Errors |", "|---|---:|---:|---:|---:|")
    )
    for module, counts in sorted(summary_by_module.items()):
        lines.append(
            f"| {module} | {counts['passed']} | {counts['failed']} | {counts['skipped']} | {counts['errors']} |"
        )
    lines.extend(("", "## Detected defects", ""))
    if not defects:
        lines.append("No contract violations were detected.")
    for index, defect in enumerate(defects, 1):
        lines.extend(
            (
                f"### {index}. {defect['module']}: {defect['test']}",
                "",
                f"Class: `{defect['class']}`  ",
                f"Reproduce: `{defect['reproduce']}`  ",
                f"Log: `{defect['log']}`",
                "",
                "```text",
                defect["actual_and_expected"][:4000],
                "```",
                "",
            )
        )
    lines.extend(("## Unavailable or skipped stands", ""))
    if skipped_stands:
        lines.extend(f"- `{item['stage']}`: {item['reason']}" for item in skipped_stands)
    else:
        lines.append("None.")
    lines.extend(("", "## Tests kept in the local failing profile", ""))
    if local_failing_tests:
        lines.extend(f"- `{nodeid}`" for nodeid in local_failing_tests)
    else:
        lines.append("None.")
    (artifact / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    artifact = Path(sys.argv[1]).expanduser().resolve() if len(sys.argv) > 1 else DEFAULT_ARTIFACT
    artifact.mkdir(parents=True, exist_ok=True)
    python = os.environ.get("PYTHON_BIN", sys.executable)
    stages = [
        Stage(
            "fast-output-contracts",
            "output-contract",
            (
                python,
                "-m",
                "pytest",
                "-q",
                "tests/test_audit_output_contracts_extended.py",
                "tests/test_discovery_rendering.py",
                "tests/test_stage_runtime.py",
                "tests/test_cve.py",
            ),
            pytest=True,
        ),
        Stage(
            "network-and-protocol-output",
            "network",
            (
                python,
                "-m",
                "pytest",
                "-q",
                "tests/test_real_mtls_integration.py",
                "tests/test_http_redirect_policy.py",
                "tests/test_redirect_matrix_contract.py",
                "tests/test_mutating_retry_safety.py",
                "tests/test_transport_fault_injection.py",
                "tests/test_protocol_replay.py",
                "tests/test_proxy_end_to_end.py",
                "tests/test_signal_lifecycle.py",
                "tests/test_fd_leak_fixes.py",
            ),
            pytest=True,
        ),
        Stage(
            "known-output-defects",
            "known-defects",
            (python, "-m", "pytest", "-q", "-m", "local_output_audit", "tests/test_local_output_audit.py"),
            pytest=True,
        ),
        Stage(
            "load-sigint-and-nested",
            "load",
            (
                python,
                "-m",
                "pytest",
                "-q",
                "-m",
                "local_output_audit",
                "tests/test_concurrency_stress.py",
                "tests/test_sigint_runtime.py",
                "tests/test_soak_qa.py",
            ),
            pytest=True,
        ),
        Stage("output-mutations", "mutation", (python, "scripts/run_mutation_smoke.py")),
        Stage(
            "docker-minio-kubeapi",
            "docker",
            ("./scripts/run_minio_kubeapi_lab.sh",),
            requires_docker=True,
            environment={"PYTHON": python},
        ),
        Stage(
            "docker-auth-matrix",
            "docker",
            ("./scripts/run_auth_service_matrix.sh",),
            requires_docker=True,
            environment={"PYTHON": python},
        ),
        Stage(
            "docker-cve-matrix",
            "docker",
            ("./scripts/run_real_cve_matrix.sh",),
            requires_docker=True,
            environment={"PYTHON": python},
        ),
        Stage(
            "docker-full-service-matrix",
            "docker",
            ("./scripts/run_lab_matrix_sequential.sh", str(artifact / "service-matrix")),
            requires_docker=True,
            environment={"PYTHON_BIN": python, "REDPOSTURE_MATRIX_PROFILE": "extended"},
        ),
    ]
    started_at = datetime.now(timezone.utc).isoformat()
    docker_available, docker_reason = _docker_available()
    results: list[StageResult] = []
    for stage in stages:
        print(f"== {stage.name} ==", flush=True)
        result = _run_stage(stage, artifact, docker_available, docker_reason)
        results.append(result)
        print(f"{result.status} ({result.duration_seconds:.3f}s): {result.log}", flush=True)
        _write_reports(artifact, results, started_at)
    failed = any(result.status == "failed" for result in results)
    print(f"reports: {artifact / 'report.json'} {artifact / 'report.md'}", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
