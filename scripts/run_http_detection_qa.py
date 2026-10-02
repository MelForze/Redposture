#!/usr/bin/env python3
"""Focused HTTP service-detection QA with an always-written local report."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from csv import DictReader
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MODULES = (
    "airflow",
    "consul",
    "docker",
    "elastic",
    "etcd",
    "gitlab",
    "grafana",
    "kubeapi",
    "minio",
    "proxmox",
    "qdrant",
    "rabbitmq",
    "registry",
    "clickhouse",
    "grpc",
)
TESTS = (
    "tests/test_network_fingerprint_matrix.py",
    "tests/test_detection_precision.py",
    "tests/test_http_detection_fuzz.py",
    "tests/test_clients_grpc.py",
    "tests/test_clients_docker_engine.py",
    "tests/test_clients_minio_api.py",
    "tests/test_clickhouse_5173.py",
)


def _junit_summary(path: Path) -> tuple[dict[str, int], dict[str, dict[str, int]], list[dict[str, str]]]:
    totals = {key: 0 for key in ("passed", "failed", "skipped", "errors")}
    modules = {name: dict(totals) for name in MODULES}
    failures: list[dict[str, str]] = []
    if not path.exists():
        return totals, modules, failures
    for case in ET.parse(path).getroot().iter("testcase"):
        name = str(case.get("name") or "")
        owner = str(case.get("file") or "")
        failure = case.find("failure")
        error = case.find("error")
        key = (
            "failed"
            if failure is not None
            else "errors"
            if error is not None
            else "skipped"
            if case.find("skipped") is not None
            else "passed"
        )
        totals[key] += 1
        for module in MODULES:
            if f"[{module}]" in name or f"[{module}-" in name or f"-{module}]" in name:
                modules[module][key] += 1
        if failure is not None or error is not None:
            detail = failure if failure is not None else error
            assert detail is not None
            failures.append(
                {
                    "test": f"{owner}::{name}",
                    "message": str(detail.get("message") or ""),
                    "trace": str(detail.text or "")[:6000],
                }
            )
    return totals, modules, failures


def _run(
    name: str, command: list[str], output: Path, *, env: dict[str, str] | None = None, junit: bool = False
) -> dict[str, Any]:
    log = output / f"{name}.log"
    xml = output / f"{name}.xml"
    actual = command + ([f"--junitxml={xml}"] if junit else [])
    started = time.monotonic()
    with log.open("w", encoding="utf-8") as stream:
        completed = subprocess.run(
            actual, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT, env={**os.environ, **(env or {})}, check=False
        )
    totals, modules, failures = _junit_summary(xml)
    return {
        "name": name,
        "command": shlex.join(actual),
        "duration_seconds": round(time.monotonic() - started, 3),
        "returncode": completed.returncode,
        "status": "passed" if completed.returncode == 0 else "failed",
        "log": str(log),
        "junit": str(xml) if junit else None,
        "counts": totals,
        "modules": modules,
        "failures": failures,
    }


def _attach_service_matrix_counts(run: dict[str, Any], status_file: Path) -> None:
    if not status_file.exists():
        return
    with status_file.open(encoding="utf-8", newline="") as stream:
        for row in DictReader(stream, delimiter="\t"):
            module = str(row.get("module") or "")
            expected = str(row.get("expected_exit") or "")
            actual = str(row.get("exit_code") or "")
            result = "passed" if expected == actual else "failed"
            run["counts"][result] += 1
            if module in run["modules"]:
                run["modules"][module][result] += 1
            if result == "failed":
                run["failures"].append(
                    {
                        "test": f"{module}/{row.get('label') or '-'}",
                        "message": f"expected exit {expected}, got {actual}",
                        "trace": str(row.get("log_path") or ""),
                    }
                )


def main() -> int:
    default = ROOT / ".redposture" / "qa" / f"http-detection-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    output = (Path(sys.argv[1]) if len(sys.argv) > 1 else default).resolve()
    output.mkdir(parents=True, exist_ok=True)
    python = str(ROOT / ".venv" / "bin" / "python") if (ROOT / ".venv" / "bin" / "python").exists() else sys.executable
    runs = [
        _run("network-and-unit", [python, "-m", "pytest", "-q", *TESTS], output, junit=True),
        _run(
            "hypothesis-local",
            [
                python,
                "-m",
                "pytest",
                "-q",
                "tests/test_http_detection_fuzz.py",
                "tests/test_detection_precision.py",
                "--hypothesis-seed=20261001",
            ],
            output,
            env={"REDPOSTURE_HYPOTHESIS_PROFILE": "redposture-local"},
            junit=True,
        ),
    ]
    reused_matrix = os.environ.get("REDPOSTURE_HTTP_QA_REUSE_MATRIX", "").strip()
    docker = shutil.which("docker")
    unavailable: list[str] = []
    if reused_matrix:
        matrix_dir = Path(reused_matrix).resolve()
        status_file = matrix_dir / "matrix-status.tsv"
        if not status_file.exists():
            raise SystemExit(f"reused matrix status file not found: {status_file}")
        runs.append(
            _run(
                "real-service-matrix",
                [
                    python,
                    "scripts/verify_postrun.py",
                    "--status-file",
                    str(status_file),
                    "--out-dir",
                    str(matrix_dir),
                    "--profile",
                    "extended",
                ],
                output,
            )
        )
        runs[-1]["source_matrix_dir"] = str(matrix_dir)
        _attach_service_matrix_counts(runs[-1], status_file)
    elif docker is None:
        unavailable.append("Docker CLI недоступен: реальные сервисные стенды пропущены")
    else:
        probe = subprocess.run(
            [docker, "info", "--format", "{{.ServerVersion}}"], cwd=ROOT, capture_output=True, text=True, check=False
        )
        if probe.returncode != 0:
            unavailable.append(f"Docker daemon недоступен: {(probe.stderr or probe.stdout).strip()}")
        elif os.environ.get("REDPOSTURE_HTTP_QA_SKIP_DOCKER") == "1":
            unavailable.append("Реальные Docker-стенды отключены REDPOSTURE_HTTP_QA_SKIP_DOCKER=1")
        else:
            runs.append(
                _run(
                    "real-service-matrix",
                    [str(ROOT / "scripts" / "run_lab_matrix_sequential.sh"), str(output / "real-services")],
                    output,
                )
            )
            _attach_service_matrix_counts(runs[-1], output / "real-services" / "matrix-status.tsv")
    for name in MODULES:
        if name in {"clickhouse", "grpc"}:
            unavailable.append(
                f"{name}: HTTP-ветка в быстрых тестах эмулирована; реальный стенд учитывается в Docker matrix"
            )
    fixture_catalog = ROOT / "lab" / "services" / "coverage.json"
    if fixture_catalog.exists():
        fixtures = json.loads(fixture_catalog.read_text(encoding="utf-8")).get("modules", {})
        for name in MODULES:
            fixture = fixtures.get(name, {})
            fidelity = str(fixture.get("fidelity") or "unknown")
            if fidelity != "real":
                unavailable.append(
                    f"{name}: Docker fixture fidelity={fidelity}; {str(fixture.get('limits') or 'no details')}"
                )
    defects: list[dict[str, str]] = [dict(item, run=str(run["name"])) for run in runs for item in run["failures"]]
    for run in runs:
        if run["status"] == "failed" and not run["failures"]:
            log_tail = Path(str(run["log"])).read_text(encoding="utf-8", errors="replace").splitlines()[-8:]
            defects.append(
                {
                    "test": str(run["name"]),
                    "message": f"QA stage failed with exit {run['returncode']}",
                    "trace": "\n".join(log_tail),
                    "run": str(run["name"]),
                }
            )
    report = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "modules": list(MODULES),
        "runs": runs,
        "unavailable_or_emulated": unavailable,
        "defects": defects,
    }
    (output / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# HTTP detection QA",
        "",
        f"Папка: `{output}`",
        "",
        "| Прогон | Результат | Passed | Failed | Skipped | Время |",
        "| --- | --- | ---: | ---: | ---: | ---: |",
    ]
    for run in runs:
        counts = run["counts"]
        lines.append(
            f"| {run['name']} | {run['status']} | {counts['passed']} | {counts['failed'] + counts['errors']} | {counts['skipped']} | {run['duration_seconds']} s |"
        )
    lines.extend(["", "## Команды", ""])
    lines.extend(f"- `{run['name']}`: `{run['command']}`" for run in runs)
    lines.extend(["", "## По модулям", "", "| Модуль | Passed | Failed | Skipped |", "| --- | ---: | ---: | ---: |"])
    for module in MODULES:
        counts = {
            key: sum(run["modules"][module][key] for run in runs) for key in ("passed", "failed", "errors", "skipped")
        }
        lines.append(f"| {module} | {counts['passed']} | {counts['failed'] + counts['errors']} | {counts['skipped']} |")
    lines.extend(["", "## Недоступно или эмулировано", ""])
    lines.extend(f"- {reason}" for reason in unavailable)
    lines.extend(["", "## Найденные дефекты", ""])
    lines.extend(f"- `{item['test']}`: {item['message']}" for item in defects)
    if not defects:
        lines.append("- Нет в выполненных проверках.")
    (output / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(output / "report.md")
    return 1 if any(run["status"] == "failed" for run in runs) else 0


if __name__ == "__main__":
    raise SystemExit(main())
