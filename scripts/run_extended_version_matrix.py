#!/usr/bin/env python3
"""Exercise real Airflow and Elasticsearch releases in isolated local labs."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.qa_owned_images import compose_images, missing_images, remove_images  # noqa: E402


@dataclass(frozen=True)
class VersionCase:
    product: str
    release: str
    image: str
    compose_file: str
    service: str
    project: str
    target: str
    version_field: str
    product_key: str
    timeout: int
    must_match: tuple[str, ...] = ()
    must_not_match: tuple[str, ...] = ()
    credentials: tuple[str, str] | None = None


CASES = (
    VersionCase(
        "airflow",
        "2.9.2",
        "apache/airflow:2.9.2-python3.11",
        "lab/services/airflow/docker-compose.yml",
        "airflow-auth",
        "redposture-version-airflow",
        "http://127.0.0.1:18080",
        "version",
        "apache_airflow",
        420,
        ("CVE-2024-45034", "CVE-2024-39877"),
        credentials=("airflow", "airflow"),
    ),
    VersionCase(
        "airflow",
        "2.9.3",
        "apache/airflow:2.9.3-python3.11",
        "lab/services/airflow/docker-compose.yml",
        "airflow-auth",
        "redposture-version-airflow",
        "http://127.0.0.1:18080",
        "version",
        "apache_airflow",
        420,
        must_match=("CVE-2024-45034",),
        must_not_match=("CVE-2024-39877",),
        credentials=("airflow", "airflow"),
    ),
    VersionCase(
        "airflow",
        "2.10.5",
        "apache/airflow:2.10.5-python3.11",
        "lab/services/airflow/docker-compose.yml",
        "airflow-auth",
        "redposture-version-airflow",
        "http://127.0.0.1:18080",
        "version",
        "apache_airflow",
        420,
        must_not_match=("CVE-2024-45034", "CVE-2024-39877"),
        credentials=("airflow", "airflow"),
    ),
    VersionCase(
        "elasticsearch",
        "8.13.4",
        "docker.elastic.co/elasticsearch/elasticsearch:8.13.4",
        "lab/services/elastic/docker-compose.yml",
        "elastic-open",
        "redposture-version-elastic",
        "http://127.0.0.1:19200",
        "server_version",
        "elasticsearch",
        300,
    ),
    VersionCase(
        "elasticsearch",
        "8.15.0",
        "docker.elastic.co/elasticsearch/elasticsearch:8.15.0",
        "lab/services/elastic/docker-compose.yml",
        "elastic-open",
        "redposture-version-elastic",
        "http://127.0.0.1:19200",
        "server_version",
        "elasticsearch",
        300,
    ),
)


def _run(command: list[str], log: Path, *, timeout: int) -> subprocess.CompletedProcess[str]:
    started = time.monotonic()
    with log.open("a", encoding="utf-8") as stream:
        stream.write(f"$ {subprocess.list2cmdline(command)}\n")
        stream.flush()
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=timeout, check=False)
        stream.write(result.stdout)
        stream.write(result.stderr)
        stream.write(f"\n[exit={result.returncode} elapsed={time.monotonic() - started:.1f}s]\n")
    return result


def _record(stdout: str) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and value.get("type") != "summary":
            records.append(value)
    if len(records) != 1:
        raise AssertionError(f"expected one target record, got {len(records)}")
    return records[0]


def _check(case: VersionCase, record: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    detected = str(record.get(case.version_field) or "")
    if detected != case.release:
        issues.append(f"version: expected {case.release}, got {detected or '-'}")
    enumeration = record.get("cve_enumeration") or {}
    products = {item.get("product_key") for item in enumeration.get("products", []) if isinstance(item, dict)}
    if case.product_key not in products:
        issues.append(f"product: expected {case.product_key}, got {sorted(str(item) for item in products)}")
    findings = {item.get("id") for item in enumeration.get("findings", []) if isinstance(item, dict)}
    for cve in case.must_match:
        if cve not in findings:
            issues.append(f"missing expected {cve}")
    for cve in case.must_not_match:
        if cve in findings:
            issues.append(f"unexpected {cve}")
    return issues


def _case(case: VersionCase, out_dir: Path) -> dict[str, Any]:
    slug = f"{case.product}-{case.release}"
    log = out_dir / f"{slug}.log"
    override = out_dir / f"{slug}.override.json"
    override.write_text(json.dumps({"services": {case.service: {"image": case.image}}}), encoding="utf-8")
    project_name = (
        f"{os.environ['REDPOSTURE_QA_PROJECT_PREFIX']}-{case.product}"
        if os.environ.get("REDPOSTURE_QA_PROJECT_PREFIX")
        else f"redpostureqa{os.getpid()}-{case.product}"
    )
    compose = [
        "docker",
        "compose",
        "--project-name",
        project_name,
        "--file",
        str(ROOT / case.compose_file),
        "--file",
        str(override),
    ]
    started = time.monotonic()
    outcome: dict[str, Any] = {"case": asdict(case), "status": "failed", "log": str(log)}
    owns_stack = False
    clean_images = os.environ.get("REDPOSTURE_QA_CLEAN_IMAGES") == "1"
    new_images: list[str] = []
    try:
        existing = _run([*compose, "ps", "--all", "-q"], log, timeout=30)
        if existing.returncode != 0 or existing.stdout.strip():
            raise RuntimeError("Compose project already exists or cannot be inspected; preserving it")
        volumes = _run(
            ["docker", "volume", "ls", "-q", "--filter", f"label=com.docker.compose.project={project_name}"],
            log,
            timeout=30,
        )
        if volumes.returncode != 0 or volumes.stdout.strip():
            raise RuntimeError("Compose volumes already exist or cannot be inspected; preserving them")
        if clean_images:
            new_images = missing_images(compose_images(compose))
        owns_stack = True
        startup = _run(
            [*compose, "up", "--detach", "--wait", "--wait-timeout", str(case.timeout), case.service],
            log,
            timeout=case.timeout + 90,
        )
        if startup.returncode != 0:
            raise RuntimeError(f"compose startup exited {startup.returncode}")
        command = [
            sys.executable,
            str(ROOT / "redposture.py"),
            "airflow" if case.product == "airflow" else "elastic",
            "-t",
            case.target,
            "--enum-cve",
            "--format",
            "json",
            "--timeout",
            "10",
        ]
        if case.credentials:
            command.extend(["-u", case.credentials[0], "-p", case.credentials[1]])
        scan = _run(command, log, timeout=90)
        (out_dir / f"{slug}.jsonl").write_text(scan.stdout, encoding="utf-8")
        if scan.returncode != 0:
            raise RuntimeError(f"scanner exited {scan.returncode}")
        record = _record(scan.stdout)
        outcome["detected_version"] = record.get(case.version_field)
        outcome["cve_status"] = (record.get("cve_enumeration") or {}).get("status")
        outcome["cve_ids"] = [item.get("id") for item in (record.get("cve_enumeration") or {}).get("findings", [])]
        issues = _check(case, record)
        if issues:
            raise AssertionError("; ".join(issues))
        outcome["status"] = "passed"
    except (AssertionError, OSError, RuntimeError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        outcome["error"] = str(exc)
    finally:
        if owns_stack:
            try:
                cleanup = _run([*compose, "down", "--volumes", "--remove-orphans"], log, timeout=90)
                if cleanup.returncode:
                    raise RuntimeError(f"cleanup exited {cleanup.returncode}")
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
                outcome["cleanup_error"] = str(exc)
                outcome["status"] = "failed"
        if clean_images:
            try:
                errors = remove_images(new_images)
                if errors:
                    outcome["image_cleanup_error"] = errors
                    outcome["status"] = "failed"
            except (OSError, subprocess.TimeoutExpired) as exc:
                outcome["image_cleanup_error"] = str(exc)
                outcome["status"] = "failed"
    outcome["duration_seconds"] = round(time.monotonic() - started, 2)
    return outcome


def main() -> int:
    out_dir = Path(sys.argv[1]).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    results = []
    for case in CASES:
        print(f"[start] {case.product} {case.release}", flush=True)
        outcome = _case(case, out_dir)
        results.append(outcome)
        print(
            f"[{outcome['status']}] {case.product} {case.release}: {outcome.get('error', 'version and CVE checks passed')}",
            flush=True,
        )
    (out_dir / "results.json").write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    lines = [
        "# Extended real-version matrix",
        "",
        "| Product | Release | Result | Detected | CVE status |",
        "|---|---|---|---|---|",
    ]
    for result in results:
        case = result["case"]
        lines.append(
            f"| {case['product']} | {case['release']} | {result['status']} | "
            f"{result.get('detected_version', '-')} | {result.get('cve_status', '-')} |"
        )
    (out_dir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return int(any(result["status"] != "passed" for result in results))


if __name__ == "__main__":
    raise SystemExit(main())
