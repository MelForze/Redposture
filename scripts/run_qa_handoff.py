#!/usr/bin/env python3
"""Run deferred release QA and write a compact, local handoff report."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.qa_owned_images import compose_images, missing_images, remove_images  # noqa: E402

GITLAB_COMPOSE = ROOT / "lab/services/gitlab-real/docker-compose.yml"
GITLAB_REGISTRY = "http://127.0.0.1:15003"
GITLAB_IMAGE = "gitlab/project-api:latest"
LAB_TOKEN = "glpat-redposture-lab-root-2026"  # Isolated, seeded QA credential.
STAGE_NAMES = ("full", "versions", "gitlab-blob", "python-matrix")


def _safe_command(command: list[str]) -> str:
    return " ".join(part.replace(LAB_TOKEN, "<lab-token>") for part in command)


def _run_logged(
    command: list[str],
    log: Path,
    *,
    timeout: int,
    env: dict[str, str] | None = None,
) -> tuple[int, float]:
    log.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    print(f"[start] {_safe_command(command)}", flush=True)
    with log.open("wb") as output:
        try:
            child = subprocess.Popen(
                command,
                cwd=ROOT,
                env=env,
                stdout=output,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        except OSError as exc:
            output.write(f"could not start: {exc}\n".encode())
            return 127, time.monotonic() - started
        try:
            while True:
                try:
                    code = child.wait(timeout=30)
                    break
                except subprocess.TimeoutExpired:
                    elapsed = int(time.monotonic() - started)
                    print(f"[running] {log.name}: {elapsed}s; log={log}", flush=True)
                    if elapsed >= timeout:
                        os.killpg(child.pid, signal.SIGTERM)
                        try:
                            child.wait(timeout=20)
                        except subprocess.TimeoutExpired:
                            os.killpg(child.pid, signal.SIGKILL)
                            child.wait()
                        output.write(f"\nQA command timed out after {timeout}s\n".encode())
                        code = 124
                        break
        except KeyboardInterrupt:
            os.killpg(child.pid, signal.SIGINT)
            try:
                child.wait(timeout=20)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
            raise
    duration = round(time.monotonic() - started, 2)
    print(f"[done] exit={code} elapsed={duration}s log={log}", flush=True)
    return code, duration


def _docker_project_is_empty(project: str) -> bool:
    for command in (
        ["docker", "ps", "-aq", "--filter", f"label=com.docker.compose.project={project}"],
        ["docker", "volume", "ls", "-q", "--filter", f"label=com.docker.compose.project={project}"],
    ):
        output = subprocess.check_output(command, cwd=ROOT, text=True, timeout=30)
        if output.strip():
            return False
    return True


def _gitlab_ports_are_free(compose: list[str]) -> tuple[bool, list[int]]:
    config = json.loads(subprocess.check_output([*compose, "config", "--format", "json"], cwd=ROOT, timeout=30))
    ports = sorted(
        {
            int(port["published"])
            for service in config.get("services", {}).values()
            for port in service.get("ports", [])
            if port.get("published")
        }
    )
    busy: list[int] = []
    for port in ports:
        with socket.socket() as probe:
            probe.settimeout(0.2)
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                busy.append(port)
    return not busy, busy


def _json_record(log: Path) -> dict[str, Any] | None:
    for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            registry = item.get("container_registry")
            if isinstance(item.get("download_result"), dict) or (
                isinstance(registry, dict) and isinstance(registry.get("download_result"), dict)
            ):
                return item
    return None


def validate_gitlab_download(record: dict[str, Any] | None, artifact_dir: Path) -> tuple[bool, str]:
    """Require a real GitLab fingerprint and every seeded OCI blob by digest."""
    if not record or record.get("is_gitlab") is not True:
        return False, "GitLab product was not confirmed"
    result = record.get("download_result")
    if not isinstance(result, dict):
        registry = record.get("container_registry")
        if not isinstance(registry, dict) or registry.get("is_gitlab") is not True:
            return False, "GitLab Container Registry was not confirmed"
        result = registry.get("download_result")
    if not isinstance(result, dict) or result.get("status") != "ok":
        return False, f"download_result={result!r}"
    path = Path(str(result.get("path") or "")).resolve()
    if not path.is_relative_to(artifact_dir.resolve()) or not path.is_dir():
        return False, "download path is missing or outside the QA artifact directory"
    manifest_file = path / "manifest.json"
    if not manifest_file.is_file():
        return False, "downloaded manifest.json is missing"
    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        descriptors = [manifest["config"], *manifest["layers"]]
        expected = {str(item["digest"]) for item in descriptors}
        actual = {
            "sha256:" + hashlib.sha256(blob.read_bytes()).hexdigest()
            for blob in [*path.glob("*.blob"), *path.glob("*.layer")]
        }
    except (OSError, TypeError, ValueError, KeyError) as exc:
        return False, f"invalid downloaded image: {exc}"
    if not expected or actual != expected:
        return False, f"blob digests differ: expected={sorted(expected)} actual={sorted(actual)}"
    return True, f"GitLab OCI blob download verified: {len(actual)} SHA-256 digest(s)"


def _gitlab_blob_qa(destination: Path, project: str, python: str) -> dict[str, Any]:
    destination.mkdir(parents=True, exist_ok=True)
    compose = ["docker", "compose", "-p", project, "-f", str(GITLAB_COMPOSE)]
    new_images: list[str] = []
    try:
        if not _docker_project_is_empty(project):
            return {"status": "blocked", "reason": f"Compose project {project} already exists"}
        free, busy = _gitlab_ports_are_free(compose)
        if not free:
            return {"status": "blocked", "reason": f"GitLab loopback ports already occupied: {busy}"}
        new_images = missing_images(compose_images(compose))
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError) as exc:
        return {"status": "blocked", "reason": f"Docker preflight failed: {exc}"}

    checks: list[dict[str, Any]] = []
    outcome: dict[str, Any] = {"status": "failed", "reason": "GitLab run did not finish", "checks": checks}
    try:
        for name, command, timeout in (
            ("up", [*compose, "up", "-d", "--wait", "--wait-timeout", "2400"], 2700),
            (
                "seed",
                [
                    python,
                    str(ROOT / "scripts/bootstrap_gitlab_lab.py"),
                    str(destination / "seed"),
                    "--compose",
                    str(GITLAB_COMPOSE),
                    "--project",
                    project,
                ],
                1200,
            ),
            (
                "download",
                [
                    python,
                    str(ROOT / "redposture.py"),
                    "gitlab",
                    "-t",
                    GITLAB_REGISTRY,
                    "-u",
                    "root",
                    "-p",
                    LAB_TOKEN,
                    "--image",
                    GITLAB_IMAGE,
                    "--inspect",
                    "--download",
                    "--download-dir",
                    str(destination / "downloads"),
                    "--timeout",
                    "30",
                    "--format",
                    "json",
                ],
                240,
            ),
        ):
            code, duration = _run_logged(command, destination / f"{name}.log", timeout=timeout)
            checks.append({"name": name, "exit_code": code, "duration_seconds": duration, "log": f"{name}.log"})
            if code:
                outcome.update(reason=f"GitLab {name} failed")
                break
        else:
            passed, reason = validate_gitlab_download(_json_record(destination / "download.log"), destination)
            outcome.update(status="passed" if passed else "failed", reason=reason)
    finally:
        code, duration = _run_logged(
            [*compose, "down", "--volumes", "--remove-orphans"], destination / "down.log", timeout=240
        )
        checks.append({"name": "down", "exit_code": code, "duration_seconds": duration, "log": "down.log"})
        if code:
            outcome.update(status="failed", reason=f"GitLab cleanup failed (exit {code}); inspect project {project}")
        else:
            try:
                errors = remove_images(new_images)
                if errors:
                    outcome.update(status="failed", reason=f"GitLab image cleanup failed: {errors}")
            except (OSError, subprocess.TimeoutExpired) as exc:
                outcome.update(status="failed", reason=f"GitLab image cleanup failed: {exc}")
    return outcome


def _run_stage(name: str, destination: Path, prefix: str, python: str) -> dict[str, Any]:
    if name == "gitlab-blob":
        return _gitlab_blob_qa(destination, f"{prefix}-gitlabblob", python)
    command = [
        "bash",
        str(ROOT / "scripts/run_full_local_qa.sh" if name == "full" else ROOT / "scripts/run_version_qa.sh"),
        str(destination / "artifacts"),
    ]
    env = {
        **os.environ,
        "REDPOSTURE_QA_PROJECT_PREFIX": f"{prefix}-{name}",
        "REDPOSTURE_QA_CLEAN_IMAGES": "1",
        "PYTHON_BIN": python,
    }
    code, duration = _run_logged(command, destination / "run.log", timeout=14400, env=env)
    return {
        "status": "passed" if code == 0 else "failed",
        "exit_code": code,
        "duration_seconds": duration,
        "log": "run.log",
    }


def _python_matrix(destination: Path) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for minor in range(10, 14):
        tag = f"py3{minor}"
        case_dir = destination / tag
        interpreter = shutil.which(f"python3.{minor}")
        if interpreter is None:
            results.append({"python": tag, "status": "blocked", "reason": "interpreter not installed"})
            continue
        venv = case_dir / "venv"
        commands = [
            [interpreter, "-m", "venv", str(venv)],
            [
                str(venv / "bin/python"),
                "-m",
                "pip",
                "install",
                "--requirement",
                str(ROOT / f"requirements/ci-{tag}.txt"),
            ],
            [str(venv / "bin/python"), "-m", "pip", "install", "--no-deps", "--no-build-isolation", "-e", str(ROOT)],
            ["bash", str(ROOT / "scripts/run_ci_job.sh"), "test"],
        ]
        steps = []
        try:
            for index, command in enumerate(commands):
                env = {
                    **os.environ,
                    "PATH": str(venv / "bin") + os.pathsep + os.environ.get("PATH", ""),
                    "PIP_DISABLE_PIP_VERSION_CHECK": "1",
                    "REDPOSTURE_COVERAGE_DIR": str(case_dir / "coverage"),
                }
                code, duration = _run_logged(command, case_dir / f"step-{index}.log", timeout=3600, env=env)
                steps.append(
                    {
                        "command": _safe_command(command),
                        "exit_code": code,
                        "duration_seconds": duration,
                        "log": f"step-{index}.log",
                    }
                )
                if code:
                    break
        finally:
            shutil.rmtree(venv, ignore_errors=True)
        results.append(
            {
                "python": tag,
                "status": "passed" if len(steps) == 4 and not steps[-1]["exit_code"] else "failed",
                "steps": steps,
            }
        )
    return {"status": "passed" if all(row["status"] == "passed" for row in results) else "failed", "results": results}


def _write_report(destination: Path, report: dict[str, Any]) -> None:
    (destination / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# QA handoff",
        "",
        f"Revision: `{report['revision']}`",
        f"Started: `{report['started_utc']}`",
        f"Overall: **{report['status']}**",
        "",
        "| Stage | Status | Detail |",
        "| --- | --- | --- |",
    ]
    for name, row in report["stages"].items():
        detail = str(row.get("reason") or (f"exit {row['exit_code']}" if "exit_code" in row else ""))
        lines.append(f"| {name} | {row['status']} | {detail.replace('|', '/')} |")
    lines += [
        "",
        "Send `report.md` and `report.json` first. If a stage failed, also send its log and nested report from that stage's directory.",
        "The full logs and GitLab download artifacts stay in this local, gitignored directory.",
        "",
    ]
    (destination / "report.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact_dir", nargs="?", type=Path)
    parser.add_argument("--only", action="append", choices=STAGE_NAMES)
    parser.add_argument("--plan", action="store_true", help="Print stages without starting QA or creating files")
    args = parser.parse_args()
    names = tuple(dict.fromkeys(args.only or STAGE_NAMES))
    destination = args.artifact_dir or ROOT / ".redposture/qa" / f"handoff-{datetime.now():%Y%m%d-%H%M%S}"
    destination = destination.resolve()
    if args.plan:
        print("Artifact directory:", destination)
        for name in names:
            print("-", name)
        return 0
    if destination.exists() and any(destination.iterdir()):
        parser.error(f"artifact directory is not empty: {destination}")
    destination.mkdir(parents=True, exist_ok=True)
    python = str(ROOT / ".venv/bin/python") if (ROOT / ".venv/bin/python").exists() else sys.executable
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    prefix = f"redposturehandoff{int(time.time())}{os.getpid()}"
    report: dict[str, Any] = {
        "revision": revision,
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "status": "running",
        "stages": {},
    }
    _write_report(destination, report)
    try:
        for name in names:
            stage_dir = destination / name
            stage_dir.mkdir()
            try:
                result = (
                    _python_matrix(stage_dir)
                    if name == "python-matrix"
                    else _run_stage(name, stage_dir, prefix, python)
                )
            except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError) as exc:
                result = {"status": "failed", "reason": f"runner error: {exc}"}
            report["stages"][name] = result
            _write_report(destination, report)
    except KeyboardInterrupt:
        report["status"] = "interrupted"
        _write_report(destination, report)
        return 130
    report["status"] = "passed" if all(row["status"] == "passed" for row in report["stages"].values()) else "failed"
    _write_report(destination, report)
    print(f"[report] {destination / 'report.md'}", flush=True)
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
