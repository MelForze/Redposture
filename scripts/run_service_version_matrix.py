#!/usr/bin/env python3
"""Run local release compatibility cases from an ignored lab manifest."""

from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from redposture_core.cli_args import build_parser  # noqa: E402
from redposture_core.cve import normalize_version  # noqa: E402
from scripts.check_compose_readiness import readiness_issues  # noqa: E402
from scripts.qa_owned_images import compose_images, missing_images, remove_images  # noqa: E402
from scripts.qa_service_policy import startup_timeout  # noqa: E402
from scripts.run_extended_version_matrix import _record  # noqa: E402


def run(command: list[str], log: Path, *, timeout: int, env: dict[str, str] | None = None) -> str:
    started = time.monotonic()
    with log.open("a", encoding="utf-8") as stream:
        stream.write(f"$ {subprocess.list2cmdline(command)}\n")
        stream.flush()
        with subprocess.Popen(
            command, cwd=ROOT, stdout=subprocess.PIPE, stderr=stream, text=True, env=env, start_new_session=True
        ) as process:
            try:
                output, _ = process.communicate(timeout=timeout)
            except (subprocess.TimeoutExpired, KeyboardInterrupt):
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    output, _ = process.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    output, _ = process.communicate()
                stream.write(output or "")
                stream.write("\n[interrupted or timed out; child process group stopped]\n")
                raise
            stream.write(output)
            stream.write(f"\n[exit={process.returncode} elapsed={time.monotonic() - started:.1f}s]\n")
            if process.returncode:
                raise RuntimeError(f"exit {process.returncode}: {subprocess.list2cmdline(command)}; see {log}")
            return output


def override_services(
    config: dict[str, Any],
    replacements: dict[str, str],
    *,
    healthy_dependencies: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    services: dict[str, Any] = {}
    used: set[str] = set()
    for name, service in config["services"].items():
        image = str(service.get("image") or "")
        for prefix, replacement in replacements.items():
            if image.startswith(prefix):
                services[name] = {"image": replacement}
                used.add(prefix)
                break
    missing = set(replacements) - used
    if missing:
        raise ValueError(f"image replacements matched no services: {sorted(missing)}")
    for name, dependencies in (healthy_dependencies or {}).items():
        if name not in config["services"]:
            raise ValueError(f"unknown dependent service: {name}")
        existing = config["services"][name].get("depends_on", {})
        conditions = {}
        for dependency in dependencies:
            if dependency not in config["services"] or dependency not in existing:
                raise ValueError(f"unknown startup dependency: {name} -> {dependency}")
            options = existing[dependency] if isinstance(existing, dict) else {}
            conditions[dependency] = {**options, "condition": "service_healthy"}
        services.setdefault(name, {})["depends_on"] = conditions
    return {"services": services}


def check_record(case: dict[str, Any], record: dict[str, Any]) -> None:
    if record.get(case["marker"]) is not True:
        raise AssertionError(f"fingerprint {case['marker']} was not confirmed")
    enumeration = record.get("cve_enumeration")
    if not isinstance(enumeration, dict):
        raise AssertionError("cve_enumeration missing from target JSON")
    if case.get("unsupported"):
        if enumeration.get("status") != "unsupported":
            raise AssertionError(f"expected unsupported CVE fingerprint, got {enumeration.get('status')}")
        return
    products = [item for item in enumeration.get("products", []) if item.get("product_key") == case["product_key"]]
    if len(products) != 1:
        raise AssertionError(f"expected exactly one {case['product_key']} product, got {products}")
    actual = str(products[0].get("normalized_version") or "")
    expected = case["expected_version"]
    same_release = actual == expected or any(actual.startswith(expected + suffix) for suffix in (".", "-", "+"))
    if case["product_key"] == "minio":
        normalized = normalize_version(actual, "minio_release")
        same_release = normalized is not None and normalized == normalize_version(expected, "minio_release")
    if not same_release:
        raise AssertionError(f"expected version {expected}, got {actual or 'unknown'}")
    findings = {item["id"] for item in enumeration.get("findings", [])}
    missing = set(case.get("must_match", [])) - findings
    unexpected = set(case.get("must_not_match", [])) & findings
    if missing or unexpected:
        raise AssertionError(f"CVE boundary mismatch: missing={sorted(missing)}, unexpected={sorted(unexpected)}")
    if case.get("require_credentials") and record.get("provided_credentials_ok") is not True:
        raise AssertionError("explicit credentials were not verified")
    if case.get("identity_field") and record.get(case["identity_field"]) is not True:
        raise AssertionError(f"identity field {case['identity_field']} was not verified")
    if case.get("expected_status") and record.get("status") != case["expected_status"]:
        raise AssertionError(f"expected auth status {case['expected_status']}, got {record.get('status')}")
    if enumeration.get("status") not in {"matched", "no_matches"}:
        raise AssertionError(f"unexpected CVE status: {enumeration.get('status')}")


def validate_case_cli(case: dict[str, Any], parser: argparse.ArgumentParser) -> None:
    """Reject stale command names and flags before starting expensive stands."""
    arguments = [str(case["module"]), *(str(item) for item in case["args"]), "--enum-cve", "--format", "json"]
    try:
        parser.parse_args(arguments)
    except SystemExit as exc:
        raise ValueError(f"invalid CLI arguments in version case {case['id']}: {arguments}") from exc


def wait_ready(
    compose: list[str], config: dict[str, Any], log: Path, timeout: int, *, readiness_url: str | None = None
) -> None:
    deadline = time.monotonic() + timeout
    last_issues = ["containers not created"]
    while time.monotonic() < deadline:
        ids = run([*compose, "ps", "--all", "-q"], log, timeout=30).split()
        if len(ids) == len(config["services"]):
            containers = json.loads(run(["docker", "inspect", *ids], log, timeout=30))
            allowed = frozenset(
                str(item.get("Name", "")).removeprefix("/")
                for item in containers
                if any(
                    word in str(item.get("Config", {}).get("Labels", {}).get("com.docker.compose.service", ""))
                    for word in ("seed", "certs")
                )
            )
            for container in containers:
                state = container.get("State", {})
                name = str(container.get("Name", "")).removeprefix("/")
                terminal = (
                    state.get("Status") == "dead"
                    or state.get("OOMKilled") is True
                    or (state.get("Status") == "exited" and state.get("ExitCode") != 0)
                )
                restart_loop = state.get("Status") in {"restarting", "exited"} and container.get("RestartCount", 0) >= 3
                seed_failed = name in allowed and state.get("Status") == "exited" and state.get("ExitCode") != 0
                if terminal or restart_loop or seed_failed:
                    raise RuntimeError(
                        f"startup failed: {name}, state={state}, restarts={container.get('RestartCount', 0)}"
                    )
            last_issues = readiness_issues(containers, allowed_completed=allowed)
            if readiness_url:
                last_issues = [
                    str(item.get("Name")) + " not running"
                    for item in containers
                    if not item.get("State", {}).get("Running")
                ]
                if not last_issues:
                    try:
                        with urllib.request.urlopen(readiness_url, timeout=5) as response:
                            payload = json.load(response)
                        if isinstance(payload, dict) and payload.get("status") == "healthy":
                            return
                        last_issues = [f"API not healthy: {payload!r}"]
                    except (OSError, ValueError, urllib.error.URLError) as exc:
                        last_issues = [str(exc)]
            elif not last_issues:
                return
        time.sleep(2)
    raise RuntimeError(f"readiness timeout: {'; '.join(last_issues)}")


def run_case(case: dict[str, Any], destination: Path, *, validate_only: bool) -> dict[str, Any]:
    directory = destination / case["id"]
    directory.mkdir()
    log = directory / "commands.log"
    started = time.monotonic()
    result: dict[str, Any] = {"case": case, "status": "failed", "log": str(log)}
    base = ROOT / "lab/services" / case["fixture"] / "docker-compose.yml"
    project_prefix = os.environ.get("REDPOSTURE_QA_PROJECT_PREFIX", f"redpostureqa{os.getpid()}")
    project_name = f"{project_prefix}-versions-{case['fixture']}"
    compose = ["docker", "compose", "-p", project_name, "-f", str(base)]
    owns_stack = False
    clean_images = os.environ.get("REDPOSTURE_QA_CLEAN_IMAGES") == "1" and not validate_only
    new_images: list[str] = []
    try:
        if clean_images and case.get("fixture") == "registry-harbor-real" and case.get("prepare"):
            release = str(case["prepare"][2])
            new_images.extend(missing_images([f"goharbor/prepare:{release}"]))
        if case.get("environment"):
            environment_file = directory / "compose.env"
            environment_file.write_text(
                "".join(f"{key}={json.dumps(str(value))}\n" for key, value in case["environment"].items()),
                encoding="utf-8",
            )
            compose += ["--env-file", str(environment_file)]
        if case.get("prepare"):
            command = [
                str(item).replace("{artifact_dir}", str(directory)).replace("{python}", sys.executable)
                for item in case["prepare"]
            ]
            run(command, directory / "prepare.log", timeout=case.get("prepare_timeout", 1800))
            if case.get("prepared_compose"):
                base = directory / case["prepared_compose"]
                compose = [*compose[: compose.index("-f")], "-f", str(base), *compose[compose.index("-f") + 2 :]]
        config = json.loads(run([*compose, "config", "--format", "json"], log, timeout=30))
        override = directory / "override.json"
        override.write_text(
            json.dumps(
                override_services(config, case["images"], healthy_dependencies=case.get("healthy_dependencies"))
            ),
            encoding="utf-8",
        )
        compose += ["-f", str(override)]
        resolved = json.loads(run([*compose, "config", "--format", "json"], log, timeout=30))
        result["resolved_images"] = {name: service.get("image") for name, service in resolved["services"].items()}
        if validate_only:
            result["status"] = "validated"
            return result
        if clean_images:
            new_images.extend(missing_images(compose_images(compose)))
        if run([*compose, "ps", "--all", "-q"], log, timeout=30).strip():
            raise RuntimeError("version Compose project already exists; stop it explicitly before rerunning")
        if run(
            ["docker", "volume", "ls", "-q", "--filter", f"label=com.docker.compose.project={project_name}"],
            log,
            timeout=30,
        ).strip():
            raise RuntimeError("version Compose volumes already exist; preserving them")
        # Only this newly created project is removed in finally, even on failed startup.
        owns_stack = True
        run(
            [*compose, "up", "-d", "--build" if case.get("build", True) else "--no-build"],
            log,
            timeout=case.get("build_timeout", 2400),
        )
        wait_ready(
            compose,
            resolved,
            log,
            startup_timeout(case["fixture"], case.get("startup_timeout")),
            readiness_url=case.get("readiness_url"),
        )
        if case.get("bootstrap"):
            bootstrap = case["bootstrap"]
            run(
                [*compose, "exec", "-T", bootstrap["service"], *bootstrap["command"]],
                directory / "bootstrap.log",
                timeout=case.get("bootstrap_timeout", 600),
            )
        arguments = [sys.executable, str(ROOT / "redposture.py"), case["module"], *case["args"], "--enum-cve"]
        record = _record(run([*arguments, "--format", "json"], directory / "probe-json.log", timeout=180))
        (directory / "record.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        check_record(case, record)
        if case.get("verify"):
            command = [
                str(item).replace("{artifact_dir}", str(directory)).replace("{python}", sys.executable)
                for item in case["verify"]
            ]
            run(command, directory / "verification.log", timeout=case.get("verification_timeout", 600))
        result["products"] = record["cve_enumeration"].get("products", [])
        result["cve_status"] = record["cve_enumeration"].get("status")
        result["boundary_assertions"] = {
            "must_match": case.get("must_match", []),
            "must_not_match": case.get("must_not_match", []),
        }
        result["cve_findings"] = [item["id"] for item in record["cve_enumeration"].get("findings", [])]
        for mode, extra in (("txt", []), ("debug", ["--debug"])):
            output = run(
                [*arguments, *extra, "--no-color", "-o", str(directory / f"{mode}.tsv")],
                directory / f"probe-{mode}.log",
                timeout=180,
            )
            if "CVE's Enumeration" in output and "potentially affected" not in output:
                raise AssertionError(f"empty CVE heading in {mode}")
        if case.get("balanced_actions", True):
            env = dict(os.environ, PYTHON_BIN=sys.executable, REDPOSTURE_LOCAL_QA_SERVICE=case["fixture"])
            run(
                ["bash", str(ROOT / "scripts/run_lab_matrix_sequential.sh"), str(directory / "actions")],
                directory / "actions.log",
                timeout=1800,
                env=env,
            )
            with (directory / "actions/matrix-status.tsv").open(encoding="utf-8") as stream:
                rows = list(csv.DictReader(stream, delimiter="\t"))
            if not rows or any(row["expected_exit"] != row["exit_code"] for row in rows):
                raise AssertionError("action cases missing or exit codes mismatched")
            result["action_cases"] = len(rows)
        result["status"] = "passed"
    except (
        AssertionError,
        OSError,
        ValueError,
        RuntimeError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
    ) as exc:
        result["error"] = str(exc)
    finally:
        if owns_stack:
            try:
                ids = run([*compose, "ps", "--all", "-q"], directory / "containers.log", timeout=30).split()
                if ids:
                    state = run(["docker", "inspect", *ids], directory / "containers.log", timeout=30)
                    (directory / "container-state.json").write_text(state, encoding="utf-8")
            except (OSError, RuntimeError, subprocess.TimeoutExpired):
                pass
            try:
                run([*compose, "logs", "--tail", "100"], directory / "containers.log", timeout=60)
            except (OSError, RuntimeError, subprocess.TimeoutExpired):
                pass
            try:
                run([*compose, "down", "-v", "--remove-orphans"], directory / "cleanup.log", timeout=180)
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
                result["cleanup_error"] = str(exc)
                result["status"] = "failed"
        if clean_images:
            try:
                errors = remove_images(new_images)
                if errors:
                    result["image_cleanup_error"] = errors
                    result["status"] = "failed"
                if case.get("prepared_compose") and "cleanup_error" not in result:
                    # The QA-owned Harbor data bind mount is no longer needed
                    # once its Compose project has been removed.
                    shutil.rmtree(directory / "prepared" / "data", ignore_errors=True)
                    shutil.rmtree(directory / "prepared" / "logs", ignore_errors=True)
            except (OSError, subprocess.TimeoutExpired) as exc:
                result["image_cleanup_error"] = str(exc)
                result["status"] = "failed"
        result["duration_seconds"] = round(time.monotonic() - started, 2)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact_dir", type=Path)
    parser.add_argument("--manifest", type=Path, default=ROOT / "lab/services/version_matrix.json")
    parser.add_argument(
        "--validate-only", action="store_true", help="resolve Compose overrides without starting services"
    )
    parser.add_argument("--case", action="append", default=[], help="run only this case ID (repeatable)")
    args = parser.parse_args()
    destination = args.artifact_dir.resolve()
    if destination.exists() and any(destination.iterdir()):
        parser.error("artifact directory must be empty")
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    cases = manifest["cases"]
    if not cases:
        parser.error("manifest contains no cases; provide actual licensed images and release boundaries")
    if args.case:
        unknown = set(args.case) - {case["id"] for case in cases}
        if unknown:
            parser.error(f"unknown cases: {sorted(unknown)}")
        cases = [case for case in cases if case["id"] in args.case]
    command_parser = build_parser()
    for case in cases:
        validate_case_cli(case, command_parser)
    destination.mkdir(parents=True, exist_ok=True)
    results = []
    interrupted = False
    try:
        for case in cases:
            print(f"[start] {case['id']}", flush=True)
            result = run_case(case, destination, validate_only=args.validate_only)
            results.append(result)
            print(f"[{result['status']}] {case['id']}: {result.get('error', 'checks completed')}", flush=True)
            (destination / "results.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    except KeyboardInterrupt:
        interrupted = True
        print("[interrupted] current Compose stack cleaned up; completed results retained", flush=True)
    report = {"results": results, "interrupted": interrupted, "limitations": manifest.get("limitations", [])}
    (destination / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    lines = ["# Service release compatibility", "", "| Case | Status | Action cases | Seconds |", "|---|---|---|---|"]
    for result in results:
        lines.append(
            f"| {result['case']['id']} | {result['status']} | {result.get('action_cases', 0)} | {result['duration_seconds']} |"
        )
    lines.extend(["", *[f"- {limit}" for limit in manifest.get("limitations", [])]])
    (destination / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 130 if interrupted else int(any(result["status"] not in {"passed", "validated"} for result in results))


if __name__ == "__main__":
    raise SystemExit(main())
