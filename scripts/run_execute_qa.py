#!/usr/bin/env python3
"""Run the isolated real-product stands for supported --execute surfaces."""

from __future__ import annotations

import argparse
import json
import os
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "tests" / "fixtures" / "execute" / "docker-compose.yml"
MODULES = ("kafka", "portainer", "jenkins", "consul")
PORTAINER_BASE = "https://127.0.0.1:19443"
PORTAINER_PASSWORD = "redposture-execute-password"
PORTAINER_ENGINE = "tcp://127.0.0.1:19237"
TLS_CONTEXT = ssl._create_unverified_context()


def _request(
    base: str, path: str, *, method: str = "GET", value: Any = None, headers: dict[str, str] | None = None
) -> tuple[int, bytes]:
    body = json.dumps(value).encode() if value is not None else None
    request = urllib.request.Request(
        base + path,
        data=body,
        headers={"Content-Type": "application/json", **(headers or {})},
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=10, context=TLS_CONTEXT) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _json_request(*args: Any, **kwargs: Any) -> tuple[int, dict[str, Any] | list[Any] | None]:
    status, raw = _request(*args, **kwargs)
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        value = None
    return status, value if isinstance(value, (dict, list)) else None


def _wait_http(base: str, path: str, *, timeout: float = 180.0) -> None:
    deadline = time.monotonic() + timeout
    last: object = None
    while time.monotonic() < deadline:
        try:
            status, _ = _request(base, path)
            if 200 <= status < 500:
                return
            last = status
        except (OSError, ValueError) as exc:
            last = exc
        time.sleep(1)
    raise RuntimeError(f"readiness timeout for {base}{path}: {last}")


def _compose(project: str, profile: str, *args: str, output: Path | None = None) -> subprocess.CompletedProcess[str]:
    command = [
        "docker",
        "compose",
        "--project-name",
        project,
        "--profile",
        profile,
        "-f",
        str(COMPOSE),
        *args,
    ]
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
    if output is not None:
        output.write_text(result.stdout + result.stderr, encoding="utf-8")
    return result


def _seed_portainer() -> None:
    _wait_http(PORTAINER_BASE, "/api/system/status")
    status, _ = _json_request(
        PORTAINER_BASE,
        "/api/users/admin/init",
        method="POST",
        value={"Username": "admin", "Password": PORTAINER_PASSWORD},
    )
    if status not in {200, 409}:
        raise RuntimeError(f"Portainer admin initialization failed: HTTP {status}")
    status, auth = _json_request(
        PORTAINER_BASE,
        "/api/auth",
        method="POST",
        value={"Username": "admin", "Password": PORTAINER_PASSWORD},
    )
    if status != 200 or not isinstance(auth, dict) or not isinstance(auth.get("jwt"), str):
        raise RuntimeError(f"Portainer login failed: HTTP {status}")
    headers = {"Authorization": "Bearer " + auth["jwt"]}
    status, endpoints = _json_request(PORTAINER_BASE, "/api/endpoints", headers=headers)
    if status != 200 or not isinstance(endpoints, list):
        raise RuntimeError(f"Portainer endpoint listing failed: HTTP {status}")
    if not any(isinstance(item, dict) and item.get("Name") == "qa-execute" for item in endpoints):
        boundary = "redposture-execute-form"
        fields = {
            "Name": "qa-execute",
            "EndpointCreationType": "1",
            "URL": "tcp://portainer-engine:2375",
            "TLS": "false",
        }
        body = (
            "".join(
                f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n'
                for key, value in fields.items()
            )
            + f"--{boundary}--\r\n"
        )
        # The endpoint API is multipart, unlike the JSON auth API.
        request = urllib.request.Request(
            PORTAINER_BASE + "/api/endpoints",
            data=body.encode(),
            headers={**headers, "Content-Type": "multipart/form-data; boundary=" + boundary},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=10, context=TLS_CONTEXT) as response:
                status = response.status
        except urllib.error.HTTPError as exc:
            status = exc.code
        if status != 200:
            raise RuntimeError(f"Portainer endpoint creation failed: HTTP {status}")
    docker = ["docker", "-H", PORTAINER_ENGINE]
    subprocess.run([*docker, "rm", "-f", "qa-execute-container"], cwd=ROOT, capture_output=True, check=False)
    result = subprocess.run(
        [
            *docker,
            "run",
            "-d",
            "--name",
            "qa-execute-container",
            "docker:27.5.1-dind",
            "sh",
            "-c",
            "while :; do sleep 3600; done",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("failed to seed the disposable Portainer target: " + result.stderr.strip())


def _cli_command(module: str, output: Path) -> list[str]:
    marker = f"redposture-{module}-execute"
    # Consul health-checks expose one Output field, so stderr cannot be
    # distinguished from stdout by the product API. Other surfaces preserve
    # both channels and exercise them independently.
    command = f"printf {marker}; exit 7" if module == "consul" else f"printf {marker}; printf {marker}-err >&2; exit 7"
    common = [
        sys.executable,
        str(ROOT / "redposture.py"),
        module,
        "--no-color",
        "--format",
        "json",
        "--timeout",
        "8",
        "--retries",
        "0",
        "--workers",
        "2",
        "--execute",
        command,
        "-o",
        str(output),
    ]
    if module == "kafka":
        return [*common, "-t", "http://127.0.0.1:19089"]
    if module == "portainer":
        return [
            *common,
            "-t",
            "https://127.0.0.1:19443",
            "-u",
            "admin",
            "-p",
            PORTAINER_PASSWORD,
            "--endpoint",
            "qa-execute",
            "--container",
            "qa-execute-container",
        ]
    if module == "jenkins":
        return [*common, "-t", "127.0.0.1:19580", "-u", "admin", "-p", "admin"]
    return [*common, "-t", "127.0.0.1:19500", "--plaintext"]


def _validate_result(module: str, output: Path) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    for line in output.read_text(encoding="utf-8").splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and isinstance(value.get("execution"), dict):
            records.append(value)
    if len(records) != 1:
        raise RuntimeError(f"expected one execution record in {output}, found {len(records)}")
    record = records[0]
    execution = record["execution"]
    marker = f"redposture-{module}-execute"
    if execution.get("executed") is not True or execution.get("exit_code") != 7:
        raise RuntimeError(f"{module} did not prove execution: {json.dumps(execution, ensure_ascii=False)}")
    if marker not in str(execution.get("stdout")):
        raise RuntimeError(f"{module} execution output markers are missing")
    if module != "consul" and marker + "-err" not in str(execution.get("stderr")):
        raise RuntimeError(f"{module} execution stderr marker is missing")
    return record


def run_module(module: str, project: str, out_dir: Path) -> dict[str, Any]:
    module_dir = out_dir / module
    module_dir.mkdir(parents=True, exist_ok=True)
    compose_log = module_dir / "compose-up.log"
    result_path = module_dir / "result.jsonl"
    try:
        result = _compose(project, module, "up", "-d", "--build", "--wait", output=compose_log)
        if result.returncode:
            raise RuntimeError("compose up failed; inspect " + str(compose_log))
        if module == "kafka":
            _wait_http("http://127.0.0.1:19089", "/api/info")
        elif module == "portainer":
            _seed_portainer()
        elif module == "jenkins":
            _wait_http("http://127.0.0.1:19580", "/login", timeout=240)
        else:
            _wait_http("http://127.0.0.1:19500", "/v1/status/leader")
        command = _cli_command(module, result_path)
        cli = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False, timeout=300)
        (module_dir / "cli.stdout.log").write_text(cli.stdout, encoding="utf-8")
        (module_dir / "cli.stderr.log").write_text(cli.stderr, encoding="utf-8")
        if cli.returncode != 0:
            raise RuntimeError(f"CLI exited {cli.returncode}; inspect {module_dir / 'cli.stderr.log'}")
        record = _validate_result(module, result_path)
        return {"module": module, "status": "passed", "record": record}
    except Exception as exc:  # noqa: BLE001 - report and clean every profile
        return {"module": module, "status": "failed", "error": str(exc)}
    finally:
        logs = _compose(project, module, "logs", "--no-color", output=module_dir / "compose.log")
        down = _compose(project, module, "down", "-v", "--remove-orphans", output=module_dir / "compose-down.log")
        if logs.returncode or down.returncode:
            (module_dir / "cleanup-warning.txt").write_text(
                f"logs_rc={logs.returncode} down_rc={down.returncode}\n", encoding="utf-8"
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("out_dir", type=Path, help="Fresh output directory for stand logs and results.")
    parser.add_argument("module", nargs="?", choices=(*MODULES, "all"), default="all")
    args = parser.parse_args()
    if args.out_dir.exists() and any(args.out_dir.iterdir()):
        parser.error(f"output directory is not empty: {args.out_dir}")
    args.out_dir.mkdir(parents=True, exist_ok=True)
    modules = MODULES if args.module == "all" else (args.module,)
    project = f"redposture-execute-{os.getpid()}"
    results = [run_module(module, project, args.out_dir) for module in modules]
    report = {"project": project, "results": results, "sequential": True, "cleaned": True}
    (args.out_dir / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    for item in results:
        print(f"{item['module']}: {item['status']}")
        if item["status"] == "failed":
            print(f"  {item['error']}", file=sys.stderr)
    return 0 if all(item["status"] == "passed" for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
