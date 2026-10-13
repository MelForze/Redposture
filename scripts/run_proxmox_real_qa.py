#!/usr/bin/env python3
"""Opt-in, exclusive real Proxmox credential QA on a Docker/KVM host."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import platform
import secrets
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "lab/services/proxmox-real/docker-compose.yml"
PROJECT = "redposture-proxmox-real-qa"
TARGET = "https://127.0.0.1:18007"
MIN_FREE_BYTES = 32 * 1024**3
LOCK = Path("/tmp/redposture-proxmox-real-qa.lock")


def _private_write(path: Path, value: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(value)


def _run(
    command: list[str], *, timeout: int, environment: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command, cwd=ROOT, capture_output=True, text=True, timeout=timeout, env=environment, check=False
    )


def _docker_ids() -> set[str]:
    result = _run(["docker", "ps", "-q"], timeout=30)
    if result.returncode:
        raise RuntimeError(f"docker ps failed: {result.stderr.strip()}")
    return set(result.stdout.split())


def _compose(*args: str, timeout: int, environment: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return _run(
        ["docker", "compose", "--project-name", PROJECT, "--file", str(COMPOSE), *args],
        timeout=timeout,
        environment=environment,
    )


def _own_container_ids() -> set[str]:
    result = _compose("ps", "-q", timeout=30)
    if result.returncode:
        raise RuntimeError(f"docker compose ps failed: {result.stderr.strip()}")
    return set(result.stdout.split())


def _assert_exclusive() -> None:
    foreign = _docker_ids() - _own_container_ids()
    if foreign:
        raise RuntimeError(f"{len(foreign)} other container(s) are running; Proxmox QA requires exclusive Docker use")


def _preflight(output: Path) -> dict[str, Any]:
    if platform.system() != "Linux" or not Path("/dev/kvm").exists():
        raise RuntimeError("real Proxmox requires Linux with /dev/kvm; Docker Desktop on macOS is unsupported")
    free = shutil.disk_usage(output).free
    if free < MIN_FREE_BYTES:
        raise RuntimeError(f"at least 32 GiB free disk space is required; available={free / 1024**3:.1f} GiB")
    info = _run(["docker", "info", "--format", "{{.OSType}}/{{.Architecture}}"], timeout=30)
    if info.returncode:
        raise RuntimeError(f"docker info failed: {info.stderr.strip()}")
    architecture = info.stdout.strip()
    if architecture not in {"linux/amd64", "linux/x86_64", "linux/arm64", "linux/aarch64"}:
        raise RuntimeError(f"Docker host architecture is unsupported: {architecture}")
    docker_os = _run(["docker", "info", "--format", "{{.OperatingSystem}}"], timeout=30)
    if docker_os.returncode or "docker desktop" in docker_os.stdout.lower():
        raise RuntimeError("Docker Desktop does not expose the KVM device required by the real Proxmox stand")
    _assert_exclusive()
    existing = _compose("ps", "-a", "-q", timeout=30)
    if existing.returncode or existing.stdout.strip():
        raise RuntimeError("Proxmox QA Compose project already exists; preserving its containers")
    config = _compose("config", "-q", timeout=30)
    if config.returncode:
        raise RuntimeError(f"Proxmox Compose configuration is invalid: {config.stderr.strip()}")
    return {"docker_architecture": architecture, "free_disk_gib": round(free / 1024**3, 1), "kvm": True}


def _api_request(
    path: str,
    *,
    method: str = "GET",
    form: dict[str, str] | None = None,
    ticket: str | None = None,
    csrf: str | None = None,
) -> tuple[int, dict[str, Any] | None]:
    payload = urllib.parse.urlencode(form).encode() if form is not None else None
    headers = {"Content-Type": "application/x-www-form-urlencoded"} if payload is not None else {}
    if ticket:
        headers["Cookie"] = f"PVEAuthCookie={ticket}"
    if csrf and method != "GET":
        headers["CSRFPreventionToken"] = csrf
    request = urllib.request.Request(TARGET + "/api2/json" + path, data=payload, headers=headers, method=method)
    context = ssl._create_unverified_context()  # isolated loopback stand with a self-signed certificate
    try:
        response = urllib.request.urlopen(request, context=context, timeout=12)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        raw = response.read(1024 * 1024)
        try:
            data = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            data = None
        return response.status, data if isinstance(data, dict) else None


def _wait_ready(deadline: float) -> dict[str, Any]:
    while time.monotonic() < deadline:
        _assert_exclusive()
        try:
            status, payload = _api_request("/version")
            data = payload.get("data") if payload else None
            if status == 200 and isinstance(data, dict) and isinstance(data.get("version"), str):
                return {"version": data["version"], "release": data.get("release")}
        except (OSError, TimeoutError):
            pass
        time.sleep(5)
    raise TimeoutError("real Proxmox API did not become ready before startup timeout")


def _qa_command(name: str, extra: list[str], output: Path, password: str) -> dict[str, Any]:
    _assert_exclusive()
    python = ROOT / ".venv/bin/python"
    command = [
        str(python if python.exists() else sys.executable),
        str(ROOT / "redposture.py"),
        "proxmox",
        "-t",
        TARGET,
        "-f",
        "json",
        "--timeout",
        "15",
        "-r",
        "0",
        "-w",
        "1",
        *extra,
    ]
    started = time.monotonic()
    completed = _run(command, timeout=180)
    _private_write(output / f"{name}.stdout.jsonl", completed.stdout)
    _private_write(output / f"{name}.stderr.log", completed.stderr)
    records = []
    for line in completed.stdout.splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict) and item.get("host") and item.get("type") != "summary":
            records.append(item)
    record = next((item for item in records if "status" in item), {})
    safe_command = [
        "<secret>" if part == password or ("PVEAPIToken=" in part or "root@pam!" in part) else part for part in command
    ]
    return {
        "name": name,
        "command": safe_command,
        "duration_seconds": round(time.monotonic() - started, 2),
        "exit_code": completed.returncode,
        "record_count": len(records),
        "status": record.get("status"),
        "is_proxmox": record.get("is_proxmox"),
        "detection_status": record.get("detection_status"),
        "nodes_count": len(record.get("nodes") or []),
        "ansi_free": "\x1b[" not in completed.stdout and "\x1b[" not in completed.stderr,
        "record": record,
    }


def _expect(row: dict[str, Any], *, statuses: set[str]) -> dict[str, Any]:
    passed = (
        row["exit_code"] == 0
        and row["record_count"] == 1
        and row["is_proxmox"] is True
        and row["ansi_free"] is True
        and row["status"] in statuses
    )
    return {key: value for key, value in row.items() if key != "record"} | {
        "passed": passed,
        "expected_statuses": sorted(statuses),
    }


def _ticket(password: str) -> tuple[str, str]:
    status, payload = _api_request("/access/ticket", method="POST", form={"username": "root@pam", "password": password})
    data = payload.get("data") if payload else None
    if status != 200 or not isinstance(data, dict) or not data.get("ticket") or not data.get("CSRFPreventionToken"):
        raise RuntimeError("real Proxmox did not issue a root ticket")
    return str(data["ticket"]), str(data["CSRFPreventionToken"])


def _run_checks(output: Path, password: str, checks: list[dict[str, Any]]) -> None:
    checks.extend(
        [
            _expect(_qa_command("anonymous", [], output, password), statuses={"auth_required", "open_no_auth"}),
            _expect(
                _qa_command(
                    "valid-password",
                    [
                        "-u",
                        "root@pam",
                        "-p",
                        password,
                        "--nodes",
                        "--users",
                        "--discover",
                        "--discover-time",
                        "30",
                        "--discover-max-bytes",
                        "5242880",
                        "--enum-cve",
                    ],
                    output,
                    password,
                ),
                statuses={"token_ok"},
            ),
            _expect(
                _qa_command(
                    "wrong-password", ["-u", "root@pam", "-p", "RedpostureQaWrong2026", "--nodes"], output, password
                ),
                statuses={"auth_failed"},
            ),
        ]
    )
    ticket, csrf = _ticket(password)
    token_id = "redpostureqa" + secrets.token_hex(4)
    token_path = "/access/users/root@pam/token/" + token_id
    token_created = False
    try:
        status, payload = _api_request(token_path, method="POST", form={"privsep": "0"}, ticket=ticket, csrf=csrf)
        data = payload.get("data") if payload else None
        token_created = status in {200, 201}
        secret = data.get("value") if isinstance(data, dict) else None
        if not token_created or not isinstance(secret, str) or not secret:
            raise RuntimeError(f"could not create an isolated QA API token: HTTP {status}")
        token = f"root@pam!{token_id}={secret}"
        checks.append(
            _expect(
                _qa_command("valid-token", ["--pveapitoken", token, "--nodes"], output, password), statuses={"token_ok"}
            )
        )
        checks.append(
            _expect(
                _qa_command("wrong-token", ["--pveapitoken", token + "wrong", "--nodes"], output, password),
                statuses={"auth_failed"},
            )
        )
    finally:
        if token_created:
            _api_request(token_path, method="DELETE", ticket=ticket, csrf=csrf)
    limited_user = "redpostureqa" + secrets.token_hex(4) + "@pve"
    limited_password = secrets.token_urlsafe(20)
    limited_path = "/access/users/" + urllib.parse.quote(limited_user, safe="@")
    user_created = False
    try:
        status, _payload = _api_request(
            "/access/users",
            method="POST",
            form={"userid": limited_user, "password": limited_password, "enable": "1"},
            ticket=ticket,
            csrf=csrf,
        )
        user_created = status in {200, 201}
        if not user_created:
            raise RuntimeError(f"could not create an isolated low-privilege QA user: HTTP {status}")
        # A ticket proves the pair even when the account cannot list nodes.
        low_ticket_status, low_ticket_body = _api_request(
            "/access/ticket", method="POST", form={"username": limited_user, "password": limited_password}
        )
        low_data = low_ticket_body.get("data") if low_ticket_body else None
        if low_ticket_status != 200 or not isinstance(low_data, dict) or not low_data.get("ticket"):
            raise RuntimeError("low-privilege QA account did not receive a ticket")
        limited = _qa_command(
            "limited-valid-password", ["-u", limited_user, "-p", limited_password, "--nodes"], output, limited_password
        )
        checks.append(_expect(limited, statuses={"token_ok", "insufficient_privileges"}))
    finally:
        if user_created:
            _api_request(limited_path, method="DELETE", ticket=ticket, csrf=csrf)
    plain_command = [
        str(ROOT / ".venv/bin/python") if (ROOT / ".venv/bin/python").exists() else sys.executable,
        str(ROOT / "redposture.py"),
        "proxmox",
        "-t",
        TARGET,
        "-u",
        "root@pam",
        "-p",
        password,
        "--nodes",
        "--no-color",
        "-o",
        str(output / "plain.txt"),
    ]
    plain = _run(plain_command, timeout=180)
    _private_write(output / "plain.stdout.log", plain.stdout)
    _private_write(output / "plain.stderr.log", plain.stderr)
    plain_bytes = (output / "plain.txt").read_bytes() if (output / "plain.txt").exists() else b""
    checks.append(
        {
            "name": "plain-no-color",
            "command": ["<secret>" if part == password else part for part in plain_command],
            "duration_seconds": 0,
            "exit_code": plain.returncode,
            "record_count": None,
            "status": "ansi-free" if plain.returncode == 0 and b"\x1b[" not in plain_bytes else "failed",
            "is_proxmox": None,
            "detection_status": None,
            "nodes_count": None,
            "passed": plain.returncode == 0 and bool(plain_bytes) and b"\x1b[" not in plain_bytes,
            "expected_statuses": ["ansi-free"],
        }
    )


def _write_report(output: Path, result: dict[str, Any]) -> None:
    _private_write(output / "report.json", json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    lines = [
        "# Real Proxmox QA",
        "",
        f"Status: **{result['status']}**. Proxmox is an opt-in, exclusive Docker/KVM stand.",
        "",
    ]
    if result.get("reason"):
        lines.append(f"Reason: {result['reason']}")
        lines.append("")
    for check in result.get("checks", []):
        lines.append(
            f"- {check['name']}: {'PASS' if check['passed'] else 'FAIL'}; status={check['status']}; duration={check['duration_seconds']} s"
        )
    lines += ["", "The runner stops only its own Compose project and keeps images and volumes."]
    _private_write(output / "report.md", "\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", nargs="?", type=Path)
    parser.add_argument("--startup-timeout", type=int, default=2400)
    args = parser.parse_args()
    if args.startup_timeout < 1:
        parser.error("--startup-timeout must be positive")
    output = args.output or ROOT / ".redposture/qa" / ("proxmox-real-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
    output.mkdir(parents=True, exist_ok=False)
    output.chmod(0o700)
    report: dict[str, Any] = {"status": "blocked", "checks": [], "started_at": datetime.now(timezone.utc).isoformat()}
    started = False
    lock_fd: int | None = None
    password = os.environ.get("REDPOSTURE_PVE_QA_PASSWORD", "Proxmox123")
    environment = dict(os.environ, REDPOSTURE_PVE_QA_PASSWORD=password)
    try:
        lock_fd = os.open(LOCK, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("another real Proxmox QA process is running") from exc
        report["preflight"] = _preflight(output)
        started = True
        up = _compose("up", "-d", timeout=args.startup_timeout + 300, environment=environment)
        _private_write(output / "compose-up.log", up.stdout + up.stderr)
        if up.returncode:
            raise RuntimeError("Proxmox Compose up failed; inspect compose-up.log")
        report["product"] = _wait_ready(time.monotonic() + args.startup_timeout)
        _run_checks(output, password, report["checks"])
        report["status"] = "passed" if all(row["passed"] for row in report["checks"]) else "failed"
    except (OSError, RuntimeError, TimeoutError, subprocess.TimeoutExpired) as exc:
        report["status"] = "failed" if started else "blocked"
        report["reason"] = str(exc)
    finally:
        if started:
            down = _compose("down", "--remove-orphans", timeout=300, environment=environment)
            _private_write(output / "compose-down.log", down.stdout + down.stderr)
            if down.returncode:
                report["status"] = "failed"
                report["reason"] = "Proxmox Compose down failed; inspect compose-down.log"
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        _write_report(output, report)
        if lock_fd is not None:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
    print(f"{report['status']}: {output / 'report.md'}")
    return 0 if report["status"] == "passed" else 2 if report["status"] == "blocked" else 1


if __name__ == "__main__":
    raise SystemExit(main())
