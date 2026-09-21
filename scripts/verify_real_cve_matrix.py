#!/usr/bin/env python3
"""Verify CVE boundaries against running vendor Redis and Grafana releases."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class MatrixCase:
    module: str
    target: str
    port: int
    version_field: str
    version: str
    cve: str
    affected: bool


CASES = (
    MatrixCase("redis", "127.0.0.1", 16370, "server_version", "7.0.3", "CVE-2022-31144", True),
    MatrixCase("redis", "127.0.0.1", 16371, "server_version", "7.0.4", "CVE-2022-31144", False),
    MatrixCase("grafana", "http://127.0.0.1:13000", 13000, "server_version", "11.0.0", "CVE-2024-9264", True),
    MatrixCase("grafana", "http://127.0.0.1:13005", 13005, "server_version", "11.0.5", "CVE-2024-9264", False),
)


def _wait_for_port(port: int, timeout: float = 120.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.25)
    raise TimeoutError(f"service on 127.0.0.1:{port} did not become ready")


def _wait_for_grafana(port: int, version: str, timeout: float = 120.0) -> None:
    deadline = time.monotonic() + timeout
    url = f"http://127.0.0.1:{port}/api/health"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                payload = json.load(response)
            if str(payload.get("version") or "") == version:
                return
        except (OSError, ValueError, urllib.error.URLError):
            pass
        time.sleep(0.25)
    raise TimeoutError(f"Grafana {version} on 127.0.0.1:{port} did not become ready")


def _scan(case: MatrixCase) -> dict[str, Any]:
    command = [
        sys.executable,
        str(ROOT / "redposture.py"),
        case.module,
        "-t",
        case.target,
        "--port",
        str(case.port),
        "--timeout",
        "5",
        "--enum-cve",
        "--format",
        "json",
    ]
    completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=45, check=False)
    if completed.returncode != 0:
        raise RuntimeError(
            f"{case.module}:{case.port} failed with {completed.returncode}: {completed.stderr or completed.stdout}"
        )
    records = []
    for line in completed.stdout.splitlines():
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and payload.get("type") != "summary":
            records.append(payload)
    if len(records) != 1:
        raise RuntimeError(f"{case.module}:{case.port} returned {len(records)} target records")
    return records[0]


def main() -> int:
    for case in CASES:
        if case.module == "grafana":
            _wait_for_grafana(case.port, case.version)
        else:
            _wait_for_port(case.port)
    for case in CASES:
        record = _scan(case)
        actual_version = str(record.get(case.version_field) or "")
        if actual_version != case.version:
            raise AssertionError(
                f"{case.module}:{case.port}: expected version {case.version}, detected {actual_version or '-'}"
            )
        findings = {str(item.get("id")) for item in record["cve_enumeration"]["findings"]}
        matched = case.cve in findings
        if matched is not case.affected:
            raise AssertionError(
                f"{case.module}:{case.port}: {case.cve} expected affected={case.affected}, got {matched}"
            )
        verdict = "affected" if matched else "fixed"
        print(f"[ok] {case.module} {case.version}: {case.cve} {verdict}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
