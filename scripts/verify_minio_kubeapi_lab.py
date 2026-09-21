#!/usr/bin/env python3
"""Exercise real MinIO and K3s HTTP-to-HTTPS discovery through the CLI."""

from __future__ import annotations

import json
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def _wait_https(url: str, timeout: float = 180.0) -> None:
    context = ssl._create_unverified_context()  # noqa: S323 - isolated QA endpoints
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=3, context=context) as response:
                if 200 <= response.status < 500:
                    return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(0.5)
    raise TimeoutError(f"QA endpoint did not become ready: {url}")


def _run(module: str, *arguments: str) -> dict[str, Any]:
    completed = subprocess.run(
        [sys.executable, str(ROOT / "redposture.py"), module, *arguments, "--format", "json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"{module} failed: {completed.stdout}\n{completed.stderr}")
    records: list[dict[str, Any]] = []
    for line in completed.stdout.splitlines():
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and payload.get("type") != "summary":
            records.append(payload)
    if len(records) != 1:
        raise RuntimeError(f"{module} returned {len(records)} target records: {completed.stdout}")
    return records[0]


def main() -> int:
    _wait_https("https://127.0.0.1:19000/minio/health/live")
    _wait_https("https://127.0.0.1:16443/version")

    minio = _run(
        "minio",
        "-t",
        "http://127.0.0.1:19000",
        "--defcreds",
        "--show-buckets",
        "--timeout",
        "5",
        "--retries",
        "0",
    )
    if minio.get("service") != "minio" or minio.get("detection_status") != "confirmed":
        raise AssertionError(f"MinIO was not confirmed correctly: {minio}")
    if minio.get("credential_state") != "valid":
        raise AssertionError(f"MinIO credentials were not verified: {minio}")
    if not str(minio.get("api_endpoint") or "").startswith("https://"):
        raise AssertionError(f"MinIO did not retain HTTPS origin: {minio}")

    kubeapi = _run(
        "kubeapi",
        "-t",
        "http://127.0.0.1:16443",
        "--namespaces",
        "--pods",
        "--timeout",
        "5",
        "--retries",
        "0",
    )
    if kubeapi.get("is_kubeapi") is not True:
        raise AssertionError(f"Kubernetes API was not confirmed: {kubeapi}")
    if not str(kubeapi.get("version") or "").startswith("v1.27.5"):
        raise AssertionError(f"unexpected Kubernetes version: {kubeapi}")
    if kubeapi.get("https") is not True:
        raise AssertionError(f"KubeAPI did not retain HTTPS origin: {kubeapi}")

    print("[ok] MinIO real TLS upgrade and credential verification")
    print("[ok] K3s real TLS upgrade, version and anonymous RBAC discovery")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
