#!/usr/bin/env python3
"""Verify authentication states against real vendor service containers."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class AuthCase:
    module: str
    target: str
    port: int
    valid_user: str
    valid_password: str
    extra: tuple[str, ...] = ()


CASES = (
    AuthCase("postgres", "127.0.0.1", 15432, "redposture", "redposture-pass", ("--sslmode", "disable")),
    AuthCase("mongodb", "127.0.0.1", 27027, "redposture", "redposture-pass"),
    AuthCase("elastic", "http://127.0.0.1:19200", 19200, "elastic", "redposture-pass"),
    AuthCase("rabbitmq", "http://127.0.0.1:15682", 15682, "redposture", "redposture-pass"),
    AuthCase("kafka", "127.0.0.1", 19092, "redposture", "redposture-pass", ("--plaintext",)),
)


def _wait_for_port(port: int, timeout: float = 240.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.5)
    raise TimeoutError(f"service on 127.0.0.1:{port} did not become ready")


def _scan(case: AuthCase, credentials: tuple[str, str] | None) -> dict[str, Any]:
    command = [
        sys.executable,
        str(ROOT / "redposture.py"),
        case.module,
        "-t",
        case.target,
        "--port",
        str(case.port),
        "--timeout",
        "8",
        "--retries",
        "0",
        *case.extra,
    ]
    if credentials is not None:
        command.extend(("-u", credentials[0], "-p", credentials[1]))
    command.extend(("--format", "json"))
    completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=90, check=False)
    if completed.returncode != 0:
        raise RuntimeError(
            f"{case.module}:{case.port} failed with {completed.returncode}: {completed.stderr or completed.stdout}"
        )
    records: list[dict[str, Any]] = []
    for line in completed.stdout.splitlines():
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and payload.get("type") != "summary":
            records.append(payload)
    if len(records) != 1:
        raise RuntimeError(f"{case.module}:{case.port} returned {len(records)} records: {completed.stdout}")
    return records[0]


def _credential_accepted(record: dict[str, Any]) -> bool:
    return (
        any(record.get(field) is True for field in ("provided_credentials_ok", "auth_valid", "credentials_valid"))
        or record.get("credential_state") == "valid"
        or record.get("status") == "valid_credentials"
    )


def _wait_for_anonymous_result(case: AuthCase, timeout: float = 240.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        try:
            record = _scan(case, None)
            if record.get("auth_required") is True:
                return record
            last_error = AssertionError(f"unexpected anonymous result: {record}")
        except (RuntimeError, subprocess.TimeoutExpired) as exc:
            last_error = exc
        time.sleep(1)
    raise TimeoutError(f"{case.module}:{case.port} did not become scannable: {last_error}")


def main() -> int:
    for case in CASES:
        _wait_for_port(case.port)

    anonymous_results = {case.module: _wait_for_anonymous_result(case) for case in CASES}
    for case in CASES:
        anonymous = anonymous_results[case.module]
        if anonymous.get("auth_required") is not True:
            raise AssertionError(f"{case.module}: anonymous access was not rejected: {anonymous}")

        valid = _scan(case, (case.valid_user, case.valid_password))
        if not _credential_accepted(valid):
            raise AssertionError(f"{case.module}: valid credentials were not accepted: {valid}")

        invalid = _scan(case, (case.valid_user, "definitely-wrong"))
        if _credential_accepted(invalid):
            raise AssertionError(f"{case.module}: invalid credentials were accepted: {invalid}")
        if invalid.get("auth_required") is not True:
            raise AssertionError(f"{case.module}: invalid credentials lost auth-required state: {invalid}")
        print(f"[ok] {case.module}: anonymous denied, valid accepted, invalid rejected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
