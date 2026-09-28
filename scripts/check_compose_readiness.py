#!/usr/bin/env python3
"""Validate Docker inspect JSON using the matrix's positive readiness contract."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Mapping
from typing import Any


def readiness_issues(
    containers: Iterable[Mapping[str, Any]],
    *,
    allowed_completed: frozenset[str] = frozenset(),
) -> list[str]:
    issues: list[str] = []
    for container in containers:
        name = str(container.get("Name") or "unknown").removeprefix("/")
        state = container.get("State")
        if not isinstance(state, Mapping):
            issues.append(f"{name}: missing state")
            continue
        status = str(state.get("Status") or "unknown").lower()
        health_payload = state.get("Health")
        health = str(health_payload.get("Status") or "unknown").lower() if isinstance(health_payload, Mapping) else None
        if status == "running" and health in {None, "healthy"}:
            continue
        exit_code = state.get("ExitCode")
        if status == "exited" and exit_code == 0 and name in allowed_completed:
            continue
        detail = f"status={status}"
        if health is not None:
            detail += f" health={health}"
        if exit_code is not None:
            detail += f" exit={exit_code}"
        issues.append(f"{name}: {detail}")
    return issues


def fatal_readiness_issues(
    containers: Iterable[Mapping[str, Any]], *, allowed_completed: frozenset[str] = frozenset()
) -> list[str]:
    """Failures that cannot be repaired merely by increasing the startup budget."""
    issues = []
    for container in containers:
        state = container.get("State")
        if not isinstance(state, Mapping):
            continue
        name = str(container.get("Name") or "unknown").removeprefix("/")
        status = str(state.get("Status") or "unknown").lower()
        restarts = container.get("RestartCount", 0)
        if state.get("OOMKilled") is True or status == "dead":
            issues.append(f"{name}: fatal status={status} OOMKilled={state.get('OOMKilled')}")
        elif name in allowed_completed and status == "exited" and state.get("ExitCode") != 0:
            issues.append(f"{name}: seed failed exit={state.get('ExitCode')}")
        elif status in {"restarting", "exited"} and isinstance(restarts, int) and restarts >= 3:
            issues.append(f"{name}: restart loop count={restarts} status={status}")
    return issues


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--allow-completed", action="append", default=[])
    args = parser.parse_args(argv)
    payload = json.load(sys.stdin)
    if not isinstance(payload, list) or not all(isinstance(item, Mapping) for item in payload):
        raise ValueError("docker inspect output must be a JSON array of objects")
    allowed = frozenset(args.allow_completed)
    fatal = fatal_readiness_issues(payload, allowed_completed=allowed)
    if fatal:
        for issue in fatal:
            print(issue)
        return 2
    issues = readiness_issues(payload, allowed_completed=allowed)
    for issue in issues:
        print(issue)
    return 1 if issues else 0


if __name__ == "__main__":
    raise SystemExit(main())
